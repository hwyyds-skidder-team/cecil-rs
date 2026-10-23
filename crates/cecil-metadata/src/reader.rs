//! `MetadataReader`: parses a complete metadata root slice and exposes heap
//! lookups plus raw cell access for every table.

use std::collections::{BTreeMap, HashMap};

use cecil_core::io::ByteReader;
use cecil_core::token::TableIndex;
use cecil_core::{Error, Result};

use crate::heaps::{BlobHeap, GuidHeap, Heaps, PdbHeap, StringHeap, UserStringHeap};
use crate::root::{parse_root, stream_slice, stream_slice_tolerant};
use crate::tables::{ColumnKind, TableSet};

/// Read-only access to one metadata root (`BSJB` blob): heaps and tables.
///
/// The reader borrows the root slice; all returned strings, blobs, and GUIDs
/// borrow from it too.
#[derive(Debug, Clone)]
pub struct MetadataReader<'a> {
    version: String,
    heaps: Heaps<'a>,
    tables: TableSet,
    /// Payload of the `#~` stream after its header (row data only).
    table_data: &'a [u8],
    tolerant: bool,
    root_len: usize,
}

impl<'a> MetadataReader<'a> {
    /// Parses a metadata root slice (as produced by
    /// `pe::Image::metadata_rva` on a real image).
    pub fn parse(root: &'a [u8]) -> Result<MetadataReader<'a>> {
        Self::parse_with_tolerance(root, false)
    }

    /// Parses a malformed metadata root using only physically available heap
    /// bytes. Optional stream extents are clipped to the input, anomalous
    /// table version bytes use the known ECMA layouts, and a malformed
    /// optional `#Pdb` stream is ignored. Table schemas, row extents, indices
    /// and allocation bounds remain checked as in [`Self::parse`].
    ///
    /// Heap names remain strict through `StringHeap::get`; callers can opt
    /// into replacement decoding through `StringHeap::get_lossy` separately.
    pub fn parse_tolerant(root: &'a [u8]) -> Result<MetadataReader<'a>> {
        Self::parse_with_tolerance(root, true)
    }

    fn parse_with_tolerance(root: &'a [u8], tolerant: bool) -> Result<MetadataReader<'a>> {
        let header = parse_root(root)?;

        let mut strings: &[u8] = &[];
        let mut user_strings: &[u8] = &[];
        let mut blob: &[u8] = &[];
        let mut guid: &[u8] = &[];
        let mut pdb: Option<PdbHeap<'a>> = None;
        let mut table_heap: Option<&[u8]> = None;

        for stream in &header.streams {
            // Validate bounds for every declared stream, even unknown ones.
            let data = if tolerant {
                stream_slice_tolerant(root, stream)
            } else {
                stream_slice(root, stream)?
            };
            match stream.name.as_str() {
                "#~" | "#-" => table_heap = Some(data),
                "#Strings" => strings = data,
                "#US" => user_strings = data,
                "#GUID" => guid = data,
                "#Blob" => blob = data,
                "#Pdb" => {
                    pdb = if tolerant {
                        PdbHeap::parse(data).ok()
                    } else {
                        Some(PdbHeap::parse(data)?)
                    };
                }
                _ => {} // Unknown streams are tolerated, like Mono.Cecil.
            }
        }

        let Some(table_data) = table_heap else {
            return Err(Error::bad_image("metadata root has no #~ stream"));
        };

        let tables = parse_table_heap(table_data, pdb.as_ref(), tolerant)?;
        let data_start = table_stream_data_start(table_data)?;
        let table_data = &table_data[data_start..];

        Ok(MetadataReader {
            version: header.version,
            heaps: Heaps {
                strings: StringHeap::new(strings),
                user_strings: UserStringHeap::new(user_strings),
                blob: BlobHeap::new(blob),
                guid: GuidHeap::new(guid),
                pdb,
            },
            tables,
            table_data,
            tolerant,
            root_len: root.len(),
        })
    }

    /// Whether this reader was created with [`Self::parse_tolerant`].
    pub fn is_tolerant(&self) -> bool {
        self.tolerant
    }

    /// Checks the projected metadata heap copies before building an owned
    /// object model. Shared strings and blobs count once per reference;
    /// physical rows and temporary index caches also consume the allowance.
    /// Both parse modes use the same limit: 128 times the metadata root size,
    /// capped at 256 MiB. The check does not materialize payload copies.
    ///
    /// String indices are grouped by NUL-terminated span so overlapping suffix
    /// references are measured in one heap scan, rather than quadratic work.
    pub fn validate_materialization_budget(&self) -> Result<()> {
        const MAX_BYTES: usize = 256 * 1024 * 1024;
        let mut remaining = self.root_len.saturating_mul(128).min(MAX_BYTES);
        let mut strings = BTreeMap::<u32, usize>::new();
        let mut blobs = HashMap::<u32, usize>::new();

        for table_byte in 0..crate::tables::TABLE_COUNT {
            let Some(table) = TableIndex::from_u8(table_byte as u8) else { continue };
            if !self.tables.is_present(table) {
                continue;
            }
            let count = self.row_count(table) as usize;
            debit_budget(&mut remaining, count.saturating_mul(128))?;
            let columns = self.tables.columns(table).expect("physical table schema");
            for rid in 1..=count as u32 {
                for (column, descriptor) in columns.iter().enumerate() {
                    let (references, heap_len) = match descriptor.kind {
                        ColumnKind::StringIdx => (&mut strings, self.heaps.strings.data().len()),
                        ColumnKind::BlobIdx => {
                            let index = self.column(table, rid, column)? as u32;
                            if index != 0 && (index as usize) < self.heaps.blob.data().len() {
                                if let Some(count) = blobs.get_mut(&index) {
                                    *count += 1;
                                } else {
                                    debit_budget(&mut remaining, 64)?;
                                    blobs.insert(index, 1);
                                }
                            }
                            continue;
                        }
                        _ => continue,
                    };
                    let index = self.column(table, rid, column)? as u32;
                    if index != 0 && (index as usize) < heap_len {
                        if let Some(count) = references.get_mut(&index) {
                            *count += 1;
                        } else {
                            debit_budget(&mut remaining, 64)?;
                            references.insert(index, 1);
                        }
                    }
                }
            }
        }

        let data = self.heaps.strings.data();
        let mut span_end = 0;
        for (index, references) in strings {
            let start = index as usize;
            if start >= span_end {
                span_end = data[start..]
                    .iter()
                    .position(|&byte| byte == 0)
                    .map_or(data.len(), |length| start + length);
            }
            let length = span_end - start;
            // A malformed UTF-8 byte may become a three-byte replacement.
            let expansion = if self.tolerant { 3 } else { 1 };
            debit_budget(
                &mut remaining,
                length.saturating_mul(references).saturating_mul(expansion),
            )?;
        }
        for (index, references) in blobs {
            let data = if self.tolerant {
                self.heaps.blob.get_tolerant(index)
            } else {
                self.heaps.blob.get(index)?
            };
            debit_budget(&mut remaining, data.len().saturating_mul(references))?;
        }
        Ok(())
    }

    /// Runtime version string from the root, e.g. `"v4.0.30319"`.
    #[inline]
    pub fn version_string(&self) -> &str {
        &self.version
    }

    /// All heaps found in this root.
    #[inline]
    pub fn heaps(&self) -> &Heaps<'a> {
        &self.heaps
    }

    /// Table layout information.
    #[inline]
    pub fn tables(&self) -> &TableSet {
        &self.tables
    }

    /// Row count of `table` (0 when absent).
    #[inline]
    pub fn row_count(&self, table: TableIndex) -> u32 {
        self.tables.row_count(table)
    }

    /// Number of columns of `table` (0 when absent).
    #[inline]
    pub fn column_count(&self, table: TableIndex) -> usize {
        self.tables.column_count(table)
    }

    /// Raw cell value of column `col` in row `rid` (1-based) of `table`.
    #[inline]
    pub fn column(&self, table: TableIndex, rid: u32, col: usize) -> Result<u64> {
        let (pos, width) = self.tables.cell_location(table, rid, col)?;
        let start = usize::try_from(pos)
            .map_err(|_| Error::bad_image("metadata cell offset exceeds the address space"))?;
        let end = start
            .checked_add(width)
            .ok_or_else(|| Error::bad_image("metadata cell range overflows"))?;
        let bytes = self
            .table_data
            .get(start..end)
            .ok_or_else(|| Error::bad_image("metadata cell extends past the table stream"))?;
        Ok(match width {
            1 => u64::from(bytes[0]),
            2 => u64::from(u16::from_le_bytes([bytes[0], bytes[1]])),
            4 => u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
            8 => u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            n => return Err(Error::bad_image(format!("unsupported cell width {n}"))),
        })
    }

    /// All cells of row `rid` (1-based) of `table`.
    pub fn row(&self, table: TableIndex, rid: u32) -> Result<Vec<u64>> {
        // Even a table without a schema must reject an invalid row rather
        // than reporting a successful empty row.
        self.tables.cell_location(table, rid, 0)?;
        let count = self.column_count(table);
        (0..count).map(|col| self.column(table, rid, col)).collect()
    }

    /// Reads a known table schema into a fixed-size row without allocating.
    /// A mismatched schema size or invalid row id is an error.
    #[inline]
    pub fn row_array<const N: usize>(&self, table: TableIndex, rid: u32) -> Result<[u64; N]> {
        if self.column_count(table) != N {
            return Err(Error::argument(format!(
                "table {} has {} columns, expected {N}",
                table.name(),
                self.column_count(table)
            )));
        }
        let (start, _) = self.tables.cell_location(table, rid, 0)?;
        let row_size = self.tables.row_size(table).expect("validated table") as usize;
        let start = usize::try_from(start)
            .map_err(|_| Error::bad_image("metadata row offset exceeds the address space"))?;
        let end = start
            .checked_add(row_size)
            .ok_or_else(|| Error::bad_image("metadata row range overflows"))?;
        let bytes = self
            .table_data
            .get(start..end)
            .ok_or_else(|| Error::bad_image("metadata row extends past the table stream"))?;
        let widths = self.tables.row_widths(table).expect("validated table");
        let mut row = [0; N];
        let mut offset = 0;
        for (cell, &width) in row.iter_mut().zip(widths) {
            *cell = match width {
                1 => u64::from(bytes[offset]),
                2 => u64::from(u16::from_le_bytes([bytes[offset], bytes[offset + 1]])),
                4 => u64::from(u32::from_le_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                ])),
                _ => unreachable!("metadata schemas have only 1, 2 or 4 byte cells"),
            };
            offset += width as usize;
        }
        Ok(row)
    }
}

fn debit_budget(remaining: &mut usize, amount: usize) -> Result<()> {
    *remaining = remaining
        .checked_sub(amount)
        .ok_or_else(|| Error::bad_image("metadata materialization exceeds decoded byte budget"))?;
    Ok(())
}

/// Reads the `#~` header and computes the table layout. Pdb-heap row counts
/// are applied first, exactly like Mono.Cecil's `ReadTableHeap`; counts then
/// present in the `#~` stream itself override them.
fn parse_table_heap(heap: &[u8], pdb: Option<&PdbHeap>, tolerant: bool) -> Result<TableSet> {
    let mut r = ByteReader::new(heap);
    let _reserved = r.u32()?;
    let major = r.u8()?;
    let minor = r.u8()?;
    // .NET 1.x images use table-stream version 1.x; 2.0 is the modern form.
    // Cecil accepts both, so we do too.
    if !tolerant && major != 1 && major != 2 {
        return Err(Error::unsupported(format!(
            "unsupported table stream version {major}.{minor}"
        )));
    }
    let heap_flags = r.u8()?;
    let _reserved2 = r.u8()?;
    let valid = r.u64()?;
    let _sorted = r.u64()?;

    let mut counts = [0u32; crate::tables::TABLE_COUNT];
    if let Some(p) = pdb {
        for (i, count) in counts.iter_mut().enumerate() {
            if let Some(t) = TableIndex::from_u8(i as u8) {
                // #Pdb describes external type-system tables for width
                // computation, never absent debug tables. Otherwise phantom
                // LocalVariable counts can drive huge scope-list allocations.
                if (i as u8) < TableIndex::PORTABLE_PDB_FIRST {
                    *count = p.row_count(t);
                }
            }
        }
    }
    for (i, count) in counts.iter_mut().enumerate() {
        if valid >> i & 1 == 0 {
            continue;
        }
        *count = r.u32()?;
    }

    let set = TableSet::compute_checked(valid, &counts, heap_flags)?;

    // Declared row counts must physically fit in the stream: the total table
    // extent (header consumed above) may not overrun the heap. Without this
    // a hostile header can declare millions of phantom rows, which readers
    // turn into per-row allocations before any column read fails.
    let data_start = table_stream_data_start(heap)? as u64;
    let extent = set.tables_extent();
    if data_start + extent > heap.len() as u64 {
        return Err(Error::bad_image(format!(
            "metadata tables ({extent} bytes) overrun the #~ stream ({} bytes of data)",
            heap.len() as u64 - data_start
        )));
    }
    Ok(set)
}

/// Size of the `#~` header including the per-table row-count array; the row
/// data begins there.
fn table_stream_data_start(heap: &[u8]) -> Result<usize> {
    let mut r = ByteReader::new(heap);
    let _reserved = r.u32()?;
    let _major = r.u8()?;
    let _minor = r.u8()?;
    let heap_flags = r.u8()?;
    let _reserved2 = r.u8()?;
    let valid = r.u64()?;
    let mut pos = 24;
    for i in 0..64 {
        if valid >> i & 1 == 0 {
            continue;
        }
        pos += 4;
    }
    // ECMA's ExtraData flag adds one DWORD after the row-count array.
    if heap_flags & 0x40 != 0 {
        pos += 4;
    }
    if pos > heap.len() {
        return Err(Error::bad_image("truncated metadata table-stream header"));
    }
    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::write_root;
    use cecil_core::io::ByteWriter;

    #[test]
    fn materialization_budget_rejects_repeated_large_heap_aliases() {
        for string_heap in [false, true] {
            let mut builder = crate::MetadataBuilder::new("v4.0");
            if string_heap {
                let name = builder.insert_string(&"x".repeat(16_384));
                for _ in 0..512 {
                    builder.add_row(TableIndex::ModuleRef, &[name as u64]).unwrap();
                }
            } else {
                let signature = builder.insert_blob(&vec![0; 16_384]);
                for _ in 0..512 {
                    builder.add_row(TableIndex::StandAloneSig, &[signature as u64]).unwrap();
                }
            }
            let bytes = builder.finalize();
            for reader in [
                MetadataReader::parse(&bytes).unwrap(),
                MetadataReader::parse_tolerant(&bytes).unwrap(),
            ] {
                assert!(reader.validate_materialization_budget().is_err());
            }
        }
    }

    #[test]
    fn materialization_budget_accepts_ordinary_suffixes_and_tracks_parse_mode() {
        let mut builder = crate::MetadataBuilder::new("v4.0");
        let name = builder.insert_string("namespace.Type");
        for index in [name, name + 10, name] {
            builder.add_row(TableIndex::ModuleRef, &[index as u64]).unwrap();
        }
        let bytes = builder.finalize();
        let strict = MetadataReader::parse(&bytes).unwrap();
        let tolerant = MetadataReader::parse_tolerant(&bytes).unwrap();
        assert!(!strict.is_tolerant());
        assert!(tolerant.is_tolerant());
        strict.validate_materialization_budget().unwrap();
        tolerant.validate_materialization_budget().unwrap();
    }

    #[test]
    fn materialization_budget_accepts_real_metadata_fixture_roots() {
        let mut checked = 0;
        for entry in std::fs::read_dir(cecil_core::fixtures_dir()).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if !matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("dll" | "exe" | "winmd")
            ) {
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            let Ok(image) = cecil_pe::Image::parse_owned(bytes) else { continue };
            let Ok((rva, size)) = image.metadata_rva() else { continue };
            let Ok(root) = image.rva_bytes(rva, size) else { continue };
            let Ok(reader) = MetadataReader::parse(root) else { continue };
            reader
                .validate_materialization_budget()
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            let tolerant = MetadataReader::parse_tolerant(root).unwrap();
            tolerant
                .validate_materialization_budget()
                .unwrap_or_else(|error| panic!("{} tolerant: {error}", path.display()));
            checked += 1;
        }
        assert!(checked >= 50, "only {checked} real roots checked");
    }

    fn module_table(count: u32, extra: bool) -> Vec<u8> {
        let mut writer = ByteWriter::new();
        writer.u32(0);
        writer.u8(2);
        writer.u8(0);
        writer.u8(if extra { 0x40 } else { 0 });
        writer.u8(1);
        writer.u64(1);
        writer.u64(0);
        writer.u32(count);
        if extra {
            writer.u32(0xdead_beef);
        }
        writer.into_vec()
    }

    #[test]
    fn extra_data_is_skipped_before_table_rows() {
        let mut tables = module_table(1, true);
        tables.extend_from_slice(&[0; 10]);
        let bytes = write_root("v4.0", &[("#~", &tables)]);
        let reader = MetadataReader::parse(&bytes).unwrap();
        assert_eq!(reader.row_array::<5>(TableIndex::Module, 1).unwrap(), [0; 5]);
        tables.pop();
        assert!(MetadataReader::parse(&write_root("v4.0", &[("#~", &tables)])).is_err());
    }

    #[test]
    fn huge_phantom_rows_and_missing_extra_data_are_rejected() {
        for count in [1, u32::MAX] {
            let tables = module_table(count, false);
            assert!(MetadataReader::parse(&write_root("v4.0", &[("#~", &tables)])).is_err());
        }
        let mut tables = module_table(0, true);
        tables.pop();
        assert!(MetadataReader::parse(&write_root("v4.0", &[("#~", &tables)])).is_err());
    }

    #[test]
    fn tolerant_metadata_clips_optional_streams_but_keeps_rows_bounded() {
        let mut tables = module_table(1, false);
        tables.extend_from_slice(&[0; 10]);
        let mut bytes = write_root("v4.0", &[("#~", &tables), ("#Strings", b"\0ok\0")]);
        // Root: 16-byte fixed header, 8-byte padded version, flags/count.
        // #~ directory is 12 bytes; #Strings entry begins at byte 40.
        bytes[44..48].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(MetadataReader::parse(&bytes).is_err());
        let reader = MetadataReader::parse_tolerant(&bytes).unwrap();
        assert_eq!(reader.row_array::<5>(TableIndex::Module, 1).unwrap(), [0; 5]);
        assert_eq!(reader.heaps().strings.get_lossy(1), "ok");
        bytes[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(MetadataReader::parse_tolerant(&bytes).unwrap().heaps().strings.data().is_empty());

        let mut phantom = module_table(100, false);
        phantom.extend_from_slice(&[0; 10]);
        let bytes = write_root("v4.0", &[("#~", &phantom)]);
        assert!(MetadataReader::parse_tolerant(&bytes).is_err());
    }

    #[test]
    fn tolerant_table_versions_use_only_known_checked_layouts() {
        let mut tables = module_table(1, false);
        tables.extend_from_slice(&[0; 10]);
        for version in [[0, 0], [255, 255]] {
            tables[4..6].copy_from_slice(&version);
            let bytes = write_root("v4.0", &[("#~", &tables)]);
            assert!(MetadataReader::parse(&bytes).is_err());
            assert_eq!(
                MetadataReader::parse_tolerant(&bytes)
                    .unwrap()
                    .row_array::<5>(TableIndex::Module, 1)
                    .unwrap(),
                [0; 5]
            );
        }
        tables[8..16].copy_from_slice(&(1u64 << 63).to_le_bytes());
        assert!(MetadataReader::parse_tolerant(&write_root("v4.0", &[("#~", &tables)])).is_err());
    }

    #[test]
    fn tolerant_metadata_ignores_broken_optional_pdb_stream() {
        let tables = module_table(0, false);
        let bytes = write_root("v4.0", &[("#~", &tables), ("#Pdb", &[0; 4])]);
        assert!(MetadataReader::parse(&bytes).is_err());
        assert!(MetadataReader::parse_tolerant(&bytes).unwrap().heaps().pdb.is_none());
    }

    #[test]
    fn deterministic_root_mutations_do_not_panic_in_heap_or_row_lookups() {
        let mut builder = crate::MetadataBuilder::new("v4.0");
        let name = builder.insert_string("sample");
        builder.add_row(TableIndex::Module, &[0, name as u64, 0, 0, 0]).unwrap();
        let good = builder.finalize();
        for index in 0..good.len() {
            for replacement in [0, 0xff] {
                let mut bytes = good.clone();
                bytes[index] = replacement;
                if let Ok(reader) = MetadataReader::parse(&bytes) {
                    let _ = reader.row(TableIndex::Module, 1);
                    for index in [0, 1, u32::MAX] {
                        let _ = reader.heaps().strings.get(index);
                        let _ = reader.heaps().blob.get(index);
                        let _ = reader.heaps().guid.get(index);
                        let _ = reader.heaps().user_strings.get(index);
                    }
                }
            }
        }
    }
}
