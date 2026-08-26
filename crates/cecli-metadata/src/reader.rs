//! `MetadataReader`: parses a complete metadata root slice and exposes heap
//! lookups plus raw cell access for every table.

use cecli_core::io::ByteReader;
use cecli_core::token::TableIndex;
use cecli_core::{Error, Result};

use crate::heaps::{BlobHeap, GuidHeap, Heaps, PdbHeap, StringHeap, UserStringHeap};
use crate::root::{parse_root, stream_slice};
use crate::tables::TableSet;

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
}

impl<'a> MetadataReader<'a> {
    /// Parses a metadata root slice (as produced by
    /// `pe::Image::metadata_rva` on a real image).
    pub fn parse(root: &'a [u8]) -> Result<MetadataReader<'a>> {
        let header = parse_root(root)?;

        let mut strings: &[u8] = &[];
        let mut user_strings: &[u8] = &[];
        let mut blob: &[u8] = &[];
        let mut guid: &[u8] = &[];
        let mut pdb: Option<PdbHeap<'a>> = None;
        let mut table_heap: Option<&[u8]> = None;

        for stream in &header.streams {
            // Validate bounds for every declared stream, even unknown ones.
            let data = stream_slice(root, stream)?;
            match stream.name.as_str() {
                "#~" | "#-" => table_heap = Some(data),
                "#Strings" => strings = data,
                "#US" => user_strings = data,
                "#GUID" => guid = data,
                "#Blob" => blob = data,
                "#Pdb" => pdb = Some(PdbHeap::parse(data)?),
                _ => {} // Unknown streams are tolerated, like Mono.Cecil.
            }
        }

        let Some(table_data) = table_heap else {
            return Err(Error::bad_image("metadata root has no #~ stream"));
        };

        let tables = parse_table_heap(table_data, pdb.as_ref())?;
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
        })
    }

    /// Runtime version string from the root, e.g. `"v4.0.30319"`.
    pub fn version_string(&self) -> &str {
        &self.version
    }

    /// All heaps found in this root.
    pub fn heaps(&self) -> &Heaps<'a> {
        &self.heaps
    }

    /// Table layout information.
    pub fn tables(&self) -> &TableSet {
        &self.tables
    }

    /// Row count of `table` (0 when absent).
    pub fn row_count(&self, table: TableIndex) -> u32 {
        self.tables.row_count(table)
    }

    /// Number of columns of `table` (0 when absent).
    pub fn column_count(&self, table: TableIndex) -> usize {
        self.tables.column_count(table)
    }

    /// Raw cell value of column `col` in row `rid` (1-based) of `table`.
    pub fn column(&self, table: TableIndex, rid: u32, col: usize) -> Result<u64> {
        let (pos, width) = self.tables.cell_location(table, rid, col)?;
        let end = pos as usize + width;
        if end > self.table_data.len() {
            return Err(Error::bad_image(format!(
                "cell [{pos}, {end}) outside #~ data of {} bytes",
                self.table_data.len()
            )));
        }
        let bytes = &self.table_data[pos as usize..end];
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
        let count = self.column_count(table);
        (0..count).map(|col| self.column(table, rid, col)).collect()
    }
}

/// Reads the `#~` header and computes the table layout. Pdb-heap row counts
/// are applied first, exactly like Mono.Cecil's `ReadTableHeap`; counts then
/// present in the `#~` stream itself override them.
fn parse_table_heap(heap: &[u8], pdb: Option<&PdbHeap>) -> Result<TableSet> {
    let mut r = ByteReader::new(heap);
    let _reserved = r.u32()?;
    let major = r.u8()?;
    let minor = r.u8()?;
    // .NET 1.x images use table-stream version 1.x; 2.0 is the modern form.
    // Cecil accepts both, so we do too.
    if major != 1 && major != 2 {
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
        for i in 0..crate::tables::TABLE_COUNT {
            if let Some(t) = TableIndex::from_u8(i as u8) {
                counts[i] = p.row_count(t);
            }
        }
    }
    for i in 0..crate::tables::TABLE_COUNT {
        if valid >> i & 1 == 0 {
            continue;
        }
        counts[i] = r.u32()?;
    }

    TableSet::compute_checked(valid, &counts, heap_flags)
}

/// Size of the `#~` header including the per-table row-count array; the row
/// data begins there.
fn table_stream_data_start(heap: &[u8]) -> Result<usize> {
    let mut r = ByteReader::new(heap);
    let _reserved = r.u32()?;
    let _major = r.u8()?;
    let _minor = r.u8()?;
    let _heap_flags = r.u8()?;
    let _reserved2 = r.u8()?;
    let valid = r.u64()?;
    let mut pos = 24;
    for i in 0..64 {
        if valid >> i & 1 == 0 {
            continue;
        }
        pos += 4;
    }
    Ok(pos)
}
