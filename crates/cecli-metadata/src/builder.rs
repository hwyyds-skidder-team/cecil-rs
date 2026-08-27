//! `MetadataBuilder`: accumulates heaps and table rows, then serializes a
//! complete BSJB metadata root (`#~`, `#Strings`, `#US`, `#GUID`, `#Blob`
//! streams) with heap-size flags, valid-table mask, and row layouts computed
//! exactly like Mono.Cecil's `TableHeapBuffer.WriteTableHeap`.

use std::collections::HashMap;

use cecli_core::io::ByteWriter;
use cecli_core::token::{TableIndex, Token};
use cecli_core::{Error, Result};

use crate::root::write_root;
use crate::tables::{column_kinds, SORTED_MASK_DEFAULT, TABLE_COUNT};

/// Append-only `#Strings` buffer with dedup. Index 0 is reserved for the
/// empty string; every other string gets the byte offset it is written at.
#[derive(Debug, Default)]
struct StringHeapBuffer {
    data: Vec<u8>,
    map: HashMap<String, u32>,
}

impl StringHeapBuffer {
    fn new() -> Self {
        StringHeapBuffer { data: vec![0], map: HashMap::new() }
    }

    fn insert(&mut self, s: &str) -> u32 {
        if s.is_empty() {
            return 0;
        }
        if let Some(&idx) = self.map.get(s) {
            return idx;
        }
        let idx = self.data.len() as u32;
        self.data.extend_from_slice(s.as_bytes());
        self.data.push(0);
        self.map.insert(s.to_owned(), idx);
        idx
    }
}

/// Append-only `#US` buffer: compressed UTF-16 length (low bit = special
/// flag), UTF-16LE payload, trailing flag byte.
#[derive(Debug, Default)]
struct UserStringHeapBuffer {
    data: Vec<u8>,
    map: HashMap<String, u32>,
}

impl UserStringHeapBuffer {
    fn new() -> Self {
        UserStringHeapBuffer { data: Vec::new(), map: HashMap::new() }
    }

    fn insert(&mut self, s: &str) -> u32 {
        if let Some(&idx) = self.map.get(s) {
            return idx;
        }
        let idx = self.data.len() as u32;
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut w = ByteWriter::new();
        w.compressed_u32(units.len() as u32 * 2 + 1);
        for unit in &units {
            w.u16(*unit);
        }
        // Flag byte: 1 when the string contains characters outside the range
        // printable without escaping (Mono.Cecil UserStringHeapBuffer).
        let mut special = 0u8;
        for c in s.chars() {
            if special == 1 {
                break;
            }
            let v = c as u32;
            if (!(0x20..=0x7e).contains(&v))
                && (v > 0x7e
                    || (0x01..=0x08).contains(&v)
                    || (0x0e..=0x1f).contains(&v)
                    || v == 0x27
                    || v == 0x2d)
            {
                special = 1;
            }
        }
        w.u8(special);
        self.data.extend_from_slice(w.as_slice());
        self.map.insert(s.to_owned(), idx);
        idx
    }
}

/// Append-only `#Blob` buffer with content dedup; index 0 is the empty blob.
#[derive(Debug, Default)]
struct BlobHeapBuffer {
    data: Vec<u8>,
    map: HashMap<Vec<u8>, u32>,
}

impl BlobHeapBuffer {
    fn new() -> Self {
        BlobHeapBuffer { data: vec![0], map: HashMap::new() }
    }

    fn insert(&mut self, blob: &[u8]) -> u32 {
        if blob.is_empty() {
            return 0;
        }
        if let Some(&idx) = self.map.get(blob) {
            return idx;
        }
        let idx = self.data.len() as u32;
        let mut w = ByteWriter::new();
        w.compressed_u32(blob.len() as u32);
        self.data.extend_from_slice(w.as_slice());
        self.data.extend_from_slice(blob);
        self.map.insert(blob.to_vec(), idx);
        idx
    }
}

/// Append-only `#GUID` buffer with dedup; GUIDs are numbered 1-based.
#[derive(Debug, Default)]
struct GuidHeapBuffer {
    data: Vec<u8>,
    count: u32,
    map: HashMap<[u8; 16], u32>,
}

impl GuidHeapBuffer {
    fn insert(&mut self, guid: &[u8; 16]) -> u32 {
        if let Some(&idx) = self.map.get(guid) {
            return idx;
        }
        self.count += 1;
        self.data.extend_from_slice(guid);
        self.map.insert(*guid, self.count);
        self.count
    }
}

/// Accumulated portable-PDB `#Pdb` heap payload: the 20-byte PDB id, the
/// module entry point token, and the row counts of the type-system tables
/// recorded in the associated assembly (ECMA-335 Part V).
#[derive(Debug, Clone)]
struct PdbHeapBuffer {
    id: [u8; 20],
    entry_point: Token,
    /// `(table byte, row count)` pairs in ascending table order.
    table_counts: Vec<(u8, u32)>,
}

/// Builds metadata from scratch: heaps plus raw table rows, finalized into
/// BSJB bytes parseable by [`crate::MetadataReader`].
#[derive(Debug)]
pub struct MetadataBuilder {
    version: String,
    strings: StringHeapBuffer,
    user_strings: UserStringHeapBuffer,
    blobs: BlobHeapBuffer,
    guids: GuidHeapBuffer,
    pdb: Option<PdbHeapBuffer>,
    rows: Vec<Vec<Vec<u64>>>,
}

impl MetadataBuilder {
    /// Creates an empty builder emitting the given runtime version string.
    pub fn new(version: &str) -> Self {
        MetadataBuilder {
            version: version.to_owned(),
            strings: StringHeapBuffer::new(),
            user_strings: UserStringHeapBuffer::new(),
            blobs: BlobHeapBuffer::new(),
            guids: GuidHeapBuffer::default(),
            pdb: None,
            rows: (0..TABLE_COUNT).map(|_| Vec::new()).collect(),
        }
    }

    /// Appends one row to `table` and returns its 1-based rid.
    ///
    /// The cell count must match the table's schema; cells are stored raw and
    /// serialized with the widths computed at [`MetadataBuilder::finalize`].
    pub fn add_row(&mut self, table: TableIndex, cells: &[u64]) -> Result<u32> {
        let expected = column_kinds(table)
            .ok_or_else(|| Error::unsupported(format!("unknown table {}", table.name())))?
            .len();
        if cells.len() != expected {
            return Err(Error::argument(format!(
                "table {} expects {} cells, got {}",
                table.name(),
                expected,
                cells.len()
            )));
        }
        let rows = &mut self.rows[table as usize];
        rows.push(cells.to_vec());
        Ok(rows.len() as u32)
    }

    /// Inserts a string into `#Strings`, returning its index. The empty
    /// string maps to index 0; duplicates are folded.
    pub fn insert_string(&mut self, s: &str) -> u32 {
        self.strings.insert(s)
    }

    /// Inserts a blob into `#Blob`, returning its index. The empty blob maps
    /// to index 0; duplicates are folded.
    pub fn insert_blob(&mut self, b: &[u8]) -> u32 {
        self.blobs.insert(b)
    }

    /// Inserts a GUID into `#GUID`, returning its 1-based index; duplicates
    /// are folded.
    pub fn insert_guid(&mut self, g: &[u8; 16]) -> u32 {
        self.guids.insert(g)
    }

    /// Inserts a user string into `#US`, returning its byte offset; the
    /// special-characters flag byte is computed from the content.
    pub fn insert_user_string(&mut self, s: &str) -> u32 {
        self.user_strings.insert(s)
    }

    /// Current number of rows accumulated for `table`.
    pub fn row_count(&self, table: TableIndex) -> u32 {
        self.rows[table as usize].len() as u32
    }

    /// Records the portable-PDB `#Pdb` heap payload emitted by
    /// [`MetadataBuilder::finalize`] as a `#Pdb` stream.
    ///
    /// `id` is the 20-byte PDB id (GUID + time stamp), `entry_point` the
    /// module entry point token, and `type_system_counts` the
    /// `(table byte, row count)` pairs recorded in ascending table order,
    /// exactly like Mono.Cecil's `PortablePdbWriter.WritePdbHeap`.
    pub fn set_pdb_heap(
        &mut self,
        id: [u8; 20],
        entry_point: Token,
        type_system_counts: &[(u8, u32)],
    ) {
        let mut counts = type_system_counts.to_vec();
        counts.sort_by_key(|&(table, _)| table);
        self.pdb = Some(PdbHeapBuffer { id, entry_point, table_counts: counts });
    }

    /// Serializes the complete BSJB root.
    ///
    /// Heap-size flags are derived from the final heap lengths (> `0xFFFF`
    /// bytes => 4-byte indexes); coded and simple index columns widen based on
    /// the final row counts, matching ECMA-335 II §22.
    pub fn finalize(self) -> Vec<u8> {
        let mut counts = [0u32; TABLE_COUNT];
        let mut valid = 0u64;
        for (i, count) in counts.iter_mut().enumerate() {
            if self.rows[i].is_empty() {
                continue;
            }
            *count = self.rows[i].len() as u32;
            valid |= 1u64 << i;
        }

        let heap_flags = (self.strings.data.len() > 0xFFFF) as u8
            | ((self.guids.data.len() > 0xFFFF) as u8) << 1
            | ((self.blobs.data.len() > 0xFFFF) as u8) << 2;

        let set = crate::tables::TableSet::compute(valid, &counts, heap_flags);

        let mut tw = ByteWriter::new();
        tw.u32(0); // Reserved
        tw.u8(2); // MajorVersion
        tw.u8(0); // MinorVersion
        tw.u8(heap_flags);
        tw.u8(10); // Reserved2
        tw.u64(valid);
        tw.u64(SORTED_MASK_DEFAULT);

        for (i, &count) in counts.iter().enumerate() {
            if valid >> i & 1 == 0 {
                continue;
            }
            tw.u32(count);
        }

        for i in 0..TABLE_COUNT {
            if valid >> i & 1 == 0 {
                continue;
            }
            // Invariants guaranteed by add_row: every valid bit has a schema.
            let table = TableIndex::from_u8(i as u8).expect("valid bit implies known table");
            let kinds = column_kinds(table).expect("schema validated by add_row");
            for row in &self.rows[i] {
                for (cell, kind) in row.iter().zip(kinds.iter()) {
                    write_cell(&mut tw, *cell, set.kind_width(kind));
                }
            }
        }

        let pdb_stream = self.pdb.map(|pdb| {
            let mut pw = ByteWriter::new();
            pw.bytes(&pdb.id);
            pw.u32(pdb.entry_point.0);
            let mut valid = 0u64;
            for &(table, _) in &pdb.table_counts {
                valid |= 1u64 << table;
            }
            pw.u64(valid);
            for &(_, count) in &pdb.table_counts {
                pw.u32(count);
            }
            pw.into_vec()
        });
        let tables = tw.into_vec();
        let mut streams: Vec<(&str, &[u8])> =
            vec![("#~", tables.as_slice()), ("#Strings", self.strings.data.as_slice())];
        if !self.user_strings.data.is_empty() {
            streams.push(("#US", self.user_strings.data.as_slice()));
        }
        if !self.guids.data.is_empty() {
            streams.push(("#GUID", self.guids.data.as_slice()));
        }
        if self.blobs.data.len() > 1 {
            streams.push(("#Blob", self.blobs.data.as_slice()));
        }
        if let Some(pdb) = &pdb_stream {
            streams.push(("#Pdb", pdb.as_slice()));
        }
        write_root(&self.version, &streams)
    }
}

fn write_cell(w: &mut ByteWriter, value: u64, width: usize) {
    match width {
        1 => w.u8(value as u8),
        2 => w.u16(value as u16),
        4 => w.u32(value as u32),
        8 => w.u64(value),
        n => unreachable!("invalid cell width {n}"),
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::MetadataReader;
    use crate::tables::{decode_coded, ColumnKind};
    use cecli_core::token::coded;

    #[test]
    fn builder_parser_roundtrip_preserves_every_cell() {
        let mut b = MetadataBuilder::new("v4.0.30319");

        // Heaps: strings (incl. empty + non-ASCII), guids, blobs (one large
        // enough to force 4-byte blob indexes), user strings.
        assert_eq!(b.insert_string(""), 0);
        let s_mod = b.insert_string("cecli.test");
        let s_obj = b.insert_string("Object");
        let s_ns = b.insert_string("System");
        let s_jp = b.insert_string("日本語テスト");
        let s_my = b.insert_string("MyClass");
        let s_m = b.insert_string("Method");
        let s_t = b.insert_string("T");
        assert_eq!(b.insert_string("System"), s_ns, "strings dedup");

        let g_mvid = b.insert_guid(&[0x11u8; 16]);
        let g_other = b.insert_guid(&[0x22u8; 16]);
        assert_eq!(b.insert_guid(&[0x11u8; 16]), g_mvid, "guids dedup");
        assert_ne!(g_mvid, g_other);

        assert_eq!(b.insert_blob(&[]), 0);
        let blob_small = b.insert_blob(&[0xAA, 0xBB]);
        let big = vec![0x5Au8; 70_000];
        let blob_big = b.insert_blob(&big);
        assert_ne!(blob_small, blob_big);

        let us_plain = b.insert_user_string("hello world");
        let us_special = b.insert_user_string("'quoted'");
        let us_nl = b.insert_user_string("line\n"); // \n is NOT special

        // Rows across eight tables.
        let module = [0u64, s_mod as u64, g_mvid as u64, 0, 0];
        // ResolutionScope: Module tag 0, rid 1.
        let typeref_1 = [(1u64 << coded::RESOLUTION_SCOPE.shift_bits()), s_obj as u64, s_ns as u64];
        // ResolutionScope: TypeRef tag 3, rid 1 (forward reference is fine).
        let typeref_2 = [(1u64 << coded::RESOLUTION_SCOPE.shift_bits()) | 3, s_my as u64, 0];
        // BaseType: TypeRef tag 1 rid 1 / TypeDef tag 0 rid 1.
        let typedef_1 = [0x0010_0001, s_obj as u64, s_ns as u64, (1u64 << 2) | 1, 1, 1];
        let typedef_2 = [0x0000_0001, s_my as u64, 0, 1, 1, 1];
        let methoddef: Vec<[u64; 6]> =
            (0..3).map(|i| [0x6000 + i, 0, 0x0096, s_m as u64, blob_small as u64, 1]).collect();
        // MemberRefParent: TypeRef tag 1 rid 1.
        let memberref = [(1u64 << 3) | 1, s_obj as u64, blob_big as u64];
        // HasCustomAttribute: TypeDef tag 3, rid 1 (shift 5). Type:
        // CustomAttributeType MemberRef tag 1, rid 1 (shift 1).
        let ca_1 = [(1u64 << 5) | 3, (1u64 << 1) | 1, 0];
        // Parent MethodDef rid 2; type CustomAttributeType MethodDef tag 0
        // rid 1 (group shift_bits = 1 in cecli-core).
        let ca_2 = [2u64 << 5, 1u64 << 1, blob_small as u64];
        let constant_1 = [0x01u64, 0, 1u64 << 2, blob_small as u64]; // Field rid 1
        let constant_2 = [0x12u64, 0, (1u64 << 2) | 2, blob_small as u64]; // Property rid 1
        let nestedclass = [2u64, 1];
        let genericparam_1 = [0u64, 0, 1u64 << 1, s_t as u64]; // TypeOrMethodDef: TypeDef rid 1
        let genericparam_2 = [1u64, 0, (1u64 << 1) | 1, s_t as u64]; // MethodDef tag 1 rid 1

        let mut expected: Vec<(TableIndex, Vec<u64>)> = Vec::new();
        macro_rules! add {
            ($t:expr, $row:expr) => {{
                let row: Vec<u64> = $row.to_vec();
                b.add_row($t, &row).expect("add_row");
                expected.push(($t, row));
            }};
        }
        add!(TableIndex::Module, module);
        add!(TableIndex::TypeRef, typeref_1);
        add!(TableIndex::TypeRef, typeref_2);
        add!(TableIndex::TypeDef, typedef_1);
        add!(TableIndex::TypeDef, typedef_2);
        for m in &methoddef {
            add!(TableIndex::MethodDef, m);
        }
        add!(TableIndex::MemberRef, memberref);
        add!(TableIndex::CustomAttribute, ca_1);
        add!(TableIndex::CustomAttribute, ca_2);
        add!(TableIndex::Constant, constant_1);
        add!(TableIndex::Constant, constant_2);
        add!(TableIndex::NestedClass, nestedclass);
        add!(TableIndex::GenericParam, genericparam_1);
        add!(TableIndex::GenericParam, genericparam_2);

        let bytes = b.finalize();
        let r = MetadataReader::parse(&bytes).expect("parses own output");
        assert_eq!(r.version_string(), "v4.0.30319");

        // Row counts per table.
        assert_eq!(r.row_count(TableIndex::Module), 1);
        assert_eq!(r.row_count(TableIndex::TypeRef), 2);
        assert_eq!(r.row_count(TableIndex::TypeDef), 2);
        assert_eq!(r.row_count(TableIndex::MethodDef), 3);
        assert_eq!(r.row_count(TableIndex::MemberRef), 1);
        assert_eq!(r.row_count(TableIndex::CustomAttribute), 2);
        assert_eq!(r.row_count(TableIndex::Constant), 2);
        assert_eq!(r.row_count(TableIndex::NestedClass), 1);
        assert_eq!(r.row_count(TableIndex::GenericParam), 2);
        assert_eq!(r.row_count(TableIndex::Field), 0);

        // Every cell of every row survives the roundtrip.
        let mut per_table: std::collections::HashMap<TableIndex, u32> =
            std::collections::HashMap::new();
        for (table, row) in &expected {
            let rid = per_table.entry(*table).or_insert(0);
            *rid += 1;
            assert_eq!(r.column_count(*table), row.len(), "column count of {}", table.name());
            for (col, want) in row.iter().enumerate() {
                assert_eq!(
                    r.column(*table, *rid, col).expect("cell"),
                    *want,
                    "{}[{}][{}]",
                    table.name(),
                    *rid,
                    col
                );
            }
        }

        let h = r.heaps();
        assert_eq!(h.strings.get(s_mod).unwrap(), "cecli.test");
        assert_eq!(h.strings.get(0).unwrap(), "");
        assert_eq!(h.strings.get(s_jp).unwrap(), "日本語テスト");
        assert_eq!(h.guid.get(g_mvid).unwrap(), [0x11u8; 16]);
        assert_eq!(h.guid.get(g_other).unwrap(), [0x22u8; 16]);
        assert_eq!(h.blob.get(0).unwrap(), &[0u8; 0]);
        assert_eq!(h.blob.get(blob_small).unwrap(), &[0xAA, 0xBB]);
        assert_eq!(h.blob.get(blob_big).unwrap(), big.as_slice());
        assert_eq!(h.user_strings.get(us_plain).unwrap(), "hello world");
        assert_eq!(h.user_strings.get(us_special).unwrap(), "'quoted'");
        assert_eq!(h.user_strings.get(us_nl).unwrap(), "line\n");

        // Width variation: blob heap is large (70 KB > 0xFFFF), so every
        // BlobIdx column is 4 bytes while string indexes stay at 2.
        let t = r.tables();
        assert!(!t.large_string());
        assert!(t.large_blob());
        assert_eq!(t.kind_width(&ColumnKind::BlobIdx), 4);
        assert_eq!(t.kind_width(&ColumnKind::StringIdx), 2);
        let mr_cols = t.columns(TableIndex::MemberRef).unwrap();
        assert_eq!(mr_cols[2].kind, ColumnKind::BlobIdx);
        assert_eq!(mr_cols[2].offset, 4, "coded parent widened to 4? no: max(TypeDef)=2");

        // Coded decode of what we encoded: MemberRef.Class -> (TypeRef, 1).
        let class = r.column(TableIndex::MemberRef, 1, 0).unwrap();
        assert_eq!(decode_coded(&coded::MEMBER_REF_PARENT, class), Some((TableIndex::TypeRef, 1)));
        let parent = r.column(TableIndex::CustomAttribute, 1, 0).unwrap();
        assert_eq!(
            decode_coded(&coded::HAS_CUSTOM_ATTRIBUTE, parent),
            Some((TableIndex::TypeDef, 1))
        );
    }

    #[test]
    fn heap_encoding_roundtrips() {
        let mut b = MetadataBuilder::new("v4.0.30319");
        let plain = b.insert_string("plain");
        let unicode = b.insert_string("ünïcode ✓ 日本");
        assert_ne!(plain, unicode);
        assert_eq!(b.insert_string("plain"), plain);

        let blob_zero = b.insert_blob(&[0u8]); // single zero byte != empty
        assert_eq!(b.insert_blob(&[]), 0);
        let long_blob: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let blob_long = b.insert_blob(&long_blob); // exercises 2-byte compressed length

        let us_empty = b.insert_user_string("");
        let us_ascii = b.insert_user_string("ascii only");
        let us_ctrl = b.insert_user_string("\u{0001}ctrl"); // flag byte 1
        let us_dash = b.insert_user_string("a-b"); // '-' triggers the flag too

        // No rows at all: only heaps are emitted.
        let bytes = b.finalize();
        let r = MetadataReader::parse(&bytes).expect("parses");
        for t in [TableIndex::Module, TableIndex::TypeDef, TableIndex::CustomDebugInformation] {
            assert_eq!(r.row_count(t), 0);
        }

        let h = r.heaps();
        assert_eq!(h.strings.get(0).unwrap(), "");
        assert_eq!(h.strings.get(plain).unwrap(), "plain");
        assert_eq!(h.strings.get(unicode).unwrap(), "ünïcode ✓ 日本");
        assert_eq!(h.blob.get(blob_zero).unwrap(), &[0u8]);
        assert_eq!(h.blob.get(blob_long).unwrap(), long_blob.as_slice());
        assert_eq!(h.user_strings.get(us_empty).unwrap(), "");
        assert_eq!(h.user_strings.get(us_ascii).unwrap(), "ascii only");
        assert_eq!(h.user_strings.get(us_ctrl).unwrap(), "\u{0001}ctrl");
        assert_eq!(h.user_strings.get(us_dash).unwrap(), "a-b");
        // Absent GUID stream reads as zero GUIDs, never panics.
        assert_eq!(h.guid.get(1).unwrap(), [0u8; 16]);
    }

    #[test]
    fn large_tables_widen_simple_and_coded_columns() {
        let mut b = MetadataBuilder::new("v2.0.50727");
        let name = b.insert_string("p");

        // 65_538 Param rows push Simple(Param) columns past 16 bits.
        for i in 0..65_538u32 {
            b.add_row(TableIndex::Param, &[0, (i & 0xFFFF) as u64, name as u64])
                .expect("param row");
        }
        // 20_000 rows in Field widen HAS_CONSTANT (Field tag 0) to 4 bytes:
        // max(Field)=20000 >= 1 << (16-2).
        let sig = b.insert_blob(&[1, 2]);
        for _i in 0..20_000u32 {
            b.add_row(TableIndex::Field, &[0, name as u64, sig as u64]).expect("field row");
        }
        b.add_row(TableIndex::Constant, &[0x08, 0, 1u64 << 2, sig as u64]).expect("constant row");

        let bytes = b.finalize();
        let r = MetadataReader::parse(&bytes).expect("parses");
        assert_eq!(r.row_count(TableIndex::Param), 65_538);
        assert_eq!(r.row_count(TableIndex::Field), 20_000);

        // Spot-check deep rows on both sides of the 0xFFFF boundary.
        assert_eq!(r.column(TableIndex::Param, 1, 2).unwrap(), name as u64);
        assert_eq!(r.column(TableIndex::Param, 65_538, 2).unwrap(), name as u64);

        // Constant's parent coded column must have widened to 4 bytes.
        let t = r.tables();
        let cols = t.columns(TableIndex::Constant).unwrap();
        assert_eq!(cols[2].kind, ColumnKind::Coded(&coded::HAS_CONSTANT));
        assert_eq!(t.kind_width(&cols[2].kind), 4);
        assert_eq!(r.column(TableIndex::Constant, 1, 2).unwrap(), 4);
        assert_eq!(
            decode_coded(&coded::HAS_CONSTANT, r.column(TableIndex::Constant, 1, 2).unwrap()),
            Some((TableIndex::Field, 1))
        );
    }

    #[test]
    fn malformed_input_is_error() {
        let err = MetadataReader::parse(b"not metadata at all").expect_err("bad signature");
        assert!(matches!(err, Error::BadImage(_)));

        // Truncated root claiming a huge stream count.
        let mut evil = MetadataBuilder::new("v4.0.30319").finalize();
        evil.truncate(30);
        assert!(MetadataReader::parse(&evil).is_err());
    }

    #[test]
    fn empty_builder_emits_parseable_root() {
        let bytes = MetadataBuilder::new("v4.0.30319").finalize();
        let r = MetadataReader::parse(&bytes).expect("parses");
        assert_eq!(r.version_string(), "v4.0.30319");
        assert_eq!(r.tables().valid_mask(), 0);
        assert_eq!(r.heaps().strings.get(0).unwrap(), "");
    }

    #[test]
    fn pdb_heap_stream_roundtrips() {
        let mut b = MetadataBuilder::new("v4.0.30319");
        b.add_row(TableIndex::Document, &[0, 1, 0, 2]).expect("document row");
        let id = [
            0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
        ];
        // Counts intentionally out of order; set_pdb_heap must sort them.
        b.set_pdb_heap(id, Token::new(TableIndex::MethodDef, 7), &[(0x32, 3), (0x30, 1)]);

        let bytes = b.finalize();
        let r = MetadataReader::parse(&bytes).expect("parses");
        let pdb = r.heaps().pdb.expect("#Pdb stream present");
        assert_eq!(pdb.id(), id.as_slice());
        assert_eq!(pdb.entry_point(), Token::new(TableIndex::MethodDef, 7).0);
        assert!(pdb.has_table(TableIndex::Document));
        assert!(pdb.has_table(TableIndex::LocalScope));
        assert!(!pdb.has_table(TableIndex::MethodDebugInformation));
        assert_eq!(pdb.row_count(TableIndex::Document), 1);
        assert_eq!(pdb.row_count(TableIndex::LocalScope), 3);
        assert_eq!(pdb.row_count(TableIndex::LocalVariable), 0);
    }
}
