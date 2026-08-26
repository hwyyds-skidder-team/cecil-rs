//! Metadata root, stream, heap, and table reading and building for ECMA-335
//! images.
//!
//! Layering: this crate sits between [`cecli_core`] (binary cursors, tokens,
//! coded-index groups) and the PE/facade crates. `cecli_pe` slices out the
//! metadata root; [`MetadataReader`] parses it, [`MetadataBuilder`] emits one
//! from scratch.
//!
//! Ported from Mono.Cecil's `Mono.Cecil.Metadata` heaps/buffers and the
//! `ReadTableHeap` / metadata-emission logic of `AssemblyReader.cs` /
//! `AssemblyWriter.cs`.

pub mod builder;
pub mod heaps;
pub mod reader;
pub mod root;
pub mod tables;

pub use builder::MetadataBuilder;
pub use heaps::{BlobHeap, GuidHeap, Heaps, PdbHeap, StringHeap, UserStringHeap};
pub use reader::MetadataReader;
pub use root::{parse_root, stream_slice, write_root, RootHeader, StreamHeader, METADATA_SIGNATURE};
pub use tables::{
    column_kinds, decode_coded, encode_coded, ColumnDesc, ColumnKind, TableSet, SORTED_MASK_DEFAULT,
    TABLE_COUNT,
};

#[cfg(test)]
mod smoke_tests {
    use super::*;
    use cecli_core::TableIndex;

    /// End-to-end sanity: a tiny module table round-trips through the
    /// builder and the reader.
    #[test]
    fn tiny_module_roundtrip() {
        let mut b = MetadataBuilder::new("v4.0.30319");
        let name = b.insert_string("tiny.exe");
        let mvid = b.insert_guid(&[7u8; 16]);
        let rid = b
            .add_row(TableIndex::Module, &[0, name as u64, mvid as u64, 0, 0])
            .expect("module row");
        assert_eq!(rid, 1);

        let bytes = b.finalize();
        let r = MetadataReader::parse(&bytes).expect("parses");
        assert_eq!(r.version_string(), "v4.0.30319");
        assert_eq!(r.row_count(TableIndex::Module), 1);
        assert_eq!(r.column(TableIndex::Module, 1, 1).unwrap(), name as u64);
        assert_eq!(
            r.heaps().strings.get(name).unwrap(),
            "tiny.exe"
        );
        assert_eq!(r.heaps().guid.get(mvid).unwrap(), [7u8; 16]);
    }
}
