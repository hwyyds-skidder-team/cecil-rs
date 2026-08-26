//! Metadata table schemas, per-table row layout computation, and
//! coded-index encode/decode helpers.
//!
//! Row layouts follow ECMA-335 II §22 exactly: heap-index columns widen to 4
//! bytes when the corresponding heap exceeds `0xFFFF` bytes, simple table
//! index columns widen when the target table holds more than `0xFFFF` rows,
//! and coded index columns widen when the largest participating table reaches
//! `1 << (16 - tag_bits)` rows.

use cecli_core::token::{coded, CodedIndexGroup, TableIndex};
use cecli_core::{Error, Result};

/// Number of table identifier slots (`0x00..=0x37`).
pub const TABLE_COUNT: usize = 0x38;

/// Sorted-table mask emitted by Cecil-compatible writers for the standard
/// sorted columns.
pub const SORTED_MASK_DEFAULT: u64 = 0x00C4_1600_3301_FA00;

/// Physical type of one column cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnKind {
    /// One raw byte.
    U8,
    /// Two-byte little-endian value.
    U16,
    /// Four-byte little-endian value.
    U32,
    /// Index into the `#Strings` heap (2 or 4 bytes).
    StringIdx,
    /// Index into the `#GUID` heap (2 or 4 bytes).
    GuidIdx,
    /// Index into the `#Blob` heap (2 or 4 bytes).
    BlobIdx,
    /// Compressed coded index over a group of tables (2 or 4 bytes).
    Coded(&'static CodedIndexGroup),
    /// Plain row index into another table (2 or 4 bytes when that table is
    /// larger than `0xFFFF` rows).
    Simple(TableIndex),
}

/// One column of a table: its kind and byte offset inside the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColumnDesc {
    /// Physical kind of the cell.
    pub kind: ColumnKind,
    /// Byte offset of the cell within the row.
    pub offset: u16,
}

/// Static per-table column kinds. Returns `None` for table numbers without a
/// defined schema (including the gaps between 0x2C and 0x30).
pub fn column_kinds(table: TableIndex) -> Option<&'static [ColumnKind]> {
    use ColumnKind as K;
    use TableIndex as T;
    Some(match table {
        T::Module => &[K::U16, K::StringIdx, K::GuidIdx, K::GuidIdx, K::GuidIdx],
        T::TypeRef => &[K::Coded(&coded::RESOLUTION_SCOPE), K::StringIdx, K::StringIdx],
        T::TypeDef => &[
            K::U32,
            K::StringIdx,
            K::StringIdx,
            K::Coded(&coded::TYPE_DEF_OR_REF),
            K::Simple(T::Field),
            K::Simple(T::MethodDef),
        ],
        T::FieldPtr => &[K::Simple(T::Field)],
        T::Field => &[K::U16, K::StringIdx, K::BlobIdx],
        T::MethodPtr => &[K::Simple(T::MethodDef)],
        T::MethodDef => &[K::U32, K::U16, K::U16, K::StringIdx, K::BlobIdx, K::Simple(T::Param)],
        T::ParamPtr => &[K::Simple(T::Param)],
        T::Param => &[K::U16, K::U16, K::StringIdx],
        T::InterfaceImpl => &[K::Simple(T::TypeDef), K::Coded(&coded::TYPE_DEF_OR_REF)],
        T::MemberRef => &[K::Coded(&coded::MEMBER_REF_PARENT), K::StringIdx, K::BlobIdx],
        // Type is physically one byte followed by one padding byte.
        T::Constant => &[K::U8, K::U8, K::Coded(&coded::HAS_CONSTANT), K::BlobIdx],
        T::CustomAttribute => &[
            K::Coded(&coded::HAS_CUSTOM_ATTRIBUTE),
            K::Coded(&coded::CUSTOM_ATTRIBUTE_TYPE),
            K::BlobIdx,
        ],
        T::FieldMarshal => &[K::Coded(&coded::HAS_FIELD_MARSHAL), K::BlobIdx],
        T::DeclSecurity => &[K::U16, K::Coded(&coded::HAS_DECL_SECURITY), K::BlobIdx],
        T::ClassLayout => &[K::U16, K::U32, K::Simple(T::TypeDef)],
        T::FieldLayout => &[K::U32, K::Simple(T::Field)],
        T::StandAloneSig => &[K::BlobIdx],
        T::EventMap => &[K::Simple(T::TypeDef), K::Simple(T::Event)],
        T::EventPtr => &[K::Simple(T::Event)],
        T::Event => &[K::U16, K::StringIdx, K::Coded(&coded::TYPE_DEF_OR_REF)],
        T::PropertyMap => &[K::Simple(T::TypeDef), K::Simple(T::Property)],
        T::PropertyPtr => &[K::Simple(T::Property)],
        T::Property => &[K::U16, K::StringIdx, K::BlobIdx],
        T::MethodSemantics => &[K::U16, K::Simple(T::MethodDef), K::Coded(&coded::HAS_SEMANTICS)],
        T::MethodImpl => &[
            K::Simple(T::TypeDef),
            K::Coded(&coded::METHOD_DEF_OR_REF),
            K::Coded(&coded::METHOD_DEF_OR_REF),
        ],
        T::ModuleRef => &[K::StringIdx],
        T::TypeSpec => &[K::BlobIdx],
        T::ImplMap => {
            &[K::U16, K::Coded(&coded::MEMBER_FORWARDED), K::StringIdx, K::Simple(T::ModuleRef)]
        }
        T::FieldRva => &[K::U32, K::Simple(T::Field)],
        T::EncLog => &[K::U32, K::U32],
        T::EncMap => &[K::U32],
        T::Assembly => &[
            K::U32,
            K::U16,
            K::U16,
            K::U16,
            K::U16,
            K::U32,
            K::BlobIdx,
            K::StringIdx,
            K::StringIdx,
        ],
        T::AssemblyProcessor => &[K::U32],
        T::AssemblyOS => &[K::U32, K::U32, K::U32],
        // ECMA-335 II 22.5: MajorVersion..Revision U16x4, Flags U32,
        // PublicKeyOrToken BlobIdx, Name StringIdx, Culture StringIdx, HashValue BlobIdx.
        T::AssemblyRef => &[
            K::U16,
            K::U16,
            K::U16,
            K::U16,
            K::U32,
            K::BlobIdx,
            K::StringIdx,
            K::StringIdx,
            K::BlobIdx,
        ],
        T::AssemblyRefProcessor => &[K::U32, K::Simple(T::AssemblyRef)],
        T::AssemblyRefOS => &[K::U32, K::U32, K::U32, K::Simple(T::AssemblyRef)],
        T::File => &[K::U32, K::StringIdx, K::BlobIdx],
        T::ExportedType => {
            &[K::U32, K::U32, K::StringIdx, K::StringIdx, K::Coded(&coded::IMPLEMENTATION)]
        }
        T::ManifestResource => &[K::U32, K::U32, K::StringIdx, K::Coded(&coded::IMPLEMENTATION)],
        T::NestedClass => &[K::Simple(T::TypeDef), K::Simple(T::TypeDef)],
        T::GenericParam => &[K::U16, K::U16, K::Coded(&coded::TYPE_OR_METHOD_DEF), K::StringIdx],
        T::MethodSpec => &[K::Coded(&coded::METHOD_DEF_OR_REF), K::BlobIdx],
        T::GenericParamConstraint => {
            &[K::Simple(T::GenericParam), K::Coded(&coded::TYPE_DEF_OR_REF)]
        }
        // Portable PDB tables (ECMA-335 II §V).
        T::Document => &[K::BlobIdx, K::GuidIdx, K::BlobIdx, K::GuidIdx],
        T::MethodDebugInformation => &[K::Simple(T::Document), K::BlobIdx],
        T::LocalScope => &[
            K::Simple(T::MethodDef),
            K::Simple(T::ImportScope),
            K::Simple(T::LocalVariable),
            K::Simple(T::LocalConstant),
            K::U32,
            K::U32,
        ],
        T::LocalVariable => &[K::U16, K::U16, K::StringIdx],
        T::LocalConstant => &[K::StringIdx, K::BlobIdx],
        T::ImportScope => &[K::Simple(T::ImportScope), K::BlobIdx],
        T::StateMachineMethod => &[K::Simple(T::MethodDef), K::Simple(T::MethodDef)],
        T::CustomDebugInformation => {
            &[K::Coded(&coded::HAS_CUSTOM_DEBUG_INFORMATION), K::GuidIdx, K::BlobIdx]
        } // Every TableIndex variant is covered; the function still returns an
          // Option for forward compatibility with unknown table numbers.
    })
}

/// Encodes `(table, rid)` into the coded-index space of `group`.
pub fn encode_coded(group: &'static CodedIndexGroup, table: TableIndex, rid: u32) -> Result<u64> {
    let tag = group
        .tables
        .iter()
        .position(|&t| t == table)
        .map(|pos| pos as u64 + group.first_tag as u64)
        .ok_or_else(|| {
            Error::argument(format!(
                "table {} does not participate in coded group {}",
                table.name(),
                group.name
            ))
        })?;
    if rid > 0x00FF_FFFF {
        return Err(Error::argument(format!("rid {rid} exceeds 24 bits")));
    }
    Ok(((rid as u64) << group.shift_bits()) | tag)
}

/// Decodes a coded-index cell into its `(table, rid)` pair. The low
/// `shift_bits()` bits select the tagged table; the remainder is the 1-based
/// row id.
pub fn decode_coded(group: &'static CodedIndexGroup, encoded: u64) -> Option<(TableIndex, u32)> {
    let mask = (1u64 << group.shift_bits()) - 1;
    let tag = (encoded & mask) as usize;
    let rid = (encoded >> group.shift_bits()) as u32;
    if (tag as u64) < group.first_tag as u64 {
        // Spec-reserved slot (e.g. CustomAttributeType tags 0-1).
        return None;
    }
    Some((*group.tables.get(tag - group.first_tag as usize)?, rid))
}

/// Layout of one present table inside the `#~` stream.
#[derive(Debug, Clone)]
struct TableLayout {
    row_size: u16,
    /// Byte offset of the first row, relative to the start of the table
    /// stream data (after the header and row-count array).
    offset: u64,
    columns: Vec<ColumnDesc>,
}

/// Complete layout of all tables in one metadata root: row counts, column
/// descriptors, row sizes, and table offsets.
#[derive(Debug, Clone)]
pub struct TableSet {
    layouts: Vec<Option<TableLayout>>,
    counts: [u32; TABLE_COUNT],
    valid: u64,
    heap_flags: u8,
}

impl TableSet {
    /// Computes the layout for every table set in `valid`.
    ///
    /// `row_counts[i]` must hold the row count for table `i` (0 when absent);
    /// `heap_flags` uses the on-disk `HeapSizes` encoding: bit 0 = 4-byte
    /// string indexes, bit 1 = 4-byte GUID indexes, bit 2 = 4-byte blob
    /// indexes.
    ///
    /// Valid bits without a known schema are silently skipped; use
    /// [`TableSet::compute_checked`] to reject them.
    pub fn compute(valid: u64, row_counts: &[u32; TABLE_COUNT], heap_flags: u8) -> TableSet {
        let mut layouts: Vec<Option<TableLayout>> = (0..TABLE_COUNT).map(|_| None).collect();
        // All counts are known before any row size is computed, so width
        // resolution for forward references (e.g. TypeDef -> Field) is exact.
        let mut probe = TableSet { layouts: Vec::new(), counts: *row_counts, valid, heap_flags };
        let mut offset = 0u64;

        for i in 0..TABLE_COUNT {
            if valid >> i & 1 == 0 {
                continue;
            }
            let Some(table) = TableIndex::from_u8(i as u8) else {
                continue;
            };
            let Some(kinds) = column_kinds(table) else {
                continue;
            };

            let mut columns = Vec::with_capacity(kinds.len());
            let mut row_offset = 0u16;
            for &kind in kinds {
                columns.push(ColumnDesc { kind, offset: row_offset });
                row_offset += probe.kind_width(&kind) as u16;
            }

            layouts[i] = Some(TableLayout { row_size: row_offset, offset, columns });
            offset += row_offset as u64 * probe.counts[i] as u64;
        }

        probe.layouts = layouts;
        probe
    }

    /// Like [`TableSet::compute`], but returns an error when any valid bit
    /// refers to a table number without a known schema.
    pub fn compute_checked(
        valid: u64,
        row_counts: &[u32; TABLE_COUNT],
        heap_flags: u8,
    ) -> Result<TableSet> {
        // Scan all 64 bits: valid masks may reference table numbers beyond
        // TABLE_COUNT, which have no schema.
        for i in 0..64u64 {
            if valid >> i & 1 == 0 {
                continue;
            }
            let known =
                u8::try_from(i).ok().and_then(TableIndex::from_u8).and_then(column_kinds).is_some();
            if !known {
                return Err(Error::unsupported(format!("unknown metadata table 0x{i:02x}")));
            }
        }
        Ok(TableSet::compute(valid, row_counts, heap_flags))
    }

    /// The `Valid` bitmask of present tables.
    pub fn valid_mask(&self) -> u64 {
        self.valid
    }

    /// The raw `HeapSizes` flags this layout was computed with.
    pub fn heap_size_flags(&self) -> u8 {
        self.heap_flags
    }

    /// Whether the table has rows.
    pub fn is_present(&self, table: TableIndex) -> bool {
        self.layouts[table as usize].is_some() && self.counts[table as usize] > 0
    }

    /// Number of rows (0 when absent).
    pub fn row_count(&self, table: TableIndex) -> u32 {
        self.counts[table as usize]
    }

    /// Row size in bytes, if present.
    pub fn row_size(&self, table: TableIndex) -> Option<u16> {
        Some(self.layouts[table as usize].as_ref()?.row_size)
    }

    /// Byte offset of the first row relative to the table-stream data, if
    /// present.
    pub fn table_offset(&self, table: TableIndex) -> Option<u64> {
        Some(self.layouts[table as usize].as_ref()?.offset)
    }

    /// Column descriptors, if present.
    pub fn columns(&self, table: TableIndex) -> Option<&[ColumnDesc]> {
        Some(self.layouts[table as usize].as_ref()?.columns.as_slice())
    }

    /// Number of columns (0 when absent).
    pub fn column_count(&self, table: TableIndex) -> usize {
        self.columns(table).map_or(0, <[ColumnDesc]>::len)
    }

    /// Whether the `#Strings` heap needs 4-byte indexes.
    pub fn large_string(&self) -> bool {
        self.heap_flags & 0x1 != 0
    }

    /// Whether the `#GUID` heap needs 4-byte indexes.
    pub fn large_guid(&self) -> bool {
        self.heap_flags & 0x2 != 0
    }

    /// Whether the `#Blob` heap needs 4-byte indexes.
    pub fn large_blob(&self) -> bool {
        self.heap_flags & 0x4 != 0
    }

    /// Resolved physical width in bytes of one column kind under this layout.
    pub fn kind_width(&self, kind: &ColumnKind) -> usize {
        match kind {
            ColumnKind::U8 => 1,
            ColumnKind::U16 => 2,
            ColumnKind::U32 => 4,
            ColumnKind::StringIdx => {
                if self.large_string() {
                    4
                } else {
                    2
                }
            }
            ColumnKind::GuidIdx => {
                if self.large_guid() {
                    4
                } else {
                    2
                }
            }
            ColumnKind::BlobIdx => {
                if self.large_blob() {
                    4
                } else {
                    2
                }
            }
            ColumnKind::Simple(t) => {
                if self.counts[*t as usize] > 0xFFFF {
                    4
                } else {
                    2
                }
            }
            ColumnKind::Coded(group) => {
                let max = group.tables.iter().map(|t| self.counts[*t as usize]).max().unwrap_or(0);
                if max < (1u32 << (16 - group.shift_bits())) {
                    2
                } else {
                    4
                }
            }
        }
    }

    /// Locates one cell: returns its byte offset within the table-stream data
    /// plus its width in bytes.
    pub fn cell_location(&self, table: TableIndex, rid: u32, col: usize) -> Result<(u64, usize)> {
        let layout = self.layouts[table as usize]
            .as_ref()
            .ok_or_else(|| Error::argument(format!("table {} is absent", table.name())))?;
        if rid == 0 || rid > self.counts[table as usize] {
            return Err(Error::argument(format!(
                "rid {rid} out of range for table {} ({} rows)",
                table.name(),
                self.counts[table as usize]
            )));
        }
        let desc = *layout.columns.get(col).ok_or_else(|| {
            Error::argument(format!("column {col} out of range for table {}", table.name()))
        })?;
        let width = self.kind_width(&desc.kind);
        let pos = layout.offset + (rid as u64 - 1) * layout.row_size as u64 + desc.offset as u64;
        Ok((pos, width))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coded_roundtrip_all_groups() {
        let groups: [&'static CodedIndexGroup; 14] = [
            &coded::TYPE_DEF_OR_REF,
            &coded::HAS_CONSTANT,
            &coded::HAS_CUSTOM_ATTRIBUTE,
            &coded::HAS_FIELD_MARSHAL,
            &coded::HAS_DECL_SECURITY,
            &coded::MEMBER_REF_PARENT,
            &coded::HAS_SEMANTICS,
            &coded::METHOD_DEF_OR_REF,
            &coded::MEMBER_FORWARDED,
            &coded::IMPLEMENTATION,
            &coded::CUSTOM_ATTRIBUTE_TYPE,
            &coded::RESOLUTION_SCOPE,
            &coded::TYPE_OR_METHOD_DEF,
            &coded::HAS_CUSTOM_DEBUG_INFORMATION,
        ];
        for g in groups {
            for t in g.tables {
                let enc = encode_coded(g, *t, 42).unwrap();
                assert!(enc <= u32::MAX as u64);
                assert_eq!(decode_coded(g, enc), Some((*t, 42)));
            }
            assert_eq!(
                encode_coded(g, TableIndex::Document, 1).is_err(),
                !g.tables.contains(&TableIndex::Document)
            );
        }
    }

    #[test]
    fn layout_widths_follow_row_and_heap_sizes() {
        let zero = [0u32; TABLE_COUNT];
        // TypeRef + TypeDef + InterfaceImpl + MemberRef present, small heaps.
        let valid = (1 << TableIndex::TypeRef as u64)
            | (1 << TableIndex::TypeDef as u64)
            | (1 << TableIndex::InterfaceImpl as u64)
            | (1 << TableIndex::MemberRef as u64);
        let small = TableSet::compute(valid, &zero, 0);
        // Coded(ResolutionScope) 2 + name 2 + namespace 2.
        assert_eq!(small.row_size(TableIndex::TypeRef), Some(6));
        // Flags 4 + name/namespace 2+2 + base type 2 + field/method lists 2+2.
        assert_eq!(small.row_size(TableIndex::TypeDef), Some(14));
        // Class 2 + interface 2.
        assert_eq!(small.row_size(TableIndex::InterfaceImpl), Some(4));
        // Parent 2 + name 2 + signature 2.
        assert_eq!(small.row_size(TableIndex::MemberRef), Some(6));

        // TypeDef grows past 0xFFFF rows: Simple(TypeDef) and
        // Coded(TypeDefOrRef) both widen to 4 bytes.
        let mut big = zero;
        big[TableIndex::TypeDef as usize] = 0x2_0000;
        let grown = TableSet::compute(valid, &big, 0);
        assert_eq!(grown.row_size(TableIndex::InterfaceImpl), Some(8));
        assert_eq!(grown.row_size(TableIndex::TypeDef), Some(16));
        // MemberRefParent (max TypeDef >= 1<<13) widens too.
        assert_eq!(grown.row_size(TableIndex::MemberRef), Some(8));

        // Large heaps widen only their own index kinds.
        let wide_heaps = TableSet::compute(valid, &zero, 0x7);
        // Scope stays 2; both #Strings indexes widen to 4.
        assert_eq!(wide_heaps.row_size(TableIndex::TypeRef), Some(10));
        assert!(wide_heaps.large_string() && wide_heaps.large_blob());
    }

    #[test]
    fn unknown_valid_bit_is_rejected_by_compute_checked() {
        let counts = [0u32; TABLE_COUNT];
        let ok = TableSet::compute_checked(1 << 0x3F, &counts, 0);
        assert!(matches!(ok, Err(Error::Unsupported(_))));
        let skipped = TableSet::compute(1 << 0x3F, &counts, 0);
        assert!(!skipped.is_present(TableIndex::Module));
    }

    #[test]
    fn portable_pdb_schemas_present() {
        for t in [
            TableIndex::Document,
            TableIndex::MethodDebugInformation,
            TableIndex::LocalScope,
            TableIndex::LocalVariable,
            TableIndex::LocalConstant,
            TableIndex::ImportScope,
            TableIndex::StateMachineMethod,
            TableIndex::CustomDebugInformation,
        ] {
            assert!(column_kinds(t).is_some(), "{} missing", t.name());
        }
        // Document: blob + guid + blob + guid = 8 bytes with small heaps.
        let counts = [0u32; TABLE_COUNT];
        let set = TableSet::compute(1 << TableIndex::Document as u64, &counts, 0);
        assert_eq!(set.row_size(TableIndex::Document), Some(8));
    }
}
