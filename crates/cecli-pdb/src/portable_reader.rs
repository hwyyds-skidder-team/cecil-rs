//! Portable PDB reader: decodes the ECMA-335 §V debug tables (`0x30`–`0x37`)
//! plus the `#Pdb` heap from a standalone `.pdb` metadata root, using
//! [`cecli_metadata::MetadataReader`] for storage access.
//!
//! Ports the reading logic of `Mono.Cecil.Cil/PortablePdb.cs` and the
//! sequence-point / scope decoders of `Mono.Cecil/AssemblyReader.cs`
//! (`ReadSequencePoints`, `ReadLocalScope`, `InitializeStateMachineMethods`,
//! `InitializeDocuments`).
//!
//! ```text
//! Document                name blob | hash-algo guid | hash blob | language guid
//! MethodDebugInformation  document  | blob (sequence-point record stream)
//! LocalScope              method | import | var-list | const-list | start | length
//! StateMachineMethod      move-next | kickoff
//! ```

use std::fmt;

use cecli_core::io::ByteReader;
use cecli_core::{Error, Result, TableIndex, Token};
use cecli_metadata::{MetadataReader, PdbHeap};

use crate::document::Document;

use TableIndex::{
    Document as TDocument, LocalConstant as TLocalConstant, LocalScope as TLocalScope,
    LocalVariable as TLocalVariable, MethodDebugInformation as TMethodDebugInformation,
    MethodDef as TMethodDef, StateMachineMethod as TStateMachineMethod,
};

/// Source line recorded for compiler-generated ("hidden") sequence points.
///
/// Ported verbatim from Mono.Cecil's `AssemblyReader.ReadSequencePoints`
/// (`0xfeefee`), which follows the Roslyn convention for instructions with
/// no user-code mapping.
pub const HIDDEN_LINE: u32 = 0x00FE_EFEE;

/// One IL-to-source mapping decoded from a `MethodDebugInformation` blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequencePoint {
    /// IL offset this point starts at.
    pub offset: i32,
    /// First source line covered (see [`HIDDEN_LINE`] when hidden).
    pub start_line: u32,
    /// First source column covered (0 for hidden points).
    pub start_column: u32,
    /// Last source line covered, inclusive.
    pub end_line: u32,
    /// Last source column covered, inclusive.
    pub end_column: u32,
}

impl SequencePoint {
    /// Whether this point maps to compiler-generated code rather than user
    /// source (`StartLine == EndLine == 0xfeefee`, as in Mono.Cecil).
    pub fn is_hidden(&self) -> bool {
        self.start_line == HIDDEN_LINE && self.start_line == self.end_line
    }
}

/// One `LocalScope` table row: an IL range owning variables and constants.
///
/// Field notes:
/// - `try_start` / `try_length` carry the scope IL range (`ScopeStart`,
///   `ScopeLength`) - the only span the format defines.
/// - `handler_start` / `handler_length` are always `-1`; portable PDB rows
///   carry no handler range. They exist so consumers can share code across
///   symbol formats.
/// - `kind` is always `0` for portable PDB scopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalScope {
    /// Owning method as a `MethodDef` token.
    pub method: Token,
    /// 1-based `ImportScope` row rid, or 0 when the scope imports nothing.
    pub import_scope: u32,
    /// 1-based `LocalVariable` row rids owned by this scope, in row order.
    pub variables: Vec<u32>,
    /// 1-based `LocalConstant` row rids owned by this scope, in row order.
    pub constants: Vec<u32>,
    /// Scope kind (always 0 in portable PDB files).
    pub kind: u32,
    /// IL offset where the scope starts.
    pub try_start: i32,
    /// Length in bytes of the scoped IL range.
    pub try_length: i32,
    /// Handler IL offset (always -1 in portable PDB files).
    pub handler_start: i32,
    /// Handler length (always -1 in portable PDB files).
    pub handler_length: i32,
}

/// One `LocalVariable` row: a named local slot within a scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVariableInfo {
    /// Slot index in the method's local signature.
    pub index: u16,
    /// `VariableAttributes` bit flags (e.g. debugger-hidden).
    pub attributes: u16,
    /// Name from the `#Strings` heap.
    pub name: String,
}

/// One `LocalConstant` row: a compile-time constant visible in a scope.
///
/// The signature blob keeps the ECMA-335 §V.C constant encoding: the element
/// type byte followed by the value (raw, undecoded - full type decoding
/// belongs to the facade layer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalConstantInfo {
    /// Constant name from the `#Strings` heap.
    pub name: String,
    /// Raw signature blob (element type + value bytes).
    pub signature: Vec<u8>,
}

/// Decoded sequence-point payload for one method: the initial document, the
/// points, and each point's document reference (records may switch documents).
type SequencePoints = (u32, Vec<SequencePoint>, Vec<u32>);

/// Reader over one portable PDB file: a metadata root carrying the debug
/// tables and the `#Pdb` heap.
#[derive(Debug, Clone)]
pub struct PortablePdbReader<'a> {
    md: MetadataReader<'a>,
}

impl fmt::Display for PortablePdbReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "portable pdb ({}, {} documents)",
            self.md.version_string(),
            self.md.row_count(TDocument)
        )
    }
}

impl<'a> PortablePdbReader<'a> {
    /// Parses a standalone portable PDB image.
    ///
    /// Returns an error when the bytes are not a metadata root or lack the
    /// mandatory `#Pdb` heap.
    pub fn parse(pdb_bytes: &'a [u8]) -> Result<Self> {
        let md = MetadataReader::parse(pdb_bytes)?;
        if md.heaps().pdb.is_none() {
            return Err(Error::bad_image("not a portable pdb: missing #Pdb heap"));
        }
        Ok(PortablePdbReader { md })
    }

    /// The underlying metadata reader (tables + heaps).
    pub fn metadata(&self) -> &MetadataReader<'a> {
        &self.md
    }

    /// The `#Pdb` heap, guaranteed present by [`Self::parse`].
    fn pdb(&self) -> &PdbHeap<'a> {
        self.md.heaps().pdb.as_ref().expect("#Pdb checked in parse")
    }

    /// The 20-byte PDB id (16-byte content GUID + 4-byte unauthenticated
    /// hash) from the `#Pdb` heap.
    pub fn pdb_id(&self) -> [u8; 20] {
        let mut id = [0u8; 20];
        id.copy_from_slice(self.pdb().id());
        id
    }

    /// Entry point method token recorded in the `#Pdb` heap
    /// (`Token::NIL` for DLLs).
    pub fn entry_point(&self) -> Token {
        Token(self.pdb().entry_point())
    }

    /// Blob heap lookup; index 0 yields an empty blob.
    fn blob(&self, index: u64) -> Result<&'a [u8]> {
        if index == 0 {
            return Ok(&[]);
        }
        self.md.heaps().blob.get(index as u32)
    }

    /// Reads every `Document` row in table order.
    pub fn documents(&self) -> Result<Vec<Document>> {
        (1..=self.md.row_count(TDocument)).map(|rid| self.document(rid)).collect()
    }

    /// Reads one `Document` row (1-based rid).
    ///
    /// The name blob decodes as a separator byte followed by compressed
    /// `#Blob` indices naming path segments (`AssemblyReader.ReadDocumentName`).
    pub fn document(&self, rid: u32) -> Result<Document> {
        let cells = self.md.row(TDocument, rid)?;
        let name_data = self.blob(cells[0])?;
        Ok(Document {
            name: self.decode_document_name(name_data)?,
            hash_algorithm: self.guid(cells[1])?,
            hash: self.blob(cells[2])?.to_vec(),
            language: self.guid(cells[3])?,
        })
    }

    fn guid(&self, index: u64) -> Result<[u8; 16]> {
        self.md.heaps().guid.get(index as u32)
    }

    /// Decodes the sequence points of one method (1-based
    /// `MethodDebugInformation` rid).
    ///
    /// Returns `None` when the row exists but carries no information blob.
    /// The tuple's rid is the document the stream starts in; individual
    /// points may switch documents mid-stream (query
    /// [`Self::sequence_point_documents`] for the per-point mapping).
    pub fn sequence_points(&self, method_rid: u32) -> Result<Option<(u32, Vec<SequencePoint>)>> {
        self.decode_sequence_points(method_rid).map(|opt| opt.map(|(doc, points, _)| (doc, points)))
    }

    /// Per-point document rids aligned with
    /// [`Self::sequence_points`]' vector (empty when there are no points).
    ///
    /// A `MethodDebugInformation` stream can switch documents between
    /// records (`delta_il == 0` followed by a document index), so each
    /// point carries its own document reference.
    pub fn sequence_point_documents(&self, method_rid: u32) -> Result<Vec<u32>> {
        Ok(self.decode_sequence_points(method_rid)?.map(|(_, _, docs)| docs).unwrap_or_default())
    }

    /// Shared decoder for the sequence-point record stream; ports
    /// `AssemblyReader.ReadSequencePoints` exactly, including the hidden
    /// sentinel and document switches.
    fn decode_sequence_points(&self, method_rid: u32) -> Result<Option<SequencePoints>> {
        let count = self.md.row_count(TMethodDebugInformation);
        if method_rid == 0 || method_rid > count {
            return Err(Error::argument(format!(
                "method rid {method_rid} outside MethodDebugInformation ({} rows)",
                count
            )));
        }

        let cells = self.md.row(TMethodDebugInformation, method_rid)?;
        let row_document = cells[0] as u32;
        let signature_index = cells[1] as u32;
        if signature_index == 0 {
            return Ok(None);
        }

        let data = self.blob(signature_index as u64)?;
        let mut r = ByteReader::new(data);

        // Leading local-signature token: parsed but unused for sequence points.
        let _local_sig_token = r.compressed_u32()?;

        // When the row names no document, the stream opens with one.
        let mut document = if row_document == 0 { r.compressed_u32()? } else { row_document };
        let initial_document = document;

        let mut points = Vec::new();
        let mut documents = Vec::new();
        let mut offset: i32 = 0;
        let mut start_line: i32 = 0;
        let mut start_column: i32 = 0;
        let mut first_non_hidden = true;
        let mut iteration: u32 = 0;

        loop {
            if r.remaining() == 0 {
                break;
            }

            let delta_il = r.compressed_u32()? as i32;
            if iteration > 0 && delta_il == 0 {
                // Document switch: the next compressed uint selects the
                // document for subsequent records.
                document = r.compressed_u32()?;
                iteration += 1;
                continue;
            }

            offset = offset.wrapping_add(delta_il);

            let delta_lines = r.compressed_u32()? as i32;
            let delta_columns =
                if delta_lines == 0 { r.compressed_u32()? as i32 } else { r.compressed_i32()? };

            if delta_lines == 0 && delta_columns == 0 {
                // Hidden sequence point (compiler-generated code).
                points.push(SequencePoint {
                    offset,
                    start_line: HIDDEN_LINE,
                    start_column: 0,
                    end_line: HIDDEN_LINE,
                    end_column: 0,
                });
                documents.push(document);
                iteration += 1;
                continue;
            }

            if first_non_hidden {
                start_line = r.compressed_u32()? as i32;
                start_column = r.compressed_u32()? as i32;
                first_non_hidden = false;
            } else {
                start_line = start_line.wrapping_add(r.compressed_i32()?);
                start_column = start_column.wrapping_add(r.compressed_i32()?);
            }

            points.push(SequencePoint {
                offset,
                start_line: start_line as u32,
                start_column: start_column as u32,
                end_line: start_line.wrapping_add(delta_lines) as u32,
                end_column: start_column.wrapping_add(delta_columns) as u32,
            });
            documents.push(document);
            iteration += 1;
        }

        Ok(Some((initial_document, points, documents)))
    }

    /// Reads every `LocalScope` row belonging to the given method
    /// (1-based `MethodDef` rid), in table order.
    pub fn local_scopes(&self, method_rid: u32) -> Result<Vec<LocalScope>> {
        let mut scopes = Vec::new();
        let count = self.md.row_count(TLocalScope);
        for rid in 1..=count {
            let cells = self.md.row(TLocalScope, rid)?;
            let method_cell = cells[0] as u32;
            if method_cell != method_rid {
                continue;
            }
            let (var_start, var_len) = self.list_range(TLocalScope, TLocalVariable, rid, 2)?;
            let (const_start, const_len) = self.list_range(TLocalScope, TLocalConstant, rid, 3)?;
            scopes.push(LocalScope {
                method: Token::new(TMethodDef, method_cell),
                import_scope: cells[1] as u32,
                variables: consecutive(var_start, var_len),
                constants: consecutive(const_start, const_len),
                kind: 0,
                try_start: cells[4] as u32 as i32,
                try_length: cells[5] as u32 as i32,
                handler_start: -1,
                handler_length: -1,
            });
        }
        Ok(scopes)
    }

    /// List-range resolution shared with Cecil's `ReadListRange`: a row's
    /// run extends until the next row's start index (or the target table's
    /// end for the final row).
    fn list_range(
        &self,
        table: TableIndex,
        target: TableIndex,
        rid: u32,
        col: usize,
    ) -> Result<(u32, u32)> {
        let start = self.md.column(table, rid, col)? as u32;
        if start == 0 {
            return Ok((0, 0));
        }
        let next = if rid == self.md.row_count(table) {
            self.md.row_count(target) + 1
        } else {
            self.md.column(table, rid + 1, col)? as u32
        };
        if next < start {
            return Err(Error::bad_image(format!(
                "corrupt list range in table {}: start {} beyond end {}",
                table.name(),
                start,
                next
            )));
        }
        Ok((start, next - start))
    }

    /// Reads the `LocalVariable` rows referenced by `scope`, in rid order.
    pub fn local_variables(&self, scope: &LocalScope) -> Result<Vec<LocalVariableInfo>> {
        scope
            .variables
            .iter()
            .map(|&rid| {
                let cells = self.md.row(TLocalVariable, rid)?;
                Ok(LocalVariableInfo {
                    attributes: cells[0] as u16,
                    index: cells[1] as u16,
                    name: self.md.heaps().strings.get(cells[2] as u32)?.to_owned(),
                })
            })
            .collect()
    }

    /// Reads the `LocalConstant` rows referenced by `scope`, in rid order.
    pub fn local_constants(&self, scope: &LocalScope) -> Result<Vec<LocalConstantInfo>> {
        scope
            .constants
            .iter()
            .map(|&rid| {
                let cells = self.md.row(TLocalConstant, rid)?;
                Ok(LocalConstantInfo {
                    name: self.md.heaps().strings.get(cells[0] as u32)?.to_owned(),
                    signature: self.blob(cells[1])?.to_vec(),
                })
            })
            .collect()
    }

    /// Decodes a `Document` name blob: a separator byte followed by
    /// compressed `#Blob` heap indices naming UTF-8 path segments joined
    /// with the separator (segments concatenate directly when the
    /// separator byte is zero). Ports `AssemblyReader.ReadDocumentName`.
    fn decode_document_name(&self, data: &[u8]) -> Result<String> {
        let mut r = ByteReader::new(data);
        let separator = r.u8()? as char;
        let mut name = String::new();
        let mut first = true;
        while r.remaining() > 0 {
            if !first && separator != '\0' {
                name.push(separator);
            }
            first = false;
            let part = r.compressed_u32()?;
            if part != 0 {
                let bytes = self.blob(part as u64)?;
                name.push_str(
                    std::str::from_utf8(bytes)
                        .map_err(|_| Error::bad_image("document name segment is not utf-8"))?,
                );
            }
        }
        Ok(name)
    }

    /// Returns the kick-off (async/iterator entry) method rid registered
    /// for `method_rid` in the `StateMachineMethod` table, if any.
    ///
    /// Mirrors Cecil: rows map each `MoveNextMethod` rid to its
    /// `KickoffMethod` rid, and lookups go move-next → kick-off.
    pub fn state_machine_kickoff(&self, method_rid: u32) -> Option<u32> {
        let count = self.md.row_count(TStateMachineMethod);
        for rid in 1..=count {
            let Ok(cells) = self.md.row(TStateMachineMethod, rid) else {
                continue;
            };
            if cells[0] as u32 == method_rid {
                return Some(cells[1] as u32);
            }
        }
        None
    }
}

/// Materializes `length` consecutive 1-based rids beginning at `start`.
fn consecutive(start: u32, length: u32) -> Vec<u32> {
    if length == 0 {
        Vec::new()
    } else {
        (start..start + length).collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use cecli_core::io::ByteWriter;
    use cecli_metadata::{parse_root, stream_slice, write_root, MetadataBuilder};

    // -- fixture helpers -------------------------------------------------

    /// Composes a `Document` name blob from a separator and literal segments.
    /// Segment strings are inserted into `#Blob` first, then referenced by
    /// compressed index inside the name blob.
    fn document_name(builder: &mut MetadataBuilder, separator: u8, parts: &[&str]) -> Vec<u8> {
        let mut w = ByteWriter::new();
        w.u8(separator);
        for part in parts {
            let idx = builder.insert_blob(part.as_bytes());
            w.compressed_u32(idx);
        }
        w.into_vec()
    }

    /// Builds the sequence-point record stream for the fixture method.
    ///
    /// Record layout per ECMA-335 §II.C (ported from Cecil
    /// `ReadSequencePoints`): `delta_il`, `delta_lines`,
    /// `delta_columns` (signed when lines move), then either absolute
    /// start line/column (first non-hidden record) or signed
    /// line/column deltas. Hidden records are three zero deltas.
    fn sequence_point_blob() -> Vec<u8> {
        let mut w = ByteWriter::new();
        w.compressed_u32(0); // local signature token (unused)
                             // Hidden point at offset 0.
        w.compressed_u32(0);
        w.compressed_u32(0);
        w.compressed_u32(0);
        // First non-hidden: offset 4, line 100..101, column 1..11.
        w.compressed_u32(4); // delta il
        w.compressed_u32(1); // delta lines
        w.compressed_i32(10); // delta columns
        w.compressed_u32(100); // absolute start line
        w.compressed_u32(1); // absolute start column
                             // Offset 10: line 102..104, column 11..19.
        w.compressed_u32(6); // delta il
        w.compressed_u32(2); // delta lines
        w.compressed_i32(8); // delta columns
        w.compressed_i32(2); // delta start line
        w.compressed_i32(10); // delta start column
                              // Mid-stream document switch to document rid 2.
        w.compressed_u32(0);
        w.compressed_u32(2);
        // Offset 11 in document 2: line 104..105, column 15..11.
        w.compressed_u32(1); // delta il
        w.compressed_u32(1); // delta lines
        w.compressed_i32(-4); // delta columns
        w.compressed_i32(2); // delta start line
        w.compressed_i32(4); // delta start column
        w.into_vec()
    }

    /// Truncated stream: dies mid-record after the line delta.
    fn truncated_sequence_point_blob() -> Vec<u8> {
        let mut w = ByteWriter::new();
        w.compressed_u32(0); // local signature token
        w.compressed_u32(4); // delta il
        w.compressed_u32(1); // delta lines
                             // EOF before delta columns.
        w.into_vec()
    }

    /// Builds a complete standalone portable PDB image around the given
    /// `MethodDebugInformation` blob for method rid 1.
    fn build_pdb(mdi_blob: &[u8]) -> Vec<u8> {
        let mut b = MetadataBuilder::new("v4.0.30319");

        // Heaps.
        let s_x = b.insert_string("x") as u64;
        let s_y = b.insert_string("y") as u64;
        let s_pi = b.insert_string("PI") as u64;

        let alg_csharp: [u8; 16] = [
            0x88, 0x29, 0x85, 0xA2, 0x1F, 0x72, 0xCE, 0x46, 0xA9, 0x6B, 0x35, 0xFD, 0x0B, 0x25,
            0xFA, 0xF9,
        ];
        let lang_csharp: [u8; 16] = [
            0x03, 0x63, 0x59, 0xFF, 0xB5, 0x86, 0xC2, 0x4F, 0xAB, 0xF4, 0xD7, 0xE8, 0xFE, 0x35,
            0xE5, 0x1C,
        ];
        let alg_other = [0x21u8; 16];
        let lang_other = [0x42u8; 16];
        let alg1 = b.insert_guid(&alg_csharp) as u64;
        let lang1 = b.insert_guid(&lang_csharp) as u64;
        let alg2 = b.insert_guid(&alg_other) as u64;
        let lang2 = b.insert_guid(&lang_other) as u64;

        let name1_blob = document_name(&mut b, b'/', &["src", "prog.cs"]);
        let name2_blob = document_name(&mut b, 0, &["unit", "tests.cs"]);

        let hash1 = b.insert_blob(&[0x11u8; 32]) as u64;
        let name1 = b.insert_blob(&name1_blob) as u64;
        let hash2 = b.insert_blob(&[]) as u64; // empty hash -> blob index 0
        let name2 = b.insert_blob(&name2_blob) as u64;

        let seq1 = b.insert_blob(mdi_blob) as u64;
        let const_sig = b.insert_blob(&{
            let mut sig = ByteWriter::new();
            sig.u8(0x0C); // ELEMENT_TYPE_R8
            sig.f64(core::f64::consts::PI);
            sig.into_vec()
        }) as u64;

        // Documents (2 rows).
        b.add_row(TableIndex::Document, &[name1, alg1, hash1, lang1]).unwrap();
        b.add_row(TableIndex::Document, &[name2, alg2, hash2, lang2]).unwrap();

        // MethodDebugInformation: rid 1 carries points, rid 2 is empty.
        b.add_row(TableIndex::MethodDebugInformation, &[1, seq1]).unwrap();
        b.add_row(TableIndex::MethodDebugInformation, &[2, 0]).unwrap();

        // Import scope rid 1 (no parent, empty imports blob).
        b.add_row(TableIndex::ImportScope, &[0, 0]).unwrap();

        let lv1 = b.add_row(TableIndex::LocalVariable, &[0, 0, s_x]).unwrap() as u64;
        let _lv2 = b.add_row(TableIndex::LocalVariable, &[0, 1, s_y]).unwrap() as u64;
        let lc1 = b.add_row(TableIndex::LocalConstant, &[s_pi, const_sig]).unwrap() as u64;

        // One scope over method 1 covering IL [0, 12).
        b.add_row(TableIndex::LocalScope, &[1, 1, lv1, lc1, 0, 12]).unwrap();

        // State machine: move-next method 2 kicks off at method 1.
        b.add_row(TableIndex::StateMachineMethod, &[2, 1]).unwrap();

        // Capture debug-table row counts for the #Pdb heap before finalize.
        let debug_tables: Vec<(TableIndex, u32)> = [
            TableIndex::Document,
            TableIndex::MethodDebugInformation,
            TableIndex::LocalScope,
            TableIndex::LocalVariable,
            TableIndex::LocalConstant,
            TableIndex::ImportScope,
            TableIndex::StateMachineMethod,
        ]
        .into_iter()
        .filter_map(|t| {
            let n = b.row_count(t);
            (n > 0).then_some((t, n))
        })
        .collect();

        let base = b.finalize();

        // Re-emit the BSJB root with an appended #Pdb stream (the builder
        // itself emits type-system roots only).
        let header = parse_root(&base).expect("fixture parses");
        let mut streams: Vec<(&str, &[u8])> = header
            .streams
            .iter()
            .map(|s| {
                let payload = stream_slice(&base, s).expect("stream bounds");
                (s.name.as_str(), payload)
            })
            .collect();

        let pdb_payload = {
            let mut w = ByteWriter::new();
            w.bytes(&[0xC0u8; 20]); // 20-byte PDB id
            w.u32(0x0600_0001); // entry point token
            let mut mask: u64 = 0;
            for (t, _) in &debug_tables {
                mask |= 1u64 << (*t as u8);
            }
            w.u64(mask);
            for (_, n) in &debug_tables {
                w.u32(*n);
            }
            w.into_vec()
        };
        streams.push(("#Pdb", pdb_payload.as_slice()));

        write_root(header.version.trim_end_matches('\0'), &streams)
    }

    // -- acceptance tests -------------------------------------------------

    #[test]
    fn roundtrip_documents_and_id() {
        let bytes = build_pdb(&sequence_point_blob());
        let reader = PortablePdbReader::parse(&bytes).expect("parses");

        assert_eq!(reader.pdb_id(), [0xC0u8; 20]);
        assert_eq!(reader.entry_point(), Token(0x0600_0001));

        let docs = reader.documents().expect("documents");
        assert_eq!(docs.len(), 2);

        // Separator '/' joins segments; zero separator concatenates directly.
        assert_eq!(docs[0].name, "src/prog.cs");
        assert_eq!(docs[1].name, "unittests.cs");

        assert_eq!(docs[0].hash_algorithm, ALG_CSHARP);
        assert_eq!(docs[0].language, LANG_CSHARP);
        assert_eq!(docs[0].hash, vec![0x11u8; 32]);

        assert_eq!(docs[1].hash_algorithm, [0x21u8; 16]);
        assert_eq!(docs[1].language, [0x42u8; 16]);
        assert!(docs[1].hash.is_empty());

        assert_eq!(docs[0].to_string(), "src/prog.cs");
    }

    static ALG_CSHARP: [u8; 16] = [
        0x88, 0x29, 0x85, 0xA2, 0x1F, 0x72, 0xCE, 0x46, 0xA9, 0x6B, 0x35, 0xFD, 0x0B, 0x25, 0xFA,
        0xF9,
    ];
    static LANG_CSHARP: [u8; 16] = [
        0x03, 0x63, 0x59, 0xFF, 0xB5, 0x86, 0xC2, 0x4F, 0xAB, 0xF4, 0xD7, 0xE8, 0xFE, 0x35, 0xE5,
        0x1C,
    ];

    #[test]
    fn sequence_points_roundtrip() {
        let bytes = build_pdb(&sequence_point_blob());
        let reader = PortablePdbReader::parse(&bytes).unwrap();

        let (doc, points) = reader.sequence_points(1).expect("points").expect("some");
        assert_eq!(doc, 1);
        assert_eq!(points.len(), 4);

        // Hidden sentinel point at offset 0.
        assert!(points[0].is_hidden());
        assert_eq!(points[0].offset, 0);
        assert_eq!(points[0].start_line, HIDDEN_LINE);
        assert_eq!(points[0].end_line, HIDDEN_LINE);
        assert_eq!(points[0].start_column, 0);
        assert_eq!(points[0].end_column, 0);

        // First non-hidden record resolves absolute coordinates.
        assert!(!points[1].is_hidden());
        assert_eq!(points[1].offset, 4);
        assert_eq!(points[1].start_line, 100);
        assert_eq!(points[1].start_column, 1);
        assert_eq!(points[1].end_line, 101);
        assert_eq!(points[1].end_column, 11);

        // Deltas accumulate onto the running position.
        assert_eq!(points[2].offset, 10);
        assert_eq!(points[2].start_line, 102);
        assert_eq!(points[2].start_column, 11);
        assert_eq!(points[2].end_line, 104);
        assert_eq!(points[2].end_column, 19);

        // Record after the document switch.
        assert_eq!(points[3].offset, 11);
        assert_eq!(points[3].start_line, 104);
        assert_eq!(points[3].end_line, 105);
        assert_eq!(points[3].start_column, 15);
        assert_eq!(points[3].end_column, 11);

        // Per-point document mapping reflects the mid-stream switch.
        let docs = reader.sequence_point_documents(1).unwrap();
        assert_eq!(docs, vec![1, 1, 1, 2]);
    }

    #[test]
    fn empty_debug_information_is_none() {
        let bytes = build_pdb(&sequence_point_blob());
        let reader = PortablePdbReader::parse(&bytes).unwrap();
        // Row 2 exists with blob index 0.
        assert!(reader.sequence_points(2).unwrap().is_none());
        assert!(reader.sequence_point_documents(2).unwrap().is_empty());
        // Out-of-range rid is an error, not None.
        assert!(reader.sequence_points(9).is_err());
    }

    #[test]
    fn scopes_locals_and_constants() {
        let bytes = build_pdb(&sequence_point_blob());
        let reader = PortablePdbReader::parse(&bytes).unwrap();

        let scopes = reader.local_scopes(1).expect("scopes");
        assert_eq!(scopes.len(), 1);
        let scope = &scopes[0];
        assert_eq!(scope.method, Token::new(TableIndex::MethodDef, 1));
        assert_eq!(scope.import_scope, 1);
        assert_eq!(scope.try_start, 0);
        assert_eq!(scope.try_length, 12);
        assert_eq!(scope.handler_start, -1);
        assert_eq!(scope.handler_length, -1);

        let vars = reader.local_variables(scope).unwrap();
        assert_eq!(
            vars,
            vec![
                LocalVariableInfo { index: 0, attributes: 0, name: "x".into() },
                LocalVariableInfo { index: 1, attributes: 0, name: "y".into() },
            ]
        );

        let consts = reader.local_constants(scope).unwrap();
        assert_eq!(consts.len(), 1);
        assert_eq!(consts[0].name, "PI");
        // Element-type byte 0x0C (R8) + little-endian f64 payload.
        assert_eq!(consts[0].signature[0], 0x0C);
        assert_eq!(consts[0].signature.len(), 9);

        assert!(reader.local_scopes(2).unwrap().is_empty());
    }

    #[test]
    fn state_machine_pairs() {
        let bytes = build_pdb(&sequence_point_blob());
        let reader = PortablePdbReader::parse(&bytes).unwrap();
        assert_eq!(reader.state_machine_kickoff(2), Some(1));
        assert_eq!(reader.state_machine_kickoff(1), None);
        assert_eq!(reader.state_machine_kickoff(99), None);
    }

    #[test]
    fn missing_pdb_heap_is_rejected() {
        // Rebuild the fixture without appending the #Pdb stream: take only
        // the original builder output by parsing and re-writing the streams
        // minus #Pdb.
        let bytes = build_pdb(&sequence_point_blob());
        let header = parse_root(&bytes).unwrap();
        let streams: Vec<(&str, &[u8])> = header
            .streams
            .iter()
            .filter(|s| s.name != "#Pdb")
            .map(|s| (s.name.as_str(), stream_slice(&bytes, s).unwrap()))
            .collect();
        let bare = write_root(header.version.trim_end_matches('\0'), &streams);

        match PortablePdbReader::parse(&bare) {
            Err(Error::BadImage(msg)) => assert!(msg.contains("#Pdb")),
            other => panic!("expected missing-#Pdb error, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn truncated_sequence_stream_is_error() {
        let bytes = build_pdb(&truncated_sequence_point_blob());
        let reader = PortablePdbReader::parse(&bytes).unwrap();
        assert!(reader.sequence_points(1).is_err(), "mid-record EOF must surface as Err");
    }

    #[test]
    fn garbage_input_is_error() {
        assert!(PortablePdbReader::parse(&[0u8; 64]).is_err());
        assert!(PortablePdbReader::parse(&[]).is_err());
    }
}
