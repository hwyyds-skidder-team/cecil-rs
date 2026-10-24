//! Portable PDB writer: builds the ECMA-335 Part V debug tables (`0x30`
//! –`0x37`) plus the `#Pdb` heap and serializes them into a standalone BSJB
//! metadata root, mirroring [`crate::portable_reader::PortablePdbReader`].
//!
//! Ports the emission logic of `Mono.Cecil.Cil/PortablePdb.cs`,
//! `AssemblyWriter.cs` (`AddDocuments`, `AddMethodDebugInformation`,
//! `AddLocalScope`, `GetDocumentNameSignature`) and
//! `PortablePdbWriter.WritePdbHeap`.
//!
//! Layout summary:
//!
//! ```text
//! Document                name blob | hash-algo guid | hash blob | language guid
//! MethodDebugInformation  document  | blob (sequence-point record stream)
//! LocalScope              method | import | var-list | const-list | start | length
//! LocalVariable           attributes | index | name
//! LocalConstant           name | signature blob
//! ImportScope             parent | imports blob
//! ```
//!
//! The `MethodDebugInformation` table is kept rid-aligned with the module's
//! `MethodDef` table, including methods without sequence points. Associated
//! type-system row counts live in `#Pdb`; only debug tables live in `#~`.

use std::collections::HashMap;

use cecil_core::io::ByteWriter;
use cecil_core::token::coded;
use cecil_core::token::{TableIndex, Token};
use cecil_core::{Error, Result};
use cecil_metadata::MetadataBuilder;

use super::portable_reader::SequencePoint;

const TYPE_SYSTEM_TABLE_COUNT: usize = TableIndex::PORTABLE_PDB_FIRST as usize;

/// Handle to a row in the `Document` table (1-based rid).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DocumentHandle(pub u32);

/// Handle to a registered `LocalScope` row (1-based source rid). Debug
/// references using this handle are relocated when finalization sorts scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopeHandle(pub u32);

/// One `MethodDebugInformation` slot keyed by the owning method's rid.
#[derive(Debug, Default, Clone)]
struct MethodDebugEntry {
    /// `Document` rid recorded in the row's document column (0 = none).
    document_rid: u32,
    /// Raw sequence points, encoded into a blob at finalize time.
    points: Option<Vec<SequencePoint>>,
    /// Per-point documents for a method that spans more than one source file.
    point_documents: Option<Vec<u32>>,
    /// Stand-alone signature rid written as the blob's leading token
    /// (readers skip it; kept for byte-level compatibility with Roslyn).
    local_sig_rid: u32,
}

/// One buffered `Document` row (cells resolved against the heaps at add time).
#[derive(Debug, Clone, Copy)]
struct DocumentRow {
    name_blob: u32,
    hash_algorithm_guid: u32,
    hash_blob: u32,
    language_guid: u32,
}

/// One buffered `ImportScope` row.
#[derive(Debug, Clone, Copy)]
struct ImportScopeRow {
    parent_rid: u32,
    imports_blob: u32,
}

/// One buffered `LocalVariable` row.
#[derive(Debug, Clone)]
struct LocalVariableRow {
    attributes: u16,
    index: u16,
    name_string: u32,
}

/// One buffered `LocalConstant` row.
#[derive(Debug, Clone, Copy)]
struct LocalConstantRow {
    name_string: u32,
    signature_blob: u32,
}

/// One buffered `CustomDebugInformation` row.
#[derive(Debug, Clone, Copy)]
struct CustomDebugInformationRow {
    /// Encoded `HasCustomDebugInformation` cell of the parent.
    parent_cell: u32,
    /// `#GUID` index of the kind GUID.
    kind_guid: u32,
    /// `#Blob` index of the raw value.
    value_blob: u32,
}

/// One buffered `LocalScope` row.
#[derive(Debug, Clone, Copy)]
struct LocalScopeRow {
    method_rid: u32,
    import_scope_rid: u32,
    variable_list_start: u32,
    constant_list_start: u32,
    start_offset: i32,
    length: i32,
}

/// Builder accumulating a module's portable-PDB debug information and
/// serializing it into standalone `.pdb` bytes.
///
/// Rows are buffered and flushed deterministically at
/// [`PortablePdbBuilder::finalize`], including required scope/CDI sorting.
/// Heap entries are interned eagerly so
/// duplicate names, hashes, and GUIDs fold like in Mono.Cecil.
#[derive(Debug)]
pub struct PortablePdbBuilder {
    metadata: MetadataBuilder,
    /// Documents deduped by name, mirroring Cecil's `document_map`.
    documents: HashMap<String, DocumentHandle>,
    document_rows: Vec<DocumentRow>,
    import_scope_rows: Vec<ImportScopeRow>,
    variable_rows: Vec<LocalVariableRow>,
    constant_rows: Vec<LocalConstantRow>,
    scope_rows: Vec<LocalScopeRow>,
    /// Buffered `CustomDebugInformation` rows, in `add` order.
    cdi_rows: Vec<CustomDebugInformationRow>,
    /// `MethodDef` rid -> debug-information slot.
    method_debug: HashMap<u32, MethodDebugEntry>,
    entry_point: Token,
    pdb_id: [u8; 20],
    type_system_counts: Option<[u32; TYPE_SYSTEM_TABLE_COUNT]>,
}

impl Default for PortablePdbBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PortablePdbBuilder {
    /// Creates an empty builder emitting the default runtime version string
    /// (`v4.0.30319`).
    pub fn new() -> Self {
        PortablePdbBuilder::with_version("v4.0.30319")
    }

    /// Creates an empty builder emitting `version` as the metadata root's
    /// runtime version string.
    pub fn with_version(version: &str) -> Self {
        PortablePdbBuilder {
            metadata: MetadataBuilder::new(version),
            documents: HashMap::new(),
            document_rows: Vec::new(),
            import_scope_rows: Vec::new(),
            variable_rows: Vec::new(),
            constant_rows: Vec::new(),
            scope_rows: Vec::new(),
            cdi_rows: Vec::new(),
            method_debug: HashMap::new(),
            entry_point: Token::NIL,
            pdb_id: [0; 20],
            type_system_counts: None,
        }
    }

    /// Adds a source document, returning its handle.
    ///
    /// Documents with identical names fold onto the same row (Cecil dedups by
    /// URL). `hash_algorithm` and `language` are GUID bytes (SHA-1/SHA-256
    /// algorithm and source-language GUIDs); `hash` is the raw file hash.
    ///
    /// The name is encoded as a document-name blob: a separator byte followed
    /// by compressed `#Blob` indices of the path segments
    /// (`AssemblyWriter.GetDocumentNameSignature`). The dominant of `/` and
    /// `\` becomes the separator; names without either are stored whole.
    pub fn add_document(
        &mut self,
        name: &str,
        hash_algorithm: [u8; 16],
        hash: &[u8],
        language: [u8; 16],
    ) -> DocumentHandle {
        if let Some(&handle) = self.documents.get(name) {
            return handle;
        }
        let name_blob = self.insert_document_name(name);
        let row = DocumentRow {
            name_blob,
            hash_algorithm_guid: self.metadata.insert_guid(&hash_algorithm),
            hash_blob: self.metadata.insert_blob(hash),
            language_guid: self.metadata.insert_guid(&language),
        };
        self.document_rows.push(row);
        let handle = DocumentHandle(self.document_rows.len() as u32);
        self.documents.insert(name.to_owned(), handle);
        handle
    }

    /// Encodes a document name into a fresh `#Blob` entry and returns its
    /// index. Empty path segments are recorded as compressed zeroes.
    fn insert_document_name(&mut self, name: &str) -> u32 {
        let separator = document_name_separator(name);
        let mut w = ByteWriter::new();
        w.u8(separator.map(|c| c as u8).unwrap_or(0));
        match separator {
            None => {
                let idx = self.metadata.insert_blob(name.as_bytes());
                w.compressed_u32(idx);
            }
            Some(sep) => {
                for part in name.split(sep) {
                    let idx = self.metadata.insert_blob(part.as_bytes());
                    w.compressed_u32(idx);
                }
            }
        }
        self.metadata.insert_blob(w.as_slice())
    }

    /// Registers the sequence points of one method.
    ///
    /// `doc` must be a handle returned by [`Self::add_document`]; every point
    /// of the method records against it (the single-document form). Points
    /// must be ordered by strictly ascending IL offsets. Hidden points
    /// ([`SequencePoint::is_hidden`]) encode as the two-zero-record sentinel.
    /// Non-hidden points must have a nonzero source extent, since two zero
    /// line/column deltas are reserved for that sentinel.
    ///
    /// Calling again for the same method replaces its points. Calling with an
    /// empty slice still reserves the `MethodDebugInformation` row so that
    /// rids stay aligned with the module's `MethodDef` table.
    pub fn set_method_sequence_points(
        &mut self,
        method: Token,
        doc: DocumentHandle,
        points: &[SequencePoint],
    ) -> Result<()> {
        let rid = method_rid(method)?;
        if doc.0 == 0 || doc.0 as usize > self.document_rows.len() {
            return Err(Error::argument(format!(
                "document handle {} outside Document table ({} rows)",
                doc.0,
                self.document_rows.len()
            )));
        }
        validate_offsets(points)?;
        let entry = self.method_debug.entry(rid).or_default();
        entry.document_rid = doc.0;
        entry.points = Some(points.to_vec());
        entry.point_documents = None;
        Ok(())
    }

    /// Replaces a method's points together with each point's source document.
    /// Input is sorted by IL offset before encoding; duplicate or negative
    /// offsets and unknown document handles return an error. Document-switch
    /// records preserve methods spanning multiple files.
    pub fn set_method_sequence_points_with_documents(
        &mut self,
        method: Token,
        points: &[(DocumentHandle, SequencePoint)],
    ) -> Result<()> {
        let rid = method_rid(method)?;
        for &(document, _) in points {
            if document.0 == 0 || document.0 as usize > self.document_rows.len() {
                return Err(Error::argument(
                    "sequence point document handle is outside Document table",
                ));
            }
        }
        let mut ordered = points.to_vec();
        ordered.sort_unstable_by_key(|&(_, point)| point.offset);
        let (documents, points): (Vec<_>, Vec<_>) =
            ordered.into_iter().map(|(document, point)| (document.0, point)).unzip();
        validate_offsets(&points)?;
        let entry = self.method_debug.entry(rid).or_default();
        entry.document_rid = documents.first().copied().unwrap_or(0);
        entry.points = Some(points);
        entry.point_documents = Some(documents);
        Ok(())
    }

    /// Records the stand-alone local signature rid emitted as the leading
    /// compressed token of the method's sequence-point blob (Roslyn writes
    /// the `StandAloneSig` rid here; readers skip the value).
    pub fn set_local_var_sig(&mut self, method: Token, stand_alone_sig_rid: u32) {
        let Ok(rid) = method_rid(method) else {
            return;
        };
        self.method_debug.entry(rid).or_default().local_sig_rid = stand_alone_sig_rid;
    }

    /// Reserves a method's debug-information row even when it has no points.
    /// Earlier missing rows are also emitted empty, preserving MethodDef RIDs.
    pub fn register_method(&mut self, method: Token) -> Result<()> {
        self.method_debug.entry(method_rid(method)?).or_default();
        Ok(())
    }

    /// Sets all row counts from the associated PE's type-system metadata.
    /// Omitted tables have zero rows; debug tables and counts exceeding the
    /// metadata token limit are rejected. Repeated table entries use the last
    /// count. Finalization rejects references outside these associated tables.
    ///
    /// Without this information, standalone builders infer minimum counts
    /// from registered methods, local signatures, scopes and debug parents.
    pub fn set_type_system_row_counts(&mut self, counts: &[(TableIndex, u32)]) -> Result<()> {
        let mut rows = [0; TYPE_SYSTEM_TABLE_COUNT];
        for &(table, count) in counts {
            if table as usize >= TYPE_SYSTEM_TABLE_COUNT || count > 0x00ff_ffff {
                return Err(Error::argument("invalid portable pdb type-system row count"));
            }
            rows[table as usize] = count;
        }
        self.type_system_counts = Some(rows);
        Ok(())
    }

    /// Adds an `ImportScope` row, returning its 1-based rid for use in
    /// [`Self::add_local_scope`]. `imports` is the raw imports blob
    /// (compressed count followed by alias/GUID packages); `parent` is a rid
    /// returned by this method, or 0 for no parent.
    pub fn add_import_scope(&mut self, parent: u32, imports: &[u8]) -> u32 {
        let row =
            ImportScopeRow { parent_rid: parent, imports_blob: self.metadata.insert_blob(imports) };
        self.import_scope_rows.push(row);
        self.import_scope_rows.len() as u32
    }

    /// Adds one `LocalScope` row covering the IL half-open range
    /// `[start_offset, start_offset + length)` of `method`.
    ///
    /// Variables are `(slot index, name, attributes)` triples; attributes are
    /// truncated to the 16-bit `VariableAttributes` column. Constants are
    /// `(name, raw constant-signature blob)` pairs (element-type byte plus
    /// value). Each call appends its variable and constant rows directly
    /// before the scope row so the table's list-range columns stay contiguous.
    /// Finalization sorts scopes by method and range, reorders their owned
    /// locals/constants, and remaps debug parents using these source handles.
    ///
    /// `kind` is accepted for parity with the Cecil scope model; the
    /// Cecil-compatible six-column `LocalScope` layout carries no Kind
    /// column, so readers always observe `0`.
    // Eight parameters mirror Cecil's Scope aggregate (method, import scope,
    // variables, constants, kind, range) and have no natural grouping object.
    #[allow(clippy::too_many_arguments)]
    pub fn add_local_scope(
        &mut self,
        method: Token,
        import_scope: u32,
        variables: &[(u16, String, u32)],
        constants: &[(&str, &[u8])],
        kind: u32,
        start_offset: i32,
        length: i32,
    ) -> ScopeHandle {
        let _ = kind;
        let Ok(method_rid) = method_rid(method) else {
            return ScopeHandle(0);
        };
        let variable_list_start = self.variable_rows.len() as u32 + 1;
        for &(index, ref name, attributes) in variables {
            let row = LocalVariableRow {
                attributes: attributes as u16,
                index,
                name_string: self.metadata.insert_string(name),
            };
            self.variable_rows.push(row);
        }
        let constant_list_start = self.constant_rows.len() as u32 + 1;
        for &(name, signature) in constants {
            let row = LocalConstantRow {
                name_string: self.metadata.insert_string(name),
                signature_blob: self.metadata.insert_blob(signature),
            };
            self.constant_rows.push(row);
        }
        let row = LocalScopeRow {
            method_rid,
            import_scope_rid: import_scope,
            variable_list_start,
            constant_list_start,
            start_offset,
            length,
        };
        self.scope_rows.push(row);
        ScopeHandle(self.scope_rows.len() as u32)
    }

    /// Sets the entry-point method token recorded in the `#Pdb` heap
    /// (`Token::NIL` for libraries).
    pub fn set_entry_point(&mut self, tok: Token) {
        self.entry_point = tok;
    }

    /// Overrides the 20-byte PDB id (16-byte GUID + 4-byte stamp) stored at
    /// the head of the `#Pdb` heap. Mono.Cecil fills this with the first 20
    /// bytes of the SHA-256 of the finished file; callers that replicate that
    /// scheme can supply the digest here. Defaults to twenty zero bytes.
    pub fn set_pdb_id(&mut self, id: [u8; 20]) {
        self.pdb_id = id;
    }

    /// Retains the associated module's GUID in `#GUID`. Portable PDBs have no
    /// physical `Module` row; their identity is set by [`Self::set_pdb_id`].
    pub fn set_module_guid(&mut self, guid: [u8; 16]) {
        self.metadata.insert_guid(&guid);
    }

    /// Adds one `CustomDebugInformation` row (Source Link, embedded source,
    /// async/state-machine hints, ...): `parent` names the owning entity by
    /// metadata token (Module/MethodDef/TypeDef/Field/Property/Event/Param/
    /// LocalScope all participate in the `HasCustomDebugInformation` coded
    /// group), `kind` is the well-known kind GUID, and `value` is the raw
    /// payload blob — the bytes round-trip verbatim (Cecil's `Binary`
    /// semantics), so callers encode higher-level kinds themselves.
    pub fn add_custom_debug_information(
        &mut self,
        parent: Token,
        kind: [u8; 16],
        value: &[u8],
    ) -> Result<()> {
        let cell = cecil_metadata::encode_coded(
            &coded::HAS_CUSTOM_DEBUG_INFORMATION,
            parent
                .try_table()
                .ok_or_else(|| Error::argument("invalid custom debug information parent token"))?,
            parent.rid(),
        )?;
        self.cdi_rows.push(CustomDebugInformationRow {
            parent_cell: cell as u32,
            kind_guid: self.metadata.insert_guid(&kind),
            value_blob: self.metadata.insert_blob(value),
        });
        Ok(())
    }

    fn sort_scopes(&mut self) -> Result<()> {
        let mut order: Vec<_> = (0..self.scope_rows.len()).collect();
        order.sort_by_key(|&i| {
            let row = self.scope_rows[i];
            (row.method_rid, row.start_offset, std::cmp::Reverse(row.length))
        });
        if order.iter().enumerate().all(|(i, &old)| i == old) {
            return Ok(());
        }
        let scopes = std::mem::take(&mut self.scope_rows);
        let mut variables: Vec<_> =
            std::mem::take(&mut self.variable_rows).into_iter().map(Some).collect();
        let constants = std::mem::take(&mut self.constant_rows);
        let mut scope_rids = vec![0; scopes.len()];
        let mut variable_rids = vec![0; variables.len()];
        let mut constant_rids = vec![0; constants.len()];
        self.scope_rows.reserve(scopes.len());
        self.variable_rows.reserve(variables.len());
        self.constant_rows.reserve(constants.len());
        for old in order {
            let mut row = scopes[old];
            let variable_start = row.variable_list_start as usize - 1;
            let variable_end = scopes
                .get(old + 1)
                .map_or(variables.len(), |next| next.variable_list_start as usize - 1);
            let constant_start = row.constant_list_start as usize - 1;
            let constant_end = scopes
                .get(old + 1)
                .map_or(constants.len(), |next| next.constant_list_start as usize - 1);
            row.variable_list_start = self.variable_rows.len() as u32 + 1;
            row.constant_list_start = self.constant_rows.len() as u32 + 1;
            for i in variable_start..variable_end {
                variable_rids[i] = self.variable_rows.len() as u32 + 1;
                self.variable_rows
                    .push(variables[i].take().expect("scope local lists are disjoint"));
            }
            for i in constant_start..constant_end {
                constant_rids[i] = self.constant_rows.len() as u32 + 1;
                self.constant_rows.push(constants[i]);
            }
            scope_rids[old] = self.scope_rows.len() as u32 + 1;
            self.scope_rows.push(row);
        }
        for row in &mut self.cdi_rows {
            let Some((table, rid)) = cecil_metadata::decode_coded(
                &coded::HAS_CUSTOM_DEBUG_INFORMATION,
                row.parent_cell as u64,
            ) else {
                continue;
            };
            let rows = match table {
                TableIndex::LocalScope => &scope_rids,
                TableIndex::LocalVariable => &variable_rids,
                TableIndex::LocalConstant => &constant_rids,
                _ => continue,
            };
            let rid = rows
                .get(rid as usize - 1)
                .copied()
                .ok_or_else(|| Error::argument("portable pdb debug parent is outside its table"))?;
            row.parent_cell =
                cecil_metadata::encode_coded(&coded::HAS_CUSTOM_DEBUG_INFORMATION, table, rid)?
                    as u32;
        }
        Ok(())
    }

    /// Serializes the complete standalone portable PDB image: a BSJB root
    /// with debug tables in `#~` and associated type-system counts in `#Pdb`.
    pub fn finalize(mut self) -> Result<Vec<u8>> {
        self.sort_scopes()?;
        self.cdi_rows.sort_by_key(|row| row.parent_cell);
        let mut required = [0; TYPE_SYSTEM_TABLE_COUNT];
        let mut reference = |table: TableIndex, rid: u32| {
            if (table as usize) < TYPE_SYSTEM_TABLE_COUNT {
                required[table as usize] = required[table as usize].max(rid);
            }
        };
        for (&rid, entry) in &self.method_debug {
            reference(TableIndex::MethodDef, rid);
            reference(TableIndex::StandAloneSig, entry.local_sig_rid);
        }
        for scope in &self.scope_rows {
            reference(TableIndex::MethodDef, scope.method_rid);
        }
        for row in &self.cdi_rows {
            if let Some((table, rid)) = cecil_metadata::decode_coded(
                &coded::HAS_CUSTOM_DEBUG_INFORMATION,
                row.parent_cell as u64,
            ) {
                reference(table, rid);
            }
        }
        if !self.entry_point.is_nil() {
            reference(TableIndex::MethodDef, method_rid(self.entry_point)?);
        }
        let counts = self.type_system_counts.unwrap_or(required);
        for (&needed, &count) in required.iter().zip(&counts) {
            if needed > count || count > 0x00ff_ffff {
                return Err(Error::argument(
                    "portable pdb reference exceeds associated table rows",
                ));
            }
        }

        // MethodDebugInformation rows, rid-aligned with MethodDef.
        let max_rid = counts[TableIndex::MethodDef as usize];
        for rid in 1..=max_rid {
            match self.method_debug.get(&rid) {
                Some(entry) => {
                    let blob_idx = match &entry.points {
                        Some(points) if !points.is_empty() => {
                            let blob = encode_sequence_points_with_documents(
                                entry.local_sig_rid,
                                points,
                                entry.point_documents.as_deref(),
                            )?;
                            self.metadata.insert_blob(&blob) as u64
                        }
                        _ => 0,
                    };
                    self.metadata.add_row(
                        TableIndex::MethodDebugInformation,
                        &[entry.document_rid as u64, blob_idx],
                    )?;
                }
                None => {
                    self.metadata.add_row(TableIndex::MethodDebugInformation, &[0, 0])?;
                }
            }
        }

        for row in &self.document_rows {
            self.metadata.add_row(
                TableIndex::Document,
                &[
                    row.name_blob as u64,
                    row.hash_algorithm_guid as u64,
                    row.hash_blob as u64,
                    row.language_guid as u64,
                ],
            )?;
        }
        for row in &self.import_scope_rows {
            self.metadata.add_row(
                TableIndex::ImportScope,
                &[row.parent_rid as u64, row.imports_blob as u64],
            )?;
        }
        for row in &self.variable_rows {
            self.metadata.add_row(
                TableIndex::LocalVariable,
                &[row.attributes as u64, row.index as u64, row.name_string as u64],
            )?;
        }
        for row in &self.constant_rows {
            self.metadata.add_row(
                TableIndex::LocalConstant,
                &[row.name_string as u64, row.signature_blob as u64],
            )?;
        }
        for row in &self.scope_rows {
            if row.start_offset < 0
                || row.length < 0
                || row.start_offset.checked_add(row.length).is_none()
                || row.import_scope_rid as usize > self.import_scope_rows.len()
            {
                return Err(Error::argument("invalid portable pdb local scope range or import"));
            }
            self.metadata.add_row(
                TableIndex::LocalScope,
                &[
                    row.method_rid as u64,
                    row.import_scope_rid as u64,
                    row.variable_list_start as u64,
                    row.constant_list_start as u64,
                    row.start_offset as u32 as u64,
                    row.length as u32 as u64,
                ],
            )?;
        }

        for row in &self.cdi_rows {
            self.metadata.add_row(
                TableIndex::CustomDebugInformation,
                &[row.parent_cell as u64, row.kind_guid as u64, row.value_blob as u64],
            )?;
        }

        // Debug tables are physical rows here. #Pdb references only the
        // associated PE's type-system tables, in ascending table order.
        let counts: Vec<_> = counts
            .into_iter()
            .enumerate()
            .filter_map(|(table, count)| (count > 0).then_some((table as u8, count)))
            .collect();
        let (pdb_id, entry_point) = (self.pdb_id, self.entry_point);
        self.metadata.set_pdb_heap(pdb_id, entry_point, &counts);
        Ok(self.metadata.finalize())
    }
}

/// Extracts the 1-based `MethodDef` rid from a method token.
fn method_rid(method: Token) -> Result<u32> {
    if method.is_nil() || method.table_byte() != TableIndex::MethodDef as u8 || method.rid() == 0 {
        return Err(Error::argument(format!("{method} is not a MethodDef token")));
    }
    Ok(method.rid())
}

/// Validates that offsets are usable as compressed deltas: non-negative and
/// non-decreasing.
fn validate_offsets(points: &[SequencePoint]) -> Result<()> {
    let mut previous: Option<i32> = None;
    for point in points {
        if point.offset < 0 {
            return Err(Error::argument(format!(
                "negative IL offset {} in sequence points",
                point.offset
            )));
        }
        if let Some(prev) = previous {
            if point.offset <= prev {
                return Err(Error::argument(
                    "sequence points must have strictly increasing IL offsets",
                ));
            }
        }
        previous = Some(point.offset);
    }
    Ok(())
}

/// Picks the dominant path separator of a document name, mirroring
/// `AssemblyWriter.TryGetDocumentNameSeparator` (ties favor `/`; names
/// without either separator yield `None`).
fn document_name_separator(name: &str) -> Option<char> {
    let unix = name.matches('/').count();
    let win = name.matches('\\').count();
    if unix == 0 && win == 0 {
        return None;
    }
    if unix >= win {
        Some('/')
    } else {
        Some('\\')
    }
}

/// Encodes the `MethodDebugInformation` sequence-point blob
/// (`AssemblyWriter.SignatureWriter.WriteSequencePoints`, ECMA-335 §V.C):
///
/// - leading compressed stand-alone signature rid (skipped by readers),
/// - per point: compressed IL-offset delta (absolute for the first record),
///   then either the hidden sentinel (two compressed zeroes) or the line /
///   column deltas with the running start-position baseline (absolute
///   compressed values for the first non-hidden point, signed deltas after).
#[cfg(test)]
fn encode_sequence_points(local_sig_rid: u32, points: &[SequencePoint]) -> Result<Vec<u8>> {
    encode_sequence_points_with_documents(local_sig_rid, points, None)
}

fn encode_sequence_points_with_documents(
    local_sig_rid: u32,
    points: &[SequencePoint],
    documents: Option<&[u32]>,
) -> Result<Vec<u8>> {
    validate_offsets(points)?;
    if let Some(documents) = documents {
        if documents.len() != points.len() {
            return Err(Error::argument("sequence point documents must match the point count"));
        }
    }
    fit_u32(local_sig_rid)?;
    let mut w = ByteWriter::new();
    w.compressed_u32(local_sig_rid);

    let mut base_line: Option<i64> = None;
    let mut base_column: Option<i64> = None;
    let mut previous_offset = 0i32;
    let mut previous_document = documents.and_then(|documents| documents.first().copied());

    for (i, point) in points.iter().enumerate() {
        if let Some(documents) = documents {
            let document = documents[i];
            if i > 0 && previous_document != Some(document) {
                w.compressed_u32(0); // document-switch marker
                w.compressed_u32(fit_u32(document)?);
            }
            previous_document = Some(document);
        }
        if i > 0 {
            w.compressed_u32(fit_u32((point.offset - previous_offset) as u32)?);
        } else {
            w.compressed_u32(fit_u32(point.offset as u32)?);
        }
        previous_offset = point.offset;

        if point.is_hidden() {
            // Two compressed zeroes: read back as delta_lines == 0 &&
            // delta_columns == 0, the hidden sentinel (0xfeefee).
            w.compressed_u32(0);
            w.compressed_u32(0);
            continue;
        }

        let delta_lines = point.end_line as i64 - point.start_line as i64;
        if delta_lines < 0 {
            return Err(Error::argument(format!(
                "sequence point at offset {} ends before it starts",
                point.offset
            )));
        }
        let delta_columns = point.end_column as i64 - point.start_column as i64;
        if delta_lines == 0 && delta_columns < 0 {
            // Same-line records carry an unsigned column delta; a negative
            // one cannot be encoded (the reader would misread it as the
            // hidden sentinel path or a bogus huge value).
            return Err(Error::argument(format!(
                "sequence point at offset {} ends before it starts on the same line",
                point.offset
            )));
        }
        if delta_lines == 0 && delta_columns == 0 {
            return Err(Error::argument(format!(
                "non-hidden sequence point at offset {} has zero source extent",
                point.offset
            )));
        }
        let delta_columns = fit_i32(delta_columns)?;

        w.compressed_u32(fit_u32(delta_lines as u32)?);
        if delta_lines == 0 {
            w.compressed_u32(fit_u32(delta_columns as u32)?);
        } else {
            w.compressed_i32(delta_columns);
        }

        let (line, column) = match (base_line, base_column) {
            (None, None) => {
                w.compressed_u32(fit_u32(point.start_line)?);
                w.compressed_u32(fit_u32(point.start_column)?);
                (point.start_line as i64, point.start_column as i64)
            }
            (Some(bl), Some(bc)) => {
                w.compressed_i32(fit_i32(point.start_line as i64 - bl)?);
                w.compressed_i32(fit_i32(point.start_column as i64 - bc)?);
                (point.start_line as i64, point.start_column as i64)
            }
            _ => unreachable!("baseline halves are always set together"),
        };
        base_line = Some(line);
        base_column = Some(column);
    }

    Ok(w.into_vec())
}

/// Checks a delta fits the compressed signed integer domain.
fn fit_i32(value: i64) -> Result<i32> {
    if !(-(1i64 << 28)..(1i64 << 28)).contains(&value) {
        return Err(Error::argument(format!(
            "sequence point delta {value} exceeds compressed signed range"
        )));
    }
    Ok(value as i32)
}

fn fit_u32(value: u32) -> Result<u32> {
    if value > 0x1fff_ffff {
        return Err(Error::argument(format!(
            "sequence point value {value} exceeds compressed unsigned range"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portable_reader::{PortablePdbReader, HIDDEN_LINE};

    #[test]
    fn invalid_tokens_and_sequence_values_return_errors() {
        let mut builder = PortablePdbBuilder::new();
        assert!(builder.add_custom_debug_information(Token(0xff00_0001), [0; 16], &[]).is_err());
        let point =
            SequencePoint { offset: 0, start_line: 1, start_column: 1, end_line: 1, end_column: 2 };
        assert!(encode_sequence_points(0, &[point, point]).is_err());
        assert!(encode_sequence_points(0, &[SequencePoint { offset: i32::MAX, ..point }]).is_err());
        assert!(encode_sequence_points(
            0,
            &[SequencePoint { start_line: u32::MAX, end_line: u32::MAX, ..point }]
        )
        .is_err());
        assert!(fit_i32(1 << 28).is_err());
        assert!(fit_i32(-(1 << 28) - 1).is_err());
    }

    const SHA256_GUID: [u8; 16] = [
        0x88, 0x29, 0x85, 0xA2, 0x1F, 0x72, 0xCE, 0x46, 0xA9, 0x6B, 0x35, 0xFD, 0x0B, 0x25, 0xFA,
        0xF9,
    ];
    const CSHARP_GUID: [u8; 16] = [
        0x03, 0x63, 0x59, 0xFF, 0xB5, 0x86, 0xC2, 0x4F, 0xAB, 0xF4, 0xD7, 0xE8, 0xFE, 0x35, 0xE5,
        0x1C,
    ];

    #[test]
    fn sequence_point_blob_matches_spec_encoding() {
        // Single non-hidden point: offset 0, lines 100..101, columns 1..11.
        let points = [SequencePoint {
            offset: 0,
            start_line: 100,
            start_column: 1,
            end_line: 101,
            end_column: 11,
        }];
        let blob = encode_sequence_points(0, &points).unwrap();
        // 00       local sig rid 0
        // 00       absolute IL offset 0
        // 01       delta lines 1
        // 14       compressed_i32(10) delta columns
        // 64       compressed_u32(100) absolute start line
        // 01       compressed_u32(1) absolute start column
        assert_eq!(blob, vec![0x00, 0x00, 0x01, 0x14, 0x64, 0x01]);
        let points = [
            SequencePoint {
                offset: 0,
                start_line: HIDDEN_LINE,
                start_column: 0,
                end_line: HIDDEN_LINE,
                end_column: 0,
            },
            SequencePoint { offset: 5, start_line: 7, start_column: 2, end_line: 7, end_column: 9 },
        ];
        let blob = encode_sequence_points(3, &points).unwrap();
        // Leading sig rid 3, absolute offset 0, hidden sentinel 00 00,
        // delta il 5, same-line deltas (0 then compressed 7), then absolute
        // start position (hidden points leave the baseline untouched).
        assert_eq!(
            blob,
            vec![
                0x03, // local sig rid
                0x00, // offset 0
                0x00, 0x00, // hidden sentinel
                0x05, // delta il 5
                0x00, // delta lines 0
                0x07, // delta columns 7
                0x07, // start line 7
                0x02, // start column 2
            ]
        );
    }

    #[test]
    fn unsorted_or_negative_points_are_rejected() {
        let ok =
            SequencePoint { offset: 4, start_line: 1, start_column: 1, end_line: 1, end_column: 5 };

        // Offset ordering and sign are validated on the public API.
        let mut b = PortablePdbBuilder::new();
        let doc = b.add_document("a.cs", [0; 16], &[], [0; 16]);
        let method = Token::new(TableIndex::MethodDef, 1);

        let backwards = SequencePoint { offset: 2, ..ok };
        let err = b.set_method_sequence_points(method, doc, &[ok, backwards]).unwrap_err();
        assert!(matches!(err, Error::Argument(_)));

        let negative = SequencePoint { offset: -1, ..ok };
        let err = b.set_method_sequence_points(method, doc, &[negative]).unwrap_err();
        assert!(matches!(err, Error::Argument(_)));

        // Span inversions are caught at encode time (finalize).
        let inverted_lines =
            SequencePoint { offset: 0, start_line: 9, start_column: 0, end_line: 3, end_column: 0 };
        assert!(encode_sequence_points(0, &[inverted_lines]).is_err());

        let inverted_columns =
            SequencePoint { offset: 0, start_line: 4, start_column: 9, end_line: 4, end_column: 3 };
        assert!(encode_sequence_points(0, &[inverted_columns]).is_err());
    }

    #[test]
    fn zero_extent_source_points_cannot_emit_the_hidden_sentinel() {
        let method = Token::new(TableIndex::MethodDef, 1);
        for column in [0, 4] {
            let mut builder = PortablePdbBuilder::new();
            let document = builder.add_document("a.cs", [0; 16], &[], [0; 16]);
            let point = SequencePoint {
                offset: 0,
                start_line: 340,
                start_column: column,
                end_line: 340,
                end_column: column,
            };
            builder.set_method_sequence_points(method, document, &[point]).unwrap();
            assert!(matches!(builder.finalize(), Err(Error::Argument(_))));
        }

        let mut builder = PortablePdbBuilder::new();
        let document = builder.add_document("a.cs", [0; 16], &[], [0; 16]);
        let points = [
            SequencePoint {
                offset: 0,
                start_line: HIDDEN_LINE,
                start_column: 0,
                end_line: HIDDEN_LINE,
                end_column: 0,
            },
            SequencePoint {
                offset: 1,
                start_line: 340,
                start_column: 0,
                end_line: 340,
                end_column: 1,
            },
        ];
        builder.set_method_sequence_points(method, document, &points).unwrap();
        let bytes = builder.finalize().unwrap();
        let reader = PortablePdbReader::parse(&bytes).unwrap();
        assert_eq!(reader.sequence_points(1).unwrap().unwrap().1, points);
    }

    #[test]
    fn multiple_documents_survive_ordering_switches_and_replacement() {
        let mut builder = PortablePdbBuilder::new();
        let first = builder.add_document("a.cs", [0; 16], &[], [0; 16]);
        let second = builder.add_document("b.cs", [0; 16], &[], [0; 16]);
        let method = Token::new(TableIndex::MethodDef, 1);
        let point =
            SequencePoint { offset: 0, start_line: 1, start_column: 1, end_line: 1, end_column: 2 };
        let points = [
            (first, SequencePoint { offset: 12, ..point }),
            (second, SequencePoint { offset: 4, start_line: 10, end_line: 10, ..point }),
            (
                first,
                SequencePoint {
                    offset: 8,
                    start_line: HIDDEN_LINE,
                    end_line: HIDDEN_LINE,
                    ..point
                },
            ),
            (first, point),
        ];
        builder.set_method_sequence_points_with_documents(method, &points).unwrap();
        builder.set_local_var_sig(method, 3);
        let bytes = builder.finalize().unwrap();
        let reader = PortablePdbReader::parse(&bytes).unwrap();
        let (initial, decoded, documents) =
            reader.sequence_points_with_documents(1).unwrap().unwrap();
        assert_eq!(initial, first.0);
        assert_eq!(decoded.iter().map(|point| point.offset).collect::<Vec<_>>(), [0, 4, 8, 12]);
        assert_eq!(documents, [first.0, second.0, first.0, first.0]);
        assert!(decoded[2].is_hidden());
        assert_eq!(decoded[1].start_line, 10);
        assert_eq!(decoded[3].start_line, 1);

        let mut builder = PortablePdbBuilder::new();
        let first = builder.add_document("a.cs", [0; 16], &[], [0; 16]);
        let second = builder.add_document("b.cs", [0; 16], &[], [0; 16]);
        assert!(builder
            .set_method_sequence_points_with_documents(method, &[(first, point); 2])
            .is_err());
        assert!(builder
            .set_method_sequence_points_with_documents(method, &[(DocumentHandle(9), point)])
            .is_err());
        builder.set_method_sequence_points_with_documents(method, &[(first, point)]).unwrap();
        builder.set_method_sequence_points(method, second, &[point]).unwrap();
        let bytes = builder.finalize().unwrap();
        assert_eq!(
            PortablePdbReader::parse(&bytes)
                .unwrap()
                .sequence_points_with_documents(1)
                .unwrap()
                .unwrap()
                .2,
            [second.0]
        );
    }

    #[test]
    fn document_name_separator_selection() {
        assert_eq!(document_name_separator("src/prog.cs"), Some('/'));
        assert_eq!(document_name_separator(r"C:\src\prog.cs"), Some('\\'));
        assert_eq!(document_name_separator("mixed/path\\file"), Some('/'));
        // Ties favor '/', matching Cecil's TryGetDocumentNameSeparator.
        assert_eq!(document_name_separator(r"win\path/file"), Some('/'));
        assert_eq!(document_name_separator("plain.cs"), None);
        assert_eq!(document_name_separator(""), None);
    }

    /// Builds a fully populated portable PDB exercising every table the
    /// writer emits, then round-trips it through the reader.
    #[test]
    fn finalize_output_roundtrips_through_reader() {
        let mut b = PortablePdbBuilder::with_version("v4.0.30319");

        // Documents: slash-separated path with an empty segment, a Windows
        // path, and a bare name (no separator).
        let doc_cs = b.add_document("/src/lib//prog.cs", SHA256_GUID, &[0x11u8; 32], CSHARP_GUID);
        let doc_gen =
            b.add_document(r"C:\gen\obj\prog.Designer.cs", SHA256_GUID, &[0x22u8; 32], CSHARP_GUID);
        let doc_plain = b.add_document("<unknown>", SHA256_GUID, &[], CSHARP_GUID);
        // Deduplication folds identical names onto the first row.
        assert_eq!(b.add_document("/src/lib//prog.cs", [0; 16], &[], [0; 16]), doc_cs);
        assert_ne!(doc_cs, doc_gen);
        assert_ne!(doc_gen, doc_plain);

        // Sequence points for method 0x06000001: hidden sentinel,
        // multi-line span, then a same-line record with a signed baseline
        // jump.
        let points = [
            SequencePoint {
                offset: 0,
                start_line: HIDDEN_LINE,
                start_column: 0,
                end_line: HIDDEN_LINE,
                end_column: 0,
            },
            SequencePoint {
                offset: 4,
                start_line: 100,
                start_column: 1,
                end_line: 102,
                end_column: 3,
            },
            SequencePoint {
                offset: 12,
                start_line: 103,
                start_column: 40,
                end_line: 103,
                end_column: 47,
            },
        ];
        b.set_method_sequence_points(Token::new(TableIndex::MethodDef, 1), doc_cs, &points)
            .unwrap();

        // Second method registered without points keeps the MDI rid aligned
        // with MethodDef rid 2.
        b.set_method_sequence_points(Token::new(TableIndex::MethodDef, 2), doc_gen, &[]).unwrap();

        // Third method with points on the plain-named document.
        let points3 = [SequencePoint {
            offset: 0,
            start_line: 42,
            start_column: 8,
            end_line: 42,
            end_column: 15,
        }];
        b.set_method_sequence_points(Token::new(TableIndex::MethodDef, 3), doc_plain, &points3)
            .unwrap();
        b.set_local_var_sig(Token::new(TableIndex::MethodDef, 3), 7);

        // Import scopes + scopes with variables and constants.
        let root_scope = b.add_import_scope(0, &[0x01, 0x02, 0x03]);
        let nested_scope = b.add_import_scope(root_scope, &[]);
        assert_eq!(root_scope, 1);
        assert_eq!(nested_scope, 2);

        let _s1 = b.add_local_scope(
            Token::new(TableIndex::MethodDef, 1),
            root_scope,
            &[(0u16, "name".to_owned(), 0), (1u16, "count".to_owned(), 1)],
            &[("PI", &[0x0C, 0x18, 0x2D, 0x44, 0x54, 0xFB, 0x21, 0x09, 0x40])],
            0,
            4,
            20,
        );
        let _s2 = b.add_local_scope(
            Token::new(TableIndex::MethodDef, 1),
            nested_scope,
            &[(2u16, "tmp".to_owned(), 0)],
            &[],
            0,
            24,
            8,
        );

        b.set_entry_point(Token::new(TableIndex::MethodDef, 1));
        let id = [
            0xA0u8, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
            0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3,
        ];
        b.set_pdb_id(id);
        b.set_module_guid([0x77u8; 16]);

        let bytes = b.finalize().unwrap();

        let reader = PortablePdbReader::parse(&bytes).expect("own output parses");
        assert_eq!(reader.entry_point(), Token::new(TableIndex::MethodDef, 1));
        assert_eq!(reader.pdb_id(), id);

        // Documents survive verbatim.
        let docs = reader.documents().unwrap();
        assert_eq!(docs.len(), 3);
        assert_eq!(docs[0].name, "/src/lib//prog.cs");
        assert_eq!(docs[0].hash_algorithm, SHA256_GUID);
        assert_eq!(docs[0].hash, vec![0x11u8; 32]);
        assert_eq!(docs[0].language, CSHARP_GUID);
        assert_eq!(docs[1].name, r"C:\gen\obj\prog.Designer.cs");
        assert_eq!(docs[2].name, "<unknown>");
        assert_eq!(docs[2].hash, Vec::<u8>::new());

        // Sequence points come back identically.
        let (doc_rid, decoded) = reader.sequence_points(1).unwrap().expect("points present");
        assert_eq!(doc_rid, doc_cs.0);
        assert_eq!(decoded, points.to_vec());
        assert!(decoded[0].is_hidden());

        // Empty registration yields an aligned but empty MDI row.
        assert!(reader.sequence_points(2).unwrap().is_none());
        let (rid3, decoded3) = reader.sequence_points(3).unwrap().expect("points present");
        assert_eq!(rid3, doc_plain.0);
        assert_eq!(decoded3, points3.to_vec());

        // Scopes, variables, constants.
        let scopes = reader.local_scopes(1).unwrap();
        assert_eq!(scopes.len(), 2);
        assert_eq!(scopes[0].method, Token::new(TableIndex::MethodDef, 1));
        assert_eq!(scopes[0].import_scope, root_scope);
        assert_eq!(scopes[0].try_start, 4);
        assert_eq!(scopes[0].try_length, 20);
        assert_eq!(scopes[0].variables, vec![1, 2]);
        assert_eq!(scopes[0].constants, vec![1]);
        assert_eq!(scopes[1].import_scope, nested_scope);
        assert_eq!(scopes[1].variables, vec![3]);
        assert_eq!(scopes[1].constants, Vec::<u32>::new());

        let vars = reader.local_variables(&scopes[0]).unwrap();
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].index, 0);
        assert_eq!(vars[0].name, "name");
        assert_eq!(vars[0].attributes, 0);
        assert_eq!(vars[1].index, 1);
        assert_eq!(vars[1].name, "count");
        assert_eq!(vars[1].attributes, 1);

        let consts = reader.local_constants(&scopes[0]).unwrap();
        assert_eq!(consts.len(), 1);
        assert_eq!(consts[0].name, "PI");
        assert_eq!(consts[0].signature, vec![0x0C, 0x18, 0x2D, 0x44, 0x54, 0xFB, 0x21, 0x09, 0x40]);

        // Only debug tables are physical; type-system counts are external.
        let md = reader.metadata();
        assert!(!md.tables().is_present(TableIndex::Module));
        assert_eq!(md.heaps().pdb.as_ref().unwrap().row_count(TableIndex::MethodDef), 3);
        assert!(md.heaps().pdb.is_some());
        assert_eq!(md.version_string(), "v4.0.30319");
    }

    #[test]
    fn invalid_inputs_are_errors() {
        let mut b = PortablePdbBuilder::new();
        let doc = b.add_document("a.cs", [0; 16], &[], [0; 16]);

        // Unknown document handle.
        let err = b
            .set_method_sequence_points(
                Token::new(TableIndex::MethodDef, 1),
                DocumentHandle(99),
                &[],
            )
            .unwrap_err();
        assert!(matches!(err, Error::Argument(_)));

        // Non-method tokens.
        let err =
            b.set_method_sequence_points(Token::new(TableIndex::Field, 1), doc, &[]).unwrap_err();
        assert!(matches!(err, Error::Argument(_)));
        assert_eq!(b.set_local_var_sig(Token::new(TableIndex::Field, 1), 1), ());

        // Unsorted points.
        let pts = [
            SequencePoint { offset: 8, start_line: 1, start_column: 1, end_line: 1, end_column: 2 },
            SequencePoint { offset: 4, start_line: 1, start_column: 3, end_line: 1, end_column: 4 },
        ];
        let err = b
            .set_method_sequence_points(Token::new(TableIndex::MethodDef, 1), doc, &pts)
            .unwrap_err();
        assert!(matches!(err, Error::Argument(_)));

        // Bad method token is ignored (no-op) by add_local_scope.
        assert_eq!(
            b.add_local_scope(Token::new(TableIndex::Field, 1), 0, &[], &[], 0, 0, 0),
            ScopeHandle(0)
        );
    }

    #[test]
    fn minimal_builder_emits_valid_empty_pdb() {
        let bytes = PortablePdbBuilder::new().finalize().unwrap();
        let reader = PortablePdbReader::parse(&bytes).expect("empty pdb parses");
        assert_eq!(reader.entry_point(), Token::NIL);
        assert_eq!(reader.pdb_id(), [0; 20]);
        assert!(reader.documents().unwrap().is_empty());
        assert_eq!(reader.metadata().tables().valid_mask(), 0);
    }

    #[test]
    fn associated_counts_include_trailing_methods_without_points() {
        let mut builder = PortablePdbBuilder::new();
        builder
            .set_type_system_row_counts(&[
                (TableIndex::Module, 1),
                (TableIndex::TypeDef, 2),
                (TableIndex::MethodDef, 4),
            ])
            .unwrap();
        let document = builder.add_document("a.cs", [0; 16], &[], [0; 16]);
        builder
            .set_method_sequence_points(
                Token::new(TableIndex::MethodDef, 1),
                document,
                &[SequencePoint {
                    offset: 0,
                    start_line: 1,
                    end_line: 1,
                    start_column: 1,
                    end_column: 2,
                }],
            )
            .unwrap();
        let bytes = builder.finalize().unwrap();
        let reader = PortablePdbReader::parse(&bytes).unwrap();
        let metadata = reader.metadata();
        assert_eq!(metadata.row_count(TableIndex::MethodDebugInformation), 4);
        assert_eq!(metadata.heaps().pdb.as_ref().unwrap().row_count(TableIndex::MethodDef), 4);
        assert!(!metadata.tables().is_present(TableIndex::Module));
        assert!(!metadata.tables().is_present(TableIndex::MethodDef));
        assert!(!metadata.heaps().pdb.as_ref().unwrap().has_table(TableIndex::Document));
        assert!(reader.sequence_points(4).unwrap().is_none());
    }

    #[test]
    fn external_counts_widen_simple_and_coded_debug_indexes() {
        let mut builder = PortablePdbBuilder::new();
        builder
            .set_type_system_row_counts(&[
                (TableIndex::MethodDef, 65_536),
                (TableIndex::Field, 2_048),
            ])
            .unwrap();
        builder.add_local_scope(
            Token::new(TableIndex::MethodDef, 65_536),
            0,
            &[(0, "last".into(), 0)],
            &[],
            0,
            7,
            1,
        );
        builder
            .add_custom_debug_information(
                Token::new(TableIndex::Field, 2_048),
                [1; 16],
                b"wide-parent",
            )
            .unwrap();
        let bytes = builder.finalize().unwrap();
        let reader = PortablePdbReader::parse(&bytes).unwrap();
        assert_eq!(reader.metadata().tables().row_size(TableIndex::LocalScope), Some(18));
        assert_eq!(
            reader.metadata().tables().row_size(TableIndex::CustomDebugInformation),
            Some(8)
        );
        assert_eq!(reader.metadata().row_count(TableIndex::MethodDebugInformation), 65_536);
        let scopes = reader.local_scopes(65_536).unwrap();
        assert_eq!(scopes[0].try_start, 7);
        assert_eq!(reader.local_variables(&scopes[0]).unwrap()[0].name, "last");
        assert_eq!(
            reader.custom_debug_informations().unwrap()[0].parent,
            Token::new(TableIndex::Field, 2_048)
        );
    }

    #[test]
    fn associated_counts_reject_invalid_tables_and_outside_references() {
        let mut builder = PortablePdbBuilder::new();
        assert!(builder.set_type_system_row_counts(&[(TableIndex::Document, 1)]).is_err());
        assert!(builder
            .set_type_system_row_counts(&[(TableIndex::MethodDef, 0x0100_0000)])
            .is_err());
        builder.set_type_system_row_counts(&[(TableIndex::MethodDef, 1)]).unwrap();
        builder.register_method(Token::new(TableIndex::MethodDef, 2)).unwrap();
        assert!(builder.finalize().is_err());
    }

    #[test]
    fn sorted_scopes_keep_locals_constants_and_debug_parents() {
        let mut builder = PortablePdbBuilder::new();
        let second = builder.add_local_scope(
            Token::new(TableIndex::MethodDef, 2),
            0,
            &[(2, "second".into(), 0)],
            &[("Second", &[0x08, 2, 0, 0, 0])],
            0,
            0,
            10,
        );
        builder.add_local_scope(
            Token::new(TableIndex::MethodDef, 1),
            0,
            &[(1, "inner".into(), 0)],
            &[("Inner", &[0x08, 1, 0, 0, 0])],
            0,
            3,
            2,
        );
        builder.add_local_scope(
            Token::new(TableIndex::MethodDef, 1),
            0,
            &[(0, "outer".into(), 0)],
            &[("Outer", &[0x08, 0, 0, 0, 0])],
            0,
            0,
            10,
        );
        for (parent, value) in [
            (Token::new(TableIndex::MethodDef, 2), "method2"),
            (Token::new(TableIndex::MethodDef, 1), "method1"),
            (Token::new(TableIndex::LocalScope, second.0), "second-scope"),
            (Token::new(TableIndex::LocalVariable, 1), "second-variable"),
            (Token::new(TableIndex::LocalConstant, 3), "outer-constant"),
        ] {
            builder.add_custom_debug_information(parent, [1; 16], value.as_bytes()).unwrap();
        }
        let bytes = builder.finalize().unwrap();
        let reader = PortablePdbReader::parse(&bytes).unwrap();
        let first = reader.local_scopes(1).unwrap();
        assert_eq!(first.iter().map(|scope| scope.try_start).collect::<Vec<_>>(), [0, 3]);
        assert_eq!(reader.local_variables(&first[0]).unwrap()[0].name, "outer");
        assert_eq!(reader.local_constants(&first[0]).unwrap()[0].name, "Outer");
        assert_eq!(reader.local_variables(&first[1]).unwrap()[0].name, "inner");
        let second = reader.local_scopes(2).unwrap();
        assert_eq!(reader.local_variables(&second[0]).unwrap()[0].name, "second");
        assert_eq!(reader.local_constants(&second[0]).unwrap()[0].name, "Second");
        let information = reader.custom_debug_informations().unwrap();
        for (value, table, rid) in [
            ("second-scope", TableIndex::LocalScope, 3),
            ("second-variable", TableIndex::LocalVariable, 3),
            ("outer-constant", TableIndex::LocalConstant, 1),
        ] {
            let entry = information.iter().find(|entry| entry.value == value.as_bytes()).unwrap();
            assert_eq!(entry.parent, Token::new(table, rid));
        }
        let parent_cells: Vec<_> = (1..=information.len() as u32)
            .map(|rid| {
                reader.metadata().column(TableIndex::CustomDebugInformation, rid, 0).unwrap()
            })
            .collect();
        assert!(parent_cells.windows(2).all(|pair| pair[0] <= pair[1]));
    }
}
