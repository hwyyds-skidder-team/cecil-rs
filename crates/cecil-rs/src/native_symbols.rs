//! Native PDB output and PE CodeView attachment for the assembly facade.

use cecil_core::{Error, Result, TableIndex, Token};
use cecil_pdb::native::{
    FunctionDebugInfo, NativePdbBuilder, NativeScope, SourceDocument, SourceLine,
};

use crate::model::types::{ROperand, ResolvedBody};
use crate::module_def::Module;

fn body_length(body: &ResolvedBody) -> Result<u32> {
    let mut end = 0u32;
    for instruction in &body.instructions {
        let mut size = cecil_cil::opcode::instruction_size(instruction.opcode);
        if let ROperand::Switch(targets) = &instruction.operand {
            size = size
                .checked_add(targets.len().saturating_mul(4))
                .ok_or_else(|| Error::argument("IL switch size overflows"))?;
        }
        end = end
            .checked_add(
                u32::try_from(size)
                    .map_err(|_| Error::argument("IL instruction size exceeds u32"))?,
            )
            .ok_or_else(|| Error::argument("IL range exceeds u32"))?;
    }
    Ok(end)
}

/// Serializes modeled native/managed Windows PDB information. Original TPI/IPI
/// streams are retained when symbols were loaded from a native PDB. Source
/// offsets come from the current debug model; callers editing IL also update
/// its sequence points and scopes, as with portable PDB output.
pub fn build_native_pdb(module: &Module) -> Result<Vec<u8>> {
    build_native_pdb_for_image(module, None)
}

pub(crate) fn build_native_pdb_for_image(
    module: &Module,
    image: Option<&cecil_pe::Image>,
) -> Result<Vec<u8>> {
    build_native_pdb_for_output(module, image, None)
}

pub(crate) fn build_native_pdb_with_local_signatures(
    module: &Module,
    signatures: &std::collections::BTreeMap<u32, Token>,
) -> Result<Vec<u8>> {
    build_native_pdb_for_output(module, None, Some(signatures))
}

fn build_native_pdb_for_output(
    module: &Module,
    image: Option<&cecil_pe::Image>,
    signatures: Option<&std::collections::BTreeMap<u32, Token>>,
) -> Result<Vec<u8>> {
    let definitions = crate::write::definition_rows::DefinitionRows::for_symbols(module)?;
    let metadata = image
        .map(|image| {
            let (rva, size) = image.metadata_rva()?;
            cecil_metadata::MetadataReader::parse(image.rva_bytes(rva, size)?)
        })
        .transpose()?;
    let mut builder = match module.native_debug.as_ref().and_then(|d| d.original_pdb.as_deref()) {
        Some(bytes) => NativePdbBuilder::from_pdb(bytes)?,
        None => {
            let mut builder = NativePdbBuilder::new();
            builder.set_identity(module.guid, 0, 1);
            builder
        }
    };
    builder.set_machine(module.architecture.machine());
    let mut functions = module.native_debug.as_ref().map_or_else(Vec::new, |d| d.functions.clone());
    functions.retain(|function| {
        function.token.is_none_or(|token| {
            token.table_byte() == TableIndex::MethodDef as u8
                && token.rid() > 0
                && module
                    .methods
                    .get(token.rid() as usize - 1)
                    .is_some_and(|method| method.body.is_some())
        })
    });
    let mut documents = module.native_debug.as_ref().map_or_else(Vec::new, |d| d.documents.clone());
    if let Some(debug) = &module.debug {
        for document in &debug.documents {
            let mapped = SourceDocument {
                name: document.name.clone(),
                checksum_kind: match document.hash_algorithm {
                    [0x60, 0xa6, 0x6e, 0x40, 0xcf, 0x64, 0x82, 0x4c, 0xb6, 0xf0, 0x42, 0xd4, 0x81, 0x72, 0xa7, 0x99] => {
                        1
                    }
                    [0xec, 0x16, 0x18, 0xff, 0xaa, 0x5e, 0x10, 0x4d, 0x87, 0xf7, 0x6f, 0x49, 0x63, 0x83, 0x34, 0x60] => {
                        2
                    }
                    [0x0f, 0xd0, 0x29, 0x88, 0xb8, 0x11, 0x13, 0x42, 0x87, 0x8b, 0x77, 0x0e, 0x85, 0x97, 0xac, 0x16] => {
                        3
                    }
                    _ if document.hash.is_empty() => 0,
                    _ => {
                        return Err(Error::argument(
                            "native PDB output requires a known source checksum algorithm",
                        ))
                    }
                },
                checksum: document.hash.clone(),
            };
            if let Some(existing) = documents.iter_mut().find(|d| d.name == mapped.name) {
                if mapped.checksum_kind != 0 || existing.checksum_kind == 0 {
                    *existing = mapped;
                }
            } else {
                documents.push(mapped);
            }
        }
    }
    // Dedicated synthetic segments keep managed IL bases distinct from native
    // machine addresses and from each other. C13 line blocks match addresses.
    let managed_segment = (1..=u16::MAX)
        .rev()
        .find(|segment| {
            !functions
                .iter()
                .any(|function| function.token.is_none() && function.segment == *segment)
        })
        .ok_or_else(|| Error::argument("no segment remains for managed PDB IL addresses"))?;
    let mut il_base = 0u32;
    for (id, method) in module.iter_methods() {
        let Some(body) = &method.body else { continue };
        let token = Token::new(TableIndex::MethodDef, id.0 + 1);
        let index = functions.iter().position(|function| function.token == Some(token));
        let index = index.unwrap_or_else(|| {
            functions.push(FunctionDebugInfo {
                token: Some(token),
                name: method.name.clone(),
                module_index: 0,
                segment: managed_segment,
                offset: 0,
                length: 0,
                rva: None,
                lines: Vec::new(),
                scopes: Vec::new(),
            });
            functions.len() - 1
        });
        let function = &mut functions[index];
        let local_signature = if let Some(signatures) = signatures {
            Some(signatures.get(&token.rid()).copied().unwrap_or(Token::NIL))
        } else if let Some(metadata) = &metadata {
            let rva = metadata.column(TableIndex::MethodDef, token.rid(), 0)?;
            let local_signature = if rva == 0 {
                Token::NIL
            } else {
                let image = image.unwrap();
                let section = image
                    .section_at_virtual_address(rva)
                    .ok_or_else(|| Error::bad_image("unmapped managed method for PDB output"))?;
                let remaining = (section.size_of_raw_data as u64)
                    .checked_sub(rva - section.virtual_address as u64)
                    .ok_or_else(|| Error::bad_image("managed method is not file backed"))?
                    as usize;
                cecil_cil::decode_method_body(image.rva_bytes(rva, remaining)?)?.0.local_var_sig_tok
            };
            Some(local_signature)
        } else {
            None
        };
        if let Some(local_signature) = local_signature {
            for scope in &mut function.scopes {
                scope.locals.retain(|local| {
                    local.index.is_none_or(|index| index < body.locals.len() as u32)
                });
                for local in &mut scope.locals {
                    if local.type_index >> 24 == TableIndex::StandAloneSig as u32 {
                        local.type_index = local_signature.0;
                    }
                }
            }
        }
        function.name = method.name.clone();
        function.segment = managed_segment;
        function.offset = il_base;
        function.length = body_length(body)?;
        function.rva = None;
        if let Some(root) = function.scopes.first_mut() {
            if root.parent.is_none() {
                root.offset = 0;
                root.length = function.length;
            }
        }
        il_base = il_base
            .checked_add(function.length.max(1))
            .ok_or_else(|| Error::argument("managed PDB IL address space exhausted"))?;
        if let Some(debug) = &module.debug {
            if let Some(groups) = debug.points.get(&token.rid()) {
                let mut lines = Vec::new();
                for (document, points) in groups {
                    let file = debug.documents.get(*document as usize).ok_or_else(|| {
                        Error::argument("PDB sequence point document is out of range")
                    })?;
                    for point in points {
                        lines.push(SourceLine {
                            rva: None,
                            offset: u32::try_from(point.offset).map_err(|_| {
                                Error::argument("negative PDB sequence point offset")
                            })?,
                            start_line: point.start_line,
                            end_line: point.end_line,
                            start_column: u16::try_from(point.start_column).map_err(|_| {
                                Error::argument("native PDB source column exceeds u16")
                            })?,
                            end_column: u16::try_from(point.end_column).map_err(|_| {
                                Error::argument("native PDB source column exceeds u16")
                            })?,
                            is_statement: !point.is_hidden(),
                            file: file.name.clone(),
                        });
                    }
                }
                function.lines = lines;
            }
            if function.scopes.is_empty() {
                function.scopes.push(NativeScope {
                    parent: None,
                    offset: 0,
                    length: function.length,
                    locals: Vec::new(),
                    constants: Vec::new(),
                    imports: Vec::new(),
                });
                if let Some(scopes) = debug.scopes.get(&token.rid()) {
                    for scope in scopes {
                        function.scopes.push(NativeScope {
                            parent: Some(0),
                            offset: u32::try_from(scope.try_start)
                                .map_err(|_| Error::argument("negative PDB scope offset"))?,
                            length: u32::try_from(scope.try_length)
                                .map_err(|_| Error::argument("negative PDB scope length"))?,
                            locals: Vec::new(),
                            constants: Vec::new(),
                            imports: Vec::new(),
                        });
                    }
                }
            } else if function.scopes[0].parent.is_none() {
                function.scopes[0].offset = 0;
                function.scopes[0].length = function.length;
                if let Some(scopes) = debug.scopes.get(&token.rid()) {
                    // Native symbol loading populates this parallel portable
                    // range model. Keep local/type data while honoring edited
                    // lexical boundaries when the same scopes are present.
                    if scopes.len() == function.scopes.len() {
                        for (scope, range) in function.scopes.iter_mut().zip(scopes).skip(1) {
                            scope.offset = u32::try_from(range.try_start)
                                .map_err(|_| Error::argument("negative PDB scope offset"))?;
                            scope.length = u32::try_from(range.try_length)
                                .map_err(|_| Error::argument("negative PDB scope length"))?;
                        }
                    }
                }
            }
        }
    }
    // Keep source tokens during all lookups above. Remapping each function
    // while iterating can make its new token collide with a later source RID.
    if let Some(rows) = &definitions {
        for function in &mut functions {
            function.token = function.token.map(|token| rows.token(token)).transpose()?;
        }
    }
    builder.clear_functions();
    builder.clear_documents();
    for document in documents {
        builder.add_document(document)?;
    }
    for function in functions {
        builder.add_function(function)?;
    }
    let bytes = builder.finalize()?;
    // Rebuilt symbol content gets a distinct, deterministic cache identity.
    // The low-level from_pdb builder intentionally preserves caller identity;
    // facade output must not match stale symbols from the original image.
    let hash = cecil_pdb::embedded::sha256(&bytes);
    let msf = cecil_pdb::native::msf::MsfImage::parse(&bytes)?;
    let mut streams: Vec<Option<Vec<u8>>> =
        (0..msf.stream_count()).map(|index| msf.stream(index).map(<[u8]>::to_vec)).collect();
    let info = streams[1].as_mut().unwrap();
    info[4..8].copy_from_slice(&hash[16..20]);
    info[8..12].copy_from_slice(&1u32.to_le_bytes());
    info[12..28].copy_from_slice(&hash[..16]);
    streams[3].as_mut().unwrap()[8..12].copy_from_slice(&1u32.to_le_bytes());
    cecil_pdb::native::msf_writer::write_msf(&streams, msf.page_size)
}

pub(crate) fn native_debug_entries(
    pdb: &[u8],
    name: &str,
) -> Result<Vec<cecil_pe::ImageDebugEntry>> {
    let reader = cecil_pdb::native::NativePdbReader::open(pdb)?;
    let (guid, _, signature, age) = reader.pdb_id();
    let mut rsds = Vec::new();
    rsds.extend_from_slice(b"RSDS");
    rsds.extend_from_slice(&guid);
    rsds.extend_from_slice(&age.to_le_bytes());
    if name.as_bytes().contains(&0) {
        return Err(Error::argument("PDB name contains NUL"));
    }
    rsds.extend_from_slice(name.as_bytes());
    rsds.push(0);
    let checksum = cecil_pdb::embedded::pdb_checksum_payload(pdb);
    Ok(vec![
        cecil_pe::ImageDebugEntry {
            directory: cecil_pe::ImageDebugDirectory {
                kind: 2,
                time_date_stamp: signature as i32,
                size_of_data: i32::try_from(rsds.len())
                    .map_err(|_| Error::argument("PDB name is too long"))?,
                ..Default::default()
            },
            data: rsds,
        },
        cecil_pe::ImageDebugEntry {
            directory: cecil_pe::ImageDebugDirectory {
                kind: 19,
                major_version: 1,
                size_of_data: checksum.len() as i32,
                ..Default::default()
            },
            data: checksum,
        },
    ])
}

/// Appends the current debug directory without moving pre-existing payload.
pub(crate) fn attach_native_pdb(image: Vec<u8>, pdb: &[u8], name: &str) -> Result<Vec<u8>> {
    attach_debug_entries(image, native_debug_entries(pdb, name)?)
}

pub(crate) fn attach_debug_entries(
    image: Vec<u8>,
    symbols: Vec<cecil_pe::ImageDebugEntry>,
) -> Result<Vec<u8>> {
    let parsed = cecil_pe::Image::parse(&image)?;
    if parsed.cli_header.flags & 8 != 0
        || parsed.cli_header.strong_name_size != 0
        || parsed.data_directories[cecil_pe::DataDirectoryIndex::Certificate as usize].size != 0
    {
        return Err(Error::unsupported("changing signed native debug data requires re-signing"));
    }
    let mut entries = parsed.debug_entries.clone();
    entries.retain(|e| !matches!(e.directory.kind, 2 | 17 | 19));
    entries.extend(symbols);
    let directory_size = u32::try_from(
        entries
            .len()
            .checked_mul(28)
            .ok_or_else(|| Error::argument("debug directory size overflows"))?,
    )
    .map_err(|_| Error::argument("debug directory exceeds 4 GiB"))?;
    let section = cecil_pe::ImageWriter::append_section_layout(&parsed)?;
    let mut payload = cecil_core::io::ByteWriter::new();
    let mut data_at = entries
        .len()
        .checked_mul(28)
        .ok_or_else(|| Error::argument("debug directory size overflows"))?;
    for entry in &entries {
        let data_offset =
            u32::try_from(data_at).map_err(|_| Error::argument("debug data exceeds 4 GiB"))?;
        payload.i32(entry.directory.characteristics);
        payload.i32(entry.directory.time_date_stamp);
        payload.i16(entry.directory.major_version);
        payload.i16(entry.directory.minor_version);
        payload.i32(entry.directory.kind);
        payload.u32(
            u32::try_from(entry.data.len())
                .map_err(|_| Error::argument("debug data exceeds 4 GiB"))?,
        );
        payload.u32(
            section
                .virtual_address
                .checked_add(data_offset)
                .ok_or_else(|| Error::argument("debug RVA exceeds 4 GiB"))?,
        );
        payload.u32(
            section
                .pointer_to_raw_data
                .checked_add(data_offset)
                .ok_or_else(|| Error::argument("debug file offset exceeds 4 GiB"))?,
        );
        data_at = data_at
            .checked_add(entry.data.len())
            .ok_or_else(|| Error::argument("debug data size overflows"))?;
    }
    for entry in entries {
        payload.bytes(&entry.data);
    }
    let mut output = cecil_pe::ImageWriter::append_managed_section(&parsed, payload.as_slice())?;
    let optional = u32::from_le_bytes(output[0x3c..0x40].try_into().unwrap()) as usize + 24;
    let magic = u16::from_le_bytes(output[optional..optional + 2].try_into().unwrap());
    let directories = optional + if magic == 0x20b { 112 } else { 96 };
    let debug = directories + cecil_pe::DataDirectoryIndex::Debug as usize * 8;
    let directory_count_at = optional + if magic == 0x20b { 108 } else { 92 };
    let directory_count =
        u32::from_le_bytes(output[directory_count_at..directory_count_at + 4].try_into().unwrap());
    if directory_count <= cecil_pe::DataDirectoryIndex::Debug as u32 {
        output[directory_count_at..directory_count_at + 4]
            .copy_from_slice(&(cecil_pe::DataDirectoryIndex::Debug as u32 + 1).to_le_bytes());
    }
    output[debug..debug + 4].copy_from_slice(&section.virtual_address.to_le_bytes());
    // IMAGE_DEBUG_DIRECTORY size excludes the separately stored payloads.
    output[debug + 4..debug + 8].copy_from_slice(&directory_size.to_le_bytes());
    Ok(output)
}
