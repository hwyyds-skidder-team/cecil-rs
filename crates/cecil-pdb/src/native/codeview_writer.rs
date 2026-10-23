//! Handwritten CodeView symbols and C13 source information emission.
//!
//! Native local records retain names and type indices. The public read model
//! has no native register/frame location expressions or procedure type index,
//! so newly constructed native procedures use T_NOTYPE and no defrange data.

use std::collections::{BTreeMap, HashMap};

use cecil_core::{Error, Result};

use super::{
    ConstantValue, FunctionDebugInfo, NativeConstant, NativeLocal, NativeScope, SourceDocument,
    SourceLine,
};

pub(super) struct EncodedModule {
    /// Symbol signature, symbol records, then C13 subsections.
    pub bytes: Vec<u8>,
    pub symbols_size: u32,
    pub c13_size: u32,
    /// Referenced sources in the shared string-table order.
    pub files: Vec<String>,
    /// Every module uses the same table, allowing /names to mirror offsets.
    pub string_table: Vec<u8>,
}

fn bad(message: &str) -> Error {
    Error::argument(format!("native PDB writer: {message}"))
}

fn u32_len(length: usize) -> Result<u32> {
    u32::try_from(length).map_err(|_| bad("stream or record offset exceeds 4 GiB"))
}

fn w16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn w32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn cstr(bytes: &mut Vec<u8>, value: &str) -> Result<()> {
    if value.as_bytes().contains(&0) {
        return Err(bad("names must not contain NUL bytes"));
    }
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(0);
    Ok(())
}

fn align4(bytes: &mut Vec<u8>) {
    bytes.resize(bytes.len().next_multiple_of(4), 0);
}

/// Symbol record lengths include the kind and padding, exclude the length.
fn record(bytes: &mut Vec<u8>, kind: u16, payload: &[u8]) -> Result<u32> {
    let start = u32_len(bytes.len())?;
    let total = payload.len().checked_add(7).ok_or_else(|| bad("symbol size overflows"))? & !3;
    // This is the standard CodeView maximum, including RecordPrefix.
    if total > 0xff00 {
        return Err(bad("symbol record exceeds CodeView's 0xFF00-byte limit"));
    }
    w16(bytes, (total - 2) as u16);
    w16(bytes, kind);
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len() + total - payload.len() - 4, 0);
    Ok(start)
}

fn patch32(bytes: &mut [u8], at: u32, value: u32) -> Result<()> {
    let at = at as usize;
    bytes
        .get_mut(at..at + 4)
        .ok_or_else(|| bad("invalid symbol fixup"))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn subsection(bytes: &mut Vec<u8>, kind: u32, payload: &[u8]) -> Result<()> {
    w32(bytes, kind);
    w32(bytes, u32_len(payload.len())?);
    bytes.extend_from_slice(payload);
    align4(bytes);
    Ok(())
}

fn validate_function(function: &FunctionDebugInfo) -> Result<Vec<Vec<usize>>> {
    if function.segment == 0 || function.offset.checked_add(function.length).is_none() {
        return Err(bad("procedure segment/range is invalid"));
    }
    if let Some(token) = function.token {
        if token.table_byte() != 6 || token.rid() == 0 {
            return Err(bad("managed procedure requires a nonzero MethodDef token"));
        }
    }
    if function.scopes.is_empty() {
        return Ok(Vec::new());
    }
    let root = &function.scopes[0];
    if root.parent.is_some() || root.offset != 0 || root.length != function.length {
        return Err(bad("scope zero must cover the whole procedure"));
    }
    let mut children = vec![Vec::new(); function.scopes.len()];
    for (index, scope) in function.scopes.iter().enumerate().skip(1) {
        let parent = scope
            .parent
            .filter(|&parent| parent < children.len() && parent != index)
            .ok_or_else(|| bad("lexical scope parent is invalid"))?;
        let owner = &function.scopes[parent];
        let end = scope
            .offset
            .checked_add(scope.length)
            .ok_or_else(|| bad("lexical scope range overflows"))?;
        let parent_end = owner
            .offset
            .checked_add(owner.length)
            .ok_or_else(|| bad("lexical parent range overflows"))?;
        if scope.offset < owner.offset || end > parent_end || end > function.length {
            return Err(bad("lexical scope extends outside its parent/procedure"));
        }
        children[parent].push(index);
    }
    // Iterative traversal also rejects disconnected cycles without recursion.
    let mut visited = vec![false; children.len()];
    let mut pending = vec![0];
    while let Some(index) = pending.pop() {
        if visited[index] {
            return Err(bad("cyclic lexical scopes"));
        }
        visited[index] = true;
        pending.extend(children[index].iter().copied());
    }
    if visited.iter().any(|&value| !value) {
        return Err(bad("disconnected or cyclic lexical scopes"));
    }
    Ok(children)
}

fn local(bytes: &mut Vec<u8>, local: &NativeLocal, segment: u16) -> Result<()> {
    let mut payload = Vec::new();
    let kind = if let Some(index) = local.index {
        // S_MANSLOT: slot, type, offset, segment, flags, name. Native locations
        // are not represented by this model; a managed slot is location-complete.
        w32(&mut payload, index);
        w32(&mut payload, local.type_index);
        w32(&mut payload, 0);
        w16(&mut payload, segment);
        w16(&mut payload, local.flags);
        0x1120
    } else {
        w32(&mut payload, local.type_index);
        w16(&mut payload, local.flags);
        0x113e // S_LOCAL
    };
    cstr(&mut payload, &local.name)?;
    record(bytes, kind, &payload)?;
    Ok(())
}

fn numeric(bytes: &mut Vec<u8>, value: &ConstantValue) -> Result<()> {
    match value {
        ConstantValue::Signed(value) => {
            if let Ok(value) = i8::try_from(*value) {
                w16(bytes, 0x8000);
                bytes.push(value as u8);
            } else if let Ok(value) = i16::try_from(*value) {
                w16(bytes, 0x8001);
                w16(bytes, value as u16);
            } else if let Ok(value) = i32::try_from(*value) {
                w16(bytes, 0x8003);
                w32(bytes, value as u32);
            } else if let Ok(value) = i64::try_from(*value) {
                w16(bytes, 0x8009);
                bytes.extend_from_slice(&value.to_le_bytes());
            } else {
                w16(bytes, 0x8017);
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
        ConstantValue::Unsigned(value) => {
            if *value < 0x8000 {
                w16(bytes, *value as u16);
            } else if let Ok(value) = u16::try_from(*value) {
                w16(bytes, 0x8002);
                w16(bytes, value);
            } else if let Ok(value) = u32::try_from(*value) {
                w16(bytes, 0x8004);
                w32(bytes, value);
            } else if let Ok(value) = u64::try_from(*value) {
                w16(bytes, 0x800a);
                bytes.extend_from_slice(&value.to_le_bytes());
            } else {
                w16(bytes, 0x8018);
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
        ConstantValue::Float(value) => {
            w16(bytes, 0x8006);
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        ConstantValue::String(value) => {
            w16(bytes, 0x8010);
            w16(
                bytes,
                u16::try_from(value.len()).map_err(|_| bad("constant string is too large"))?,
            );
            bytes.extend_from_slice(value.as_bytes());
        }
        ConstantValue::Raw { leaf, bytes: payload } => {
            let expected = match leaf {
                0x8007 => 10,
                0x800b => 6,
                0x800c | 0x801a => 8,
                0x800e => 20,
                0x800f => 32,
                0x801c => 2,
                0x8008 | 0x800d | 0x8019 => 16,
                _ => return Err(bad("unsupported raw numeric leaf")),
            };
            if payload.len() != expected {
                return Err(bad("raw numeric leaf payload length is invalid"));
            }
            w16(bytes, *leaf);
            bytes.extend_from_slice(payload);
        }
    }
    Ok(())
}

fn constant(bytes: &mut Vec<u8>, value: &NativeConstant, managed: bool) -> Result<()> {
    let mut payload = Vec::new();
    w32(&mut payload, value.type_index);
    numeric(&mut payload, &value.value)?;
    cstr(&mut payload, &value.name)?;
    record(bytes, if managed { 0x112d } else { 0x1107 }, &payload)?;
    Ok(())
}

fn scope_members(
    bytes: &mut Vec<u8>,
    scope: &NativeScope,
    function: &FunctionDebugInfo,
) -> Result<()> {
    for item in &scope.locals {
        local(bytes, item, function.segment)?;
    }
    for item in &scope.constants {
        constant(bytes, item, function.token.is_some())?;
    }
    for item in &scope.imports {
        let mut payload = Vec::new();
        cstr(&mut payload, item)?;
        record(bytes, 0x1124, &payload)?;
    }
    Ok(())
}

fn procedure(
    bytes: &mut Vec<u8>,
    function: &FunctionDebugInfo,
    procedure_type: u32,
) -> Result<u32> {
    let children = validate_function(function)?;
    let mut payload = Vec::new();
    w32(&mut payload, 0); // parent
    w32(&mut payload, 0); // end fixup
    w32(&mut payload, 0); // next fixup
    w32(&mut payload, function.length);
    w32(&mut payload, 0); // debug start
    w32(&mut payload, function.length); // debug end
    w32(&mut payload, function.token.map_or(procedure_type, |token| token.0));
    w32(&mut payload, function.offset);
    w16(&mut payload, function.segment);
    payload.push(0); // procedure flags
    if function.token.is_some() {
        w16(&mut payload, 0);
    } // managed return register
    cstr(&mut payload, &function.name)?;
    let start = record(bytes, if function.token.is_some() { 0x112a } else { 0x1110 }, &payload)?;

    if !function.scopes.is_empty() {
        scope_members(bytes, &function.scopes[0], function)?;
        // Entry/exit events retain parent pointers even for arbitrarily ordered
        // flat scope vectors, with no process-stack dependence on nesting.
        enum Event {
            Enter(usize, u32),
            Exit(u32),
        }
        let mut pending = Vec::new();
        for &child in children[0].iter().rev() {
            pending.push(Event::Enter(child, start));
        }
        while let Some(event) = pending.pop() {
            match event {
                Event::Enter(index, parent) => {
                    let scope = &function.scopes[index];
                    let mut payload = Vec::new();
                    w32(&mut payload, parent);
                    w32(&mut payload, 0);
                    w32(&mut payload, scope.length);
                    w32(
                        &mut payload,
                        function
                            .offset
                            .checked_add(scope.offset)
                            .ok_or_else(|| bad("lexical block address overflows"))?,
                    );
                    w16(&mut payload, function.segment);
                    cstr(&mut payload, "")?;
                    let block = record(bytes, 0x1103, &payload)?;
                    scope_members(bytes, scope, function)?;
                    pending.push(Event::Exit(block));
                    for &child in children[index].iter().rev() {
                        pending.push(Event::Enter(child, block));
                    }
                }
                Event::Exit(block) => {
                    let end = record(bytes, 0x0006, &[])?;
                    patch32(bytes, block + 8, end)?;
                }
            }
        }
    }
    let end = record(bytes, 0x0006, &[])?;
    patch32(bytes, start + 8, end)?;
    Ok(start)
}

struct Sources {
    strings: Vec<u8>,
    checksums: Vec<u8>,
    checksum_offsets: HashMap<String, u32>,
    files: Vec<String>,
}

fn sources(documents: &[SourceDocument]) -> Result<Sources> {
    let mut result = Sources {
        strings: vec![0],
        checksums: Vec::new(),
        checksum_offsets: HashMap::new(),
        files: Vec::new(),
    };
    let mut name_offsets = HashMap::new();
    for document in documents {
        if document.name.len() > 1_048_576 {
            return Err(bad("source path exceeds limit"));
        }
        let length = match document.checksum_kind {
            0 => 0,
            1 => 16,
            2 => 20,
            3 => 32,
            _ => return Err(bad("unknown source checksum kind")),
        };
        if document.checksum.len() != length {
            return Err(bad("source checksum length does not match its kind"));
        }
        let name_offset = match name_offsets.get(&document.name) {
            Some(&offset) => offset,
            None => {
                let offset = u32_len(result.strings.len())?;
                cstr(&mut result.strings, &document.name)?;
                name_offsets.insert(document.name.clone(), offset);
                result.files.push(document.name.clone());
                offset
            }
        };
        let offset = u32_len(result.checksums.len())?;
        result.checksum_offsets.entry(document.name.clone()).or_insert(offset);
        w32(&mut result.checksums, name_offset);
        result.checksums.push(length as u8);
        result.checksums.push(document.checksum_kind);
        result.checksums.extend_from_slice(&document.checksum);
        align4(&mut result.checksums);
    }
    Ok(result)
}

fn line_equal(a: &SourceLine, b: &SourceLine) -> bool {
    a.offset == b.offset
        && a.start_line == b.start_line
        && a.end_line == b.end_line
        && a.start_column == b.start_column
        && a.end_column == b.end_column
        && a.is_statement == b.is_statement
        && a.file == b.file
}

fn lines(bytes: &mut Vec<u8>, function: &FunctionDebugInfo, sources: &Sources) -> Result<()> {
    if function.lines.is_empty() {
        return Ok(());
    }
    let mut by_file: BTreeMap<&str, Vec<&SourceLine>> = BTreeMap::new();
    for line in &function.lines {
        if function.offset.checked_add(line.offset).is_none() {
            return Err(bad("source line address overflows"));
        }
        if line.offset >= function.length && function.length != 0 {
            return Err(bad("source line offset exceeds procedure"));
        }
        if line.start_line > 0x00ff_ffff
            || line.end_line < line.start_line
            || line.end_line - line.start_line > 127
        {
            return Err(bad("source line range exceeds C13 representation"));
        }
        by_file.entry(&line.file).or_default().push(line);
    }
    let mut payload = Vec::new();
    w32(&mut payload, function.offset);
    w16(&mut payload, function.segment);
    w16(&mut payload, 1); // columns present
    w32(&mut payload, function.length);
    for (file, mut lines) in by_file {
        lines.sort_by_key(|line| line.offset);
        let file_offset = sources
            .checksum_offsets
            .get(file)
            .copied()
            .ok_or_else(|| bad("source line file has no document/checksum entry"))?;
        w32(&mut payload, file_offset);
        w32(&mut payload, u32_len(lines.len())?);
        w32(
            &mut payload,
            u32_len(
                lines
                    .len()
                    .checked_mul(12)
                    .and_then(|v| v.checked_add(12))
                    .ok_or_else(|| bad("line block size overflows"))?,
            )?,
        );
        for line in &lines {
            w32(&mut payload, line.offset);
            w32(
                &mut payload,
                line.start_line
                    | ((line.end_line - line.start_line) << 24)
                    | if line.is_statement { 0x8000_0000 } else { 0 },
            );
        }
        for line in lines {
            w16(&mut payload, line.start_column);
            w16(&mut payload, line.end_column);
        }
    }
    subsection(bytes, 0xf2, &payload)
}

pub(super) fn encode_module(
    functions: &[FunctionDebugInfo],
    documents: &[SourceDocument],
) -> Result<EncodedModule> {
    encode_module_with_procedure_types(functions, documents, &vec![0; functions.len()])
}

/// Retains native procedure signatures extracted from an original symbol
/// stream. Type indices align with the unsorted input function slice;
/// managed records always use their MethodDef tokens instead of type indices.
pub(super) fn encode_module_with_procedure_types(
    functions: &[FunctionDebugInfo],
    documents: &[SourceDocument],
    procedure_types: &[u32],
) -> Result<EncodedModule> {
    if procedure_types.len() != functions.len() {
        return Err(bad("procedure type indices must align with input functions"));
    }
    let sources = sources(documents)?;
    let mut bytes = 4u32.to_le_bytes().to_vec();
    let mut ordered: Vec<_> = functions.iter().zip(procedure_types).collect();
    ordered.sort_by(|(a, _), (b, _)| {
        (a.segment, a.offset, a.token.map_or(0, |t| t.0), &a.name).cmp(&(
            b.segment,
            b.offset,
            b.token.map_or(0, |t| t.0),
            &b.name,
        ))
    });
    let mut previous = None;
    for (function, &procedure_type) in &ordered {
        let start = procedure(&mut bytes, function, procedure_type)?;
        if let Some(previous) = previous {
            patch32(&mut bytes, previous + 12, start)?;
        }
        previous = Some(start);
    }
    let symbols_size = u32_len(bytes.len())?;
    subsection(&mut bytes, 0xf3, &sources.strings)?;
    subsection(&mut bytes, 0xf4, &sources.checksums)?;
    let mut addresses: HashMap<(u16, u32), &FunctionDebugInfo> = HashMap::new();
    for (function, _) in ordered {
        if let Some(other) = addresses.get(&(function.segment, function.offset)) {
            // C13 targets segment/address, not symbol identity. Emitting the
            // same line block twice would duplicate every target's mappings.
            if function.lines.len() != other.lines.len()
                || !function.lines.iter().zip(&other.lines).all(|(a, b)| line_equal(a, b))
            {
                return Err(bad("procedures sharing an address have conflicting source lines"));
            }
            continue;
        }
        lines(&mut bytes, function, &sources)?;
        addresses.insert((function.segment, function.offset), function);
    }
    let c13_size = u32_len(bytes.len() - symbols_size as usize)?;
    // The module debug stream ends in a sized global-reference substream.
    // This writer emits no module-global reference offsets.
    w32(&mut bytes, 0);
    Ok(EncodedModule {
        bytes,
        symbols_size,
        c13_size,
        files: sources.files,
        string_table: sources.strings,
    })
}

/// Public-symbol records, with no module signature or hash/index header.
/// Segment zero occurs in managed COM+ entry-point records: their offset is a
/// metadata token rather than a section-relative native address.
pub(super) fn encode_publics(publics: &[(String, u16, u32, u32)]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for (name, segment, offset, flags) in publics {
        if flags & !0xf != 0 {
            return Err(bad("public symbol flags exceed the CodeView mask"));
        }
        let mut payload = Vec::new();
        w32(&mut payload, *flags);
        w32(&mut payload, *offset);
        w16(&mut payload, *segment);
        cstr(&mut payload, name)?;
        record(&mut bytes, 0x110e, &payload)?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{NativePdbBuilder, NativePdbReader};
    use cecil_core::Token;

    fn function(managed: bool) -> FunctionDebugInfo {
        FunctionDebugInfo {
            token: managed.then_some(Token(0x0600_0001)),
            name: if managed { "Managed" } else { "Native" }.into(),
            module_index: 0,
            segment: 1,
            offset: if managed { 0x40 } else { 0x100 },
            length: 64,
            rva: None,
            lines: vec![
                SourceLine {
                    rva: None,
                    offset: 0,
                    start_line: 5,
                    end_line: 6,
                    start_column: 1,
                    end_column: 7,
                    is_statement: true,
                    file: "a.cs".into(),
                },
                SourceLine {
                    rva: None,
                    offset: 9,
                    start_line: 20,
                    end_line: 20,
                    start_column: 3,
                    end_column: 9,
                    is_statement: false,
                    file: "b.cs".into(),
                },
            ],
            scopes: vec![
                NativeScope {
                    parent: None,
                    offset: 0,
                    length: 64,
                    locals: vec![NativeLocal {
                        name: "arg".into(),
                        index: managed.then_some(2),
                        type_index: 0x74,
                        flags: 1,
                    }],
                    constants: vec![NativeConstant {
                        name: "negative".into(),
                        type_index: 0x74,
                        value: ConstantValue::Signed(-12),
                    }],
                    imports: vec!["System".into()],
                },
                NativeScope {
                    parent: Some(2),
                    offset: 12,
                    length: 3,
                    locals: vec![NativeLocal {
                        name: "inner".into(),
                        index: managed.then_some(3),
                        type_index: 0x74,
                        flags: 0,
                    }],
                    constants: Vec::new(),
                    imports: Vec::new(),
                },
                NativeScope {
                    parent: Some(0),
                    offset: 10,
                    length: 20,
                    locals: Vec::new(),
                    constants: Vec::new(),
                    imports: Vec::new(),
                },
            ],
        }
    }

    fn documents() -> Vec<SourceDocument> {
        vec![
            SourceDocument { name: "a.cs".into(), checksum_kind: 1, checksum: vec![1; 16] },
            SourceDocument { name: "b.cs".into(), checksum_kind: 3, checksum: vec![2; 32] },
        ]
    }

    #[test]
    fn emitted_procedures_scopes_locals_and_lines_read_back() {
        let mut builder = NativePdbBuilder::new();
        builder.set_identity([7; 16], 42, 3);
        let mut headers = [0; 40];
        headers[12..16].copy_from_slice(&0x1000u32.to_le_bytes());
        builder.set_section_headers(&headers).unwrap();
        for document in documents() {
            builder.add_document(document).unwrap();
        }
        let originals = [function(true), function(false)];
        for function in &originals {
            builder.add_function(function.clone()).unwrap();
        }
        builder.add_public("Native", 1, 0x100, 2).unwrap();
        let bytes = builder.finalize().unwrap();
        let reader = NativePdbReader::open(&bytes).unwrap();
        assert_eq!(reader.function_debug_info().len(), 2);
        for original in &originals {
            let actual = reader
                .function_debug_info()
                .iter()
                .find(|item| item.name == original.name)
                .unwrap();
            assert_eq!(actual.token, original.token);
            assert_eq!(
                (actual.segment, actual.offset, actual.length),
                (original.segment, original.offset, original.length)
            );
            assert_eq!(actual.lines.len(), original.lines.len());
            for (a, b) in actual.lines.iter().zip(&original.lines) {
                assert!(line_equal(a, b));
            }
            assert_eq!(actual.scopes[0], original.scopes[0]);
            assert_eq!(actual.scopes[1].offset, 10);
            assert_eq!(actual.scopes[2].offset, 12);
            assert_eq!(actual.scopes[2].parent, Some(1));
            assert_eq!(actual.scopes[2].locals, original.scopes[1].locals);
            assert_eq!(actual.rva, original.token.is_none().then_some(0x1100));
        }
        assert_eq!(reader.source_documents(), documents());
        assert!(reader.publics().iter().any(|(name, rva)| name == "Native" && *rva == 0x1100));
    }

    #[test]
    fn scope_pointers_address_record_starts_and_every_record_is_aligned() {
        let module = encode_module(&[function(false)], &documents()).unwrap();
        let bytes = &module.bytes[..module.symbols_size as usize];
        let mut at = 4;
        while at < bytes.len() {
            let size = u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap()) as usize;
            assert_eq!((size + 2) % 4, 0);
            let kind = u16::from_le_bytes(bytes[at + 2..at + 4].try_into().unwrap());
            if matches!(kind, 0x1110 | 0x1103) {
                let parent = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
                let end = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as usize;
                if parent != 0 {
                    assert!(parent < at);
                }
                assert!(end > at);
                assert_eq!(u16::from_le_bytes(bytes[end + 2..end + 4].try_into().unwrap()), 6);
            }
            at += size + 2;
        }
        assert_eq!(at, bytes.len());
    }

    #[test]
    fn retained_native_procedure_types_follow_functions_when_sorted() {
        let native = function(false);
        let managed = function(true);
        let module =
            encode_module_with_procedure_types(&[native, managed], &documents(), &[0x1001, 0x2222])
                .unwrap();
        let mut at = 4;
        let mut types = Vec::new();
        while at < module.symbols_size as usize {
            let size = u16::from_le_bytes(module.bytes[at..at + 2].try_into().unwrap()) as usize;
            let kind = u16::from_le_bytes(module.bytes[at + 2..at + 4].try_into().unwrap());
            if matches!(kind, 0x1110 | 0x112a) {
                types.push((
                    kind,
                    u32::from_le_bytes(module.bytes[at + 28..at + 32].try_into().unwrap()),
                ));
            }
            at += size + 2;
        }
        assert_eq!(types, vec![(0x112a, 0x0600_0001), (0x1110, 0x1001)]);
        assert!(encode_module_with_procedure_types(&[function(false)], &documents(), &[]).is_err());
    }

    #[test]
    fn invalid_scope_cycles_ranges_names_and_source_data_fail() {
        let docs = documents();
        let mut f = function(false);
        f.scopes[2].parent = Some(1);
        assert!(encode_module(&[f], &docs).is_err());
        let mut f = function(false);
        f.scopes[1].length = 100;
        assert!(encode_module(&[f], &docs).is_err());
        let mut f = function(false);
        f.name = "bad\0name".into();
        assert!(encode_module(&[f], &docs).is_err());
        let mut f = function(false);
        f.lines[0].end_line = 200;
        assert!(encode_module(&[f], &docs).is_err());
        let mut f = function(false);
        f.lines[0].file = "missing.cs".into();
        assert!(encode_module(&[f], &docs).is_err());
        let mut bad_docs = docs;
        bad_docs[0].checksum.clear();
        assert!(encode_module(&[], &bad_docs).is_err());
        assert!(encode_publics(&[("native".into(), 1, 0, 0x10)]).is_err());
    }

    #[test]
    fn managed_entry_point_publics_keep_zero_segment_and_input_order() {
        let records = encode_publics(&[
            ("COM+_Entry_Point".into(), 0, 0x0600_0010, 0),
            ("native".into(), 1, 0x40, 2),
        ])
        .unwrap();
        assert_eq!(u16::from_le_bytes(records[12..14].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(records[8..12].try_into().unwrap()), 0x0600_0010);
        let end = 2 + u16::from_le_bytes(records[..2].try_into().unwrap()) as usize;
        assert_eq!(
            &records[14..end].split(|byte| *byte == 0).next().unwrap(),
            &b"COM+_Entry_Point"
        );
        assert_eq!(u16::from_le_bytes(records[end + 12..end + 14].try_into().unwrap()), 1);
    }

    #[test]
    fn shared_procedure_addresses_do_not_duplicate_line_blocks() {
        let docs = documents();
        let mut native = function(false);
        let mut managed = function(true);
        managed.offset = native.offset;
        let module = encode_module(&[managed.clone(), native.clone()], &docs).unwrap();
        let mut at = module.symbols_size as usize;
        let mut line_blocks = 0;
        while at < module.symbols_size as usize + module.c13_size as usize {
            let kind = u32::from_le_bytes(module.bytes[at..at + 4].try_into().unwrap());
            let len = u32::from_le_bytes(module.bytes[at + 4..at + 8].try_into().unwrap()) as usize;
            line_blocks += usize::from(kind == 0xf2);
            at = (at + 8 + len).next_multiple_of(4);
        }
        assert_eq!(line_blocks, 1);
        native.lines[0].start_line += 1;
        assert!(encode_module(&[native, managed], &docs).is_err());
    }

    #[test]
    fn numeric_leaves_represent_full_signed_unsigned_and_opaque_domains() {
        for value in [
            ConstantValue::Signed(i128::MIN),
            ConstantValue::Signed(-1),
            ConstantValue::Unsigned(u128::MAX),
            ConstantValue::Unsigned(5),
            ConstantValue::Float(-0.0),
            ConstantValue::String("中文\0blob".into()),
            ConstantValue::Raw { leaf: 0x8007, bytes: vec![0; 10] },
        ] {
            let mut bytes = Vec::new();
            numeric(&mut bytes, &value).unwrap();
            assert!(bytes.len() >= 2);
        }
        assert!(numeric(&mut Vec::new(), &ConstantValue::Raw { leaf: 0x8007, bytes: vec![0; 9] })
            .is_err());
    }

    #[test]
    fn full_numeric_constant_values_survive_native_pdb_readback() {
        let values = [
            ConstantValue::Signed(i128::MIN),
            ConstantValue::Signed(-1),
            ConstantValue::Unsigned(u128::MAX),
            ConstantValue::Unsigned(5),
            ConstantValue::Float(-0.0),
            ConstantValue::String("中文\0blob".into()),
            ConstantValue::Raw { leaf: 0x8007, bytes: vec![0; 10] },
        ];
        let mut f = function(false);
        f.scopes[0].constants = values
            .iter()
            .enumerate()
            .map(|(i, value)| NativeConstant {
                name: format!("C{i}"),
                type_index: 0x74,
                value: value.clone(),
            })
            .collect();
        let mut builder = NativePdbBuilder::new();
        for document in documents() {
            builder.add_document(document).unwrap();
        }
        builder.add_function(f).unwrap();
        let bytes = builder.finalize().unwrap();
        let reader = NativePdbReader::open(&bytes).unwrap();
        let actual = &reader.function_debug_info()[0].scopes[0].constants;
        assert_eq!(actual.len(), values.len());
        for (constant, expected) in actual.iter().zip(values) {
            match (&constant.value, expected) {
                (ConstantValue::Float(a), ConstantValue::Float(b)) => {
                    assert_eq!(a.to_bits(), b.to_bits())
                }
                (actual, expected) => assert_eq!(actual, &expected),
            }
        }
    }
}
