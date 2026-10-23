//! Handwritten CodeView decoder. Every cursor is restricted to its record or
//! subsection; limits apply to aggregate work as well as individual lengths.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::{heap_string, positive_size, sym, BitReader, DbiDbgHdr, DbiHeader, DbiModuleInfo};
use crate::native::msf::MsfImage;
use cecil_core::{Error, Result, Token};

/// A source checksum from a C13 file-checksum subsection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDocument {
    pub name: String,
    /// CodeView checksum kind: 0 none, 1 MD5, 2 SHA-1, 3 SHA-256.
    pub checksum_kind: u8,
    pub checksum: Vec<u8>,
}

/// A line entry with a function-relative IL/native-code offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLine {
    /// Native image RVA when section/OMAP information is available. Managed
    /// procedures carry IL offsets and therefore always have `None` here.
    pub rva: Option<u64>,
    pub offset: u32,
    pub start_line: u32,
    pub end_line: u32,
    pub start_column: u16,
    pub end_column: u16,
    pub is_statement: bool,
    pub file: String,
}

/// A local's name, slot/type information and CodeView local flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeLocal {
    pub name: String,
    /// Managed IL slot; `None` for register/frame-based native locals.
    pub index: Option<u32>,
    pub type_index: u32,
    pub flags: u16,
}

/// CodeView numeric leaves decoded without platform-specific APIs.
#[derive(Debug, Clone, PartialEq)]
pub enum ConstantValue {
    Signed(i128),
    Unsigned(u128),
    Float(f64),
    String(String),
    /// Formats without a portable primitive equivalent (e.g. real80).
    Raw {
        leaf: u16,
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct NativeConstant {
    pub name: String,
    pub type_index: u32,
    pub value: ConstantValue,
}

/// Flat lexical scope tree. Parent indices refer to the same function's scope
/// vector; offsets are relative to that function, not image RVAs.
#[derive(Debug, Clone, PartialEq)]
pub struct NativeScope {
    pub parent: Option<usize>,
    pub offset: u32,
    pub length: u32,
    pub locals: Vec<NativeLocal>,
    pub constants: Vec<NativeConstant>,
    pub imports: Vec<String>,
}

/// Managed and unmanaged procedures recovered from module CodeView records.
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionDebugInfo {
    /// Managed MethodDef token; native type/item indices are never tokens.
    pub token: Option<Token>,
    pub name: String,
    pub module_index: usize,
    pub segment: u16,
    /// Section-relative native address or the managed procedure's IL base.
    pub offset: u32,
    pub length: u32,
    pub rva: Option<u64>,
    pub lines: Vec<SourceLine>,
    pub scopes: Vec<NativeScope>,
}

pub(super) struct ParsedSymbols {
    pub functions: Vec<FunctionDebugInfo>,
    pub documents: Vec<SourceDocument>,
    pub publics: Vec<(String, u64)>,
}

struct Budget {
    left: usize,
}

impl Budget {
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.left = self.left.checked_sub(bytes).ok_or_else(|| {
            Error::bad_image("native pdb: aggregate decoding/allocation limit exceeded")
        })?;
        Ok(())
    }
}

struct Addresses {
    sections: Vec<u32>,
    omap: Vec<(u32, u32)>,
}

impl Addresses {
    fn read(image: &MsfImage<'_>, dbg: &DbiDbgHdr) -> Result<Self> {
        let stream = |index: u16| {
            if index == 0 || index == u16::MAX {
                None
            } else {
                image.stream(index as usize)
            }
        };
        let omap_data = stream(dbg.sn_omap_from_src);
        let section_data = if omap_data.is_some() {
            stream(dbg.sn_section_hdr_orig).or_else(|| stream(dbg.sn_section_hdr))
        } else {
            stream(dbg.sn_section_hdr)
        };
        let mut sections = Vec::new();
        if let Some(data) = section_data {
            if data.len() % 40 != 0 {
                return Err(Error::bad_image("native pdb: truncated section-header stream"));
            }
            for section in data.chunks_exact(40) {
                sections.push(u32::from_le_bytes(section[12..16].try_into().unwrap()));
            }
        }
        let mut omap = Vec::new();
        if let Some(data) = omap_data {
            if data.len() % 8 != 0 {
                return Err(Error::bad_image("native pdb: truncated OMAP stream"));
            }
            for entry in data.chunks_exact(8) {
                let from = u32::from_le_bytes(entry[..4].try_into().unwrap());
                let to = u32::from_le_bytes(entry[4..].try_into().unwrap());
                if omap.last().is_some_and(|&(previous, _)| previous >= from) {
                    return Err(Error::bad_image("native pdb: unsorted OMAP stream"));
                }
                omap.push((from, to));
            }
        }
        Ok(Self { sections, omap })
    }

    fn rva(&self, segment: u16, offset: u32) -> Option<u64> {
        let index = segment.checked_sub(1)? as usize;
        let rva = self.sections.get(index)?.checked_add(offset)?;
        if self.omap.is_empty() {
            return Some(rva as u64);
        }
        let i = self.omap.partition_point(|&(from, _)| from <= rva).checked_sub(1)?;
        let (from, to) = self.omap[i];
        if to == 0 {
            None
        } else {
            to.checked_add(rva - from).map(u64::from)
        }
    }
}

pub(super) fn read(
    image: &MsfImage<'_>,
    modules: &[DbiModuleInfo],
    dbg: &DbiDbgHdr,
    header: &DbiHeader,
    names: &HashMap<u32, String>,
) -> Result<ParsedSymbols> {
    let addresses = Addresses::read(image, dbg)?;
    let mut budget = Budget { left: image.image_len().saturating_mul(32).max(4096) };
    let mut result =
        ParsedSymbols { functions: Vec::new(), documents: Vec::new(), publics: Vec::new() };
    let mut seen_documents = HashSet::new();
    for (module_index, info) in modules.iter().enumerate() {
        if info.stream as u16 == u16::MAX || info.stream == 0 {
            continue;
        }
        let data = image.stream(info.stream as u16 as usize).ok_or_else(|| {
            Error::bad_image(format!(
                "native pdb: missing module stream for '{}'",
                info.module_name
            ))
        })?;
        let symbols = positive_size(info.cb_syms, "module symbols")?;
        let old_lines = positive_size(info.cb_old_lines, "module old lines")?;
        let lines = positive_size(info.cb_lines, "module C13 lines")?;
        let begin = symbols
            .checked_add(old_lines)
            .ok_or_else(|| Error::bad_image("native pdb: module region overflow"))?;
        let end = begin
            .checked_add(lines)
            .ok_or_else(|| Error::bad_image("native pdb: module region overflow"))?;
        if end > data.len() || (symbols > 0 && symbols < 4) {
            return Err(Error::bad_image("native pdb: module regions exceed stream"));
        }
        budget.charge(end)?;
        if info.module_name == "TokenSourceLineInfo" {
            continue;
        }
        let first_function = result.functions.len();
        if symbols > 0 {
            read_symbols(
                &data[..symbols],
                module_index,
                &addresses,
                &mut result.functions,
                &mut budget,
            )?;
        }
        read_c13(
            &data[begin..end],
            names,
            &addresses,
            &mut result.functions[first_function..],
            &mut result.documents,
            &mut seen_documents,
            &mut budget,
        )?;
    }
    apply_tokens(&mut result.functions, image, dbg)?;
    // The DBI symbol-record stream holds actual PUB32 records even when GSI
    // and PSI streams contain only hashes. No GSI hash traversal is necessary
    // when enumerating all publics.
    if header.symrec_stream as u16 != u16::MAX && header.symrec_stream != 0 {
        if let Some(bytes) = image.stream(header.symrec_stream as u16 as usize) {
            budget.charge(bytes.len())?;
            result.publics = read_publics(bytes, &addresses, &mut budget)?;
        }
    }
    if result.publics.is_empty() {
        for index in [header.pssym_stream, header.gssym_stream] {
            if index as u16 == u16::MAX || index == 0 {
                continue;
            }
            if let Some(data) = image.stream(index as u16 as usize) {
                budget.charge(data.len())?;
                // Legacy inline streams only; modern hash headers are skipped.
                if data.starts_with(&[255; 4]) {
                    continue;
                }
                for start in [0, 28] {
                    if let Some(bytes) = data.get(start..) {
                        if let Ok(publics) = read_publics(bytes, &addresses, &mut budget) {
                            if !publics.is_empty() {
                                result.publics = publics;
                                break;
                            }
                        }
                    }
                }
                if !result.publics.is_empty() {
                    break;
                }
            }
        }
    }
    result
        .functions
        .sort_by_key(|f| (f.segment, f.offset, f.token.map_or(0, |t| t.0), f.module_index));
    Ok(result)
}

fn symbol_name(bits: &mut BitReader<'_>, kind: u16, budget: &mut Budget) -> Result<String> {
    if kind < 0x1100 {
        let len = bits.read_u8()? as usize;
        budget.charge(len.saturating_mul(4).saturating_add(32))?;
        Ok(String::from_utf8_lossy(bits.take(len)?).into_owned())
    } else {
        let rest = &bits.data[bits.pos..];
        let len = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| Error::bad_image("native pdb: unterminated symbol name"))?;
        budget.charge(len.saturating_mul(4).saturating_add(32))?;
        bits.read_cstring()
    }
}

fn is_proc(kind: u16) -> bool {
    matches!(
        kind,
        sym::S_LPROC32_ST
            | sym::S_GPROC32_ST
            | 0x101a
            | 0x101b
            | sym::S_LPROC32
            | sym::S_GPROC32
            | sym::S_GMANPROC
            | sym::S_LMANPROC
            | 0x1146
            | 0x1147
    )
}

fn is_managed(kind: u16) -> bool {
    sym::is_manproc(kind)
}

/// `None` frames keep inline/thunk scope ends from closing lexical scopes.
fn read_symbols(
    data: &[u8],
    module_index: usize,
    addresses: &Addresses,
    functions: &mut Vec<FunctionDebugInfo>,
    budget: &mut Budget,
) -> Result<()> {
    let mut bits = BitReader::new(data);
    if bits.read_u32()? != 4 {
        return Err(Error::bad_image("native pdb: invalid module symbol signature"));
    }
    let mut frames: Vec<Option<(usize, usize)>> = Vec::new();
    while bits.remaining() > 0 {
        let size = bits.read_u16()? as usize;
        if size < 2 {
            return Err(Error::bad_image("native pdb: undersized symbol record"));
        }
        let mut record = BitReader::new(bits.take(size)?);
        let kind = record.read_u16()?;
        budget.charge(32)?;
        if matches!(kind, sym::S_END | 0x114e | 0x114f) {
            frames.pop();
            continue;
        }
        if is_proc(kind) {
            if !frames.is_empty() {
                return Err(Error::bad_image(
                    "native pdb: procedure starts before preceding scope ends",
                ));
            }
            record.take(12)?; // parent/end/next are hints, never followed.
            let length = record.read_u32()?;
            record.take(8)?;
            let type_or_token = record.read_u32()?;
            let offset = record.read_u32()?;
            let segment = record.read_u16()?;
            record.read_u8()?;
            let managed = is_managed(kind);
            if managed {
                record.read_u16()?;
            }
            let name = symbol_name(&mut record, kind, budget)?;
            let token = if managed {
                if type_or_token >> 24 != 6 || type_or_token & 0x00ff_ffff == 0 {
                    return Err(Error::bad_image("native pdb: invalid managed method token"));
                }
                Some(Token(type_or_token))
            } else {
                None
            };
            budget.charge(256)?;
            let index = functions.len();
            functions.push(FunctionDebugInfo {
                token,
                name,
                module_index,
                segment,
                offset,
                length,
                rva: if managed { None } else { addresses.rva(segment, offset) },
                lines: Vec::new(),
                scopes: vec![NativeScope {
                    parent: None,
                    offset: 0,
                    length,
                    locals: Vec::new(),
                    constants: Vec::new(),
                    imports: Vec::new(),
                }],
            });
            frames.push(Some((index, 0)));
            continue;
        }
        if matches!(kind, sym::S_BLOCK32_ST | sym::S_BLOCK32) {
            record.take(8)?;
            let length = record.read_u32()?;
            let offset = record.read_u32()?;
            let segment = record.read_u16()?;
            let _name = symbol_name(&mut record, kind, budget)?;
            if let Some(&(function_index, parent)) = frames.last().and_then(|f| f.as_ref()) {
                let function = &mut functions[function_index];
                if segment != function.segment || offset < function.offset {
                    return Err(Error::bad_image(
                        "native pdb: lexical block outside procedure segment/range",
                    ));
                }
                let scope_offset = offset - function.offset;
                if scope_offset as u64 + length as u64 > function.length as u64 {
                    return Err(Error::bad_image("native pdb: lexical block exceeds procedure"));
                }
                let parent_scope = &function.scopes[parent];
                if scope_offset < parent_scope.offset
                    || scope_offset as u64 + length as u64
                        > parent_scope.offset as u64 + parent_scope.length as u64
                {
                    return Err(Error::bad_image("native pdb: lexical block exceeds parent scope"));
                }
                budget.charge(128)?;
                let scope = function.scopes.len();
                function.scopes.push(NativeScope {
                    parent: Some(parent),
                    offset: scope_offset,
                    length,
                    locals: Vec::new(),
                    constants: Vec::new(),
                    imports: Vec::new(),
                });
                frames.push(Some((function_index, scope)));
            } else {
                frames.push(None);
            }
            continue;
        }
        if matches!(kind, 0x0206 | 0x1102 | 0x0208 | 0x1104 | 0x1132 | 0x114d | 0x115d) {
            frames.push(None);
            continue;
        }
        let Some(&(function_index, scope_index)) = frames.last().and_then(|f| f.as_ref()) else {
            continue;
        };
        let scope = &mut functions[function_index].scopes[scope_index];
        if matches!(kind, 0x1029 | 0x1124) {
            scope.imports.push(symbol_name(&mut record, kind, budget)?);
        } else if matches!(kind, 0x1002 | 0x1107 | 0x112d) {
            let type_index = record.read_u32()?;
            if let Some(value) = read_constant(&mut record, budget)? {
                let name = symbol_name(&mut record, kind, budget)?;
                budget.charge(96)?;
                scope.constants.push(NativeConstant { name, type_index, value });
            }
        } else if let Some(local) = read_local(&mut record, kind, budget)? {
            budget.charge(64)?;
            scope.locals.push(local);
        }
    }
    if !frames.is_empty() {
        return Err(Error::bad_image("native pdb: unterminated procedure/scope"));
    }
    Ok(())
}

fn read_local(
    bits: &mut BitReader<'_>,
    kind: u16,
    budget: &mut Budget,
) -> Result<Option<NativeLocal>> {
    let mut index = None;
    let mut flags = 0;
    let type_index = match kind {
        0x1017 | 0x1018 | 0x111a | 0x111b | 0x1024 | 0x1120 => {
            index = Some(bits.read_u32()?);
            let typ = bits.read_u32()?;
            if matches!(kind, 0x1024 | 0x1120) {
                bits.take(6)?;
                flags = bits.read_u16()?;
            }
            typ
        }
        0x1006 | 0x110b => {
            bits.read_u32()?;
            bits.read_u32()?
        }
        0x100d | 0x1111 => {
            bits.read_u32()?;
            let typ = bits.read_u32()?;
            bits.read_u16()?;
            typ
        }
        0x1001 | 0x1106 => {
            let typ = bits.read_u32()?;
            bits.read_u16()?;
            typ
        }
        0x113e => {
            let typ = bits.read_u32()?;
            flags = bits.read_u16()?;
            typ
        }
        _ => return Ok(None),
    };
    let name = symbol_name(bits, kind, budget)?;
    Ok(Some(NativeLocal { name, index, type_index, flags }))
}

fn read_constant(bits: &mut BitReader<'_>, budget: &mut Budget) -> Result<Option<ConstantValue>> {
    use ConstantValue::*;
    let leaf = bits.read_u16()?;
    let value = match leaf {
        0..=0x7fff => Unsigned(leaf as u128),
        0x8000 => Signed(bits.read_u8()? as i8 as i128),
        0x8001 => Signed(bits.read_i16()? as i128),
        0x8002 => Unsigned(bits.read_u16()? as u128),
        0x8003 => Signed(bits.read_i32()? as i128),
        0x8004 => Unsigned(bits.read_u32()? as u128),
        0x8005 => Float(f32::from_le_bytes(bits.take(4)?.try_into().unwrap()) as f64),
        0x8006 => Float(f64::from_le_bytes(bits.take(8)?.try_into().unwrap())),
        0x8009 => Signed(i64::from_le_bytes(bits.take(8)?.try_into().unwrap()) as i128),
        0x800a => Unsigned(u64::from_le_bytes(bits.take(8)?.try_into().unwrap()) as u128),
        0x8017 => Signed(i128::from_le_bytes(bits.take(16)?.try_into().unwrap())),
        0x8018 => Unsigned(u128::from_le_bytes(bits.take(16)?.try_into().unwrap())),
        0x8010 => {
            let len = bits.read_u16()? as usize;
            budget.charge(len.saturating_mul(4))?;
            String(std::string::String::from_utf8_lossy(bits.take(len)?).into_owned())
        }
        0x801b => String(symbol_name(bits, 0x1100, budget)?),
        0x8007 | 0x8008 | 0x800b | 0x800c | 0x800d | 0x800e | 0x800f | 0x8019 | 0x801a | 0x801c => {
            let len = match leaf {
                0x8007 => 10,
                0x800b => 6,
                0x800c | 0x801a => 8,
                0x800e => 20,
                0x800f => 32,
                0x801c => 2,
                _ => 16,
            };
            Raw { leaf, bytes: bits.take(len)?.to_vec() }
        }
        _ => return Ok(None), // Unknown numeric leaf cannot be split from its name.
    };
    Ok(Some(value))
}

fn c13_subsections(data: &[u8]) -> Result<Vec<(u32, &[u8])>> {
    let mut bits = BitReader::new(data);
    let mut result = Vec::new();
    while bits.remaining() > 0 {
        let kind = bits.read_u32()?;
        let size = bits.read_u32()? as usize;
        result.push((kind, bits.take(size)?));
        let padding = (4 - bits.pos % 4) % 4;
        if padding > 0 && bits.remaining() > 0 {
            bits.take(padding)?;
        }
    }
    Ok(result)
}

fn read_c13(
    data: &[u8],
    names: &HashMap<u32, String>,
    addresses: &Addresses,
    functions: &mut [FunctionDebugInfo],
    documents: &mut Vec<SourceDocument>,
    seen: &mut HashSet<(String, u8, Vec<u8>)>,
    budget: &mut Budget,
) -> Result<()> {
    let subsections = c13_subsections(data)?;
    let local_strings = subsections.iter().find(|&&(kind, _)| kind == 0xf3).map(|&(_, data)| data);
    let mut checks = HashMap::new();
    for &(kind, body) in &subsections {
        if kind != super::debug_s_subsection::FILECHKSMS as u32 {
            continue;
        }
        let mut bits = BitReader::new(body);
        while bits.remaining() > 0 {
            let index = bits.position() as u32;
            let name_index = bits.read_u32()?;
            let len = bits.read_u8()? as usize;
            let checksum_kind = bits.read_u8()?;
            let checksum = bits.take(len)?.to_vec();
            // A module's C13 STRINGTABLE owns its checksum name offsets.
            // The global /names heap is a fallback only when no local table
            // exists; identical integers do not imply identical strings.
            let name = match local_strings {
                Some(strings) => heap_string(strings, name_index as usize)?,
                None => names.get(&name_index).cloned().ok_or_else(|| {
                    Error::bad_image("native pdb: checksum name missing from string table")
                })?,
            };
            budget.charge(name.len().saturating_mul(4).saturating_add(128))?;
            checks.insert(index, name.clone());
            if seen.insert((name.clone(), checksum_kind, checksum.clone())) {
                documents.push(SourceDocument { name, checksum_kind, checksum });
            }
            let padding = (4 - bits.pos % 4) % 4;
            bits.take(padding)?;
        }
    }
    let mut by_address: BTreeMap<(u16, u32), Vec<usize>> = BTreeMap::new();
    for (i, function) in functions.iter().enumerate() {
        by_address.entry((function.segment, function.offset)).or_default().push(i);
    }
    for &(kind, body) in &subsections {
        if kind != 0xf2 {
            continue;
        }
        let mut bits = BitReader::new(body);
        let offset = bits.read_u32()?;
        let segment = bits.read_u16()?;
        let flags = bits.read_u16()?;
        let length = bits.read_u32()?;
        let has_columns = flags & 1 != 0;
        let targets = if let Some(indices) = by_address.get(&(segment, offset)) {
            budget.charge(indices.len().saturating_mul(16))?;
            indices.clone()
        } else {
            if let Some((_, indices)) =
                by_address.range((segment, 0)..=(segment, offset)).next_back()
            {
                budget.charge(indices.len().saturating_mul(16))?;
                indices
                    .iter()
                    .copied()
                    .filter(|&i| {
                        offset as u64 + length as u64
                            <= functions[i].offset as u64 + functions[i].length as u64
                    })
                    .collect()
            } else {
                Vec::new()
            }
        };
        while bits.remaining() > 0 {
            let file_index = bits.read_u32()?;
            let count = bits.read_u32()? as usize;
            let block_size = bits.read_u32()? as usize;
            let stride = if has_columns { 12 } else { 8 };
            let payload = count
                .checked_mul(stride)
                .ok_or_else(|| Error::bad_image("native pdb: line count overflow"))?;
            // Real CV block size includes its 12-byte header; old Cci writers
            // also emitted payload-only sizes. Both are bounded by count.
            if block_size != payload && block_size != payload.saturating_add(12) {
                return Err(Error::bad_image("native pdb: inconsistent line-block size"));
            }
            let line_data = bits.take(payload)?;
            let file = checks.get(&file_index).ok_or_else(|| {
                Error::bad_image("native pdb: line file index missing from checksum subsection")
            })?;
            for i in 0..count {
                let mut line = BitReader::new(&line_data[i * 8..i * 8 + 8]);
                let delta = line.read_u32()?;
                let line_flags = line.read_u32()?;
                if delta >= length && length != 0 {
                    return Err(Error::bad_image(
                        "native pdb: line offset exceeds subsection code range",
                    ));
                }
                let start_line = line_flags & 0x00ff_ffff;
                let end_line = start_line + ((line_flags >> 24) & 0x7f);
                let (start_column, end_column) = if has_columns {
                    let mut columns =
                        BitReader::new(&line_data[count * 8 + i * 4..count * 8 + i * 4 + 4]);
                    (columns.read_u16()?, columns.read_u16()?)
                } else {
                    (0, 0)
                };
                let absolute = offset
                    .checked_add(delta)
                    .ok_or_else(|| Error::bad_image("native pdb: line address overflow"))?;
                for &target in &targets {
                    budget.charge(96usize.saturating_add(file.len().saturating_mul(4)))?;
                    let function = &mut functions[target];
                    let relative = absolute
                        .checked_sub(function.offset)
                        .ok_or_else(|| Error::bad_image("native pdb: line precedes procedure"))?;
                    if relative >= function.length && function.length != 0 {
                        return Err(Error::bad_image(
                            "native pdb: line exceeds procedure code range",
                        ));
                    }
                    function.lines.push(SourceLine {
                        rva: if function.token.is_some() {
                            None
                        } else {
                            addresses.rva(segment, absolute)
                        },
                        offset: relative,
                        start_line,
                        end_line,
                        start_column,
                        end_column,
                        is_statement: line_flags & 0x8000_0000 != 0,
                        file: file.clone(),
                    });
                }
            }
        }
    }
    for function in functions {
        function.lines.sort_by_key(|line| line.offset);
    }
    Ok(())
}

fn apply_tokens(
    functions: &mut [FunctionDebugInfo],
    image: &MsfImage<'_>,
    dbg: &DbiDbgHdr,
) -> Result<()> {
    if dbg.sn_token_rid_map == 0 || dbg.sn_token_rid_map == u16::MAX {
        return Ok(());
    }
    let data = image
        .stream(dbg.sn_token_rid_map as usize)
        .ok_or_else(|| Error::bad_image("native pdb: missing token RID map"))?;
    if data.len() % 4 != 0 {
        return Err(Error::bad_image("native pdb: truncated token RID map"));
    }
    for function in functions {
        let Some(token) = function.token else {
            continue;
        };
        let offset = (token.0 & 0x00ff_ffff) as usize * 4;
        let bytes = data
            .get(offset..offset + 4)
            .ok_or_else(|| Error::bad_image("native pdb: token outside RID map"))?;
        let rid = u32::from_le_bytes(bytes.try_into().unwrap());
        if rid == 0 || rid > 0x00ff_ffff {
            return Err(Error::bad_image("native pdb: invalid remapped RID"));
        }
        function.token = Some(Token(0x0600_0000 | rid));
    }
    Ok(())
}

fn read_publics(
    data: &[u8],
    addresses: &Addresses,
    budget: &mut Budget,
) -> Result<Vec<(String, u64)>> {
    let mut bits = BitReader::new(data);
    let mut result = Vec::new();
    while bits.remaining() > 0 {
        let size = bits.read_u16()? as usize;
        if size < 2 {
            return Err(Error::bad_image("native pdb: undersized public record"));
        }
        let mut record = BitReader::new(bits.take(size)?);
        let kind = record.read_u16()?;
        if sym::is_pub32(kind) {
            record.read_u32()?;
            let offset = record.read_u32()?;
            let segment = record.read_u16()?;
            let name = symbol_name(&mut record, kind, budget)?;
            result.push((name, addresses.rva(segment, offset).unwrap_or(offset as u64)));
        }
    }
    Ok(result)
}
