//! Reader for the Mono MDB debug-information format.
//!
//! Port of `Mono.CompilerServices.SymbolWriter.MonoSymbolFile` and the on-disk
//! structures from `MonoSymbolTable.cs`. The file layout is:
//!
//! ```text
//! magic u64 | major i32 | minor i32 | guid [u8;16]   (32-byte header)
//! OffsetTable (20 x i32, back-patched by the writer)
//! data section   (source-file payloads, compile-unit payloads, method payloads)
//! method table   (12 bytes per method: token, data offset, line-number-table offset)
//! source table   (8 bytes per source: index, payload offset)
//! compile-unit table (8 bytes per unit: index, payload offset)
//! anonymous-scope table
//! ```
//!
//! All integers are little-endian. Variable-length values use the .NET
//! `Write7BitEncodedInt` encoding (`leb128`). Strings are length-prefixed UTF-8.
//!
//! Table payloads are parsed eagerly in [`MdbReader::open`] so malformed or
//! truncated files are reported as [`Error::BadImage`] up front, while the more
//! expensive line-number tables decode lazily in [`MdbReader::method_lines`].

use cecli_core::io::ByteReader;
use cecli_core::{Error, Result, Token};

/// 64-bit magic value (`OffsetTable.Magic`).
pub const MAGIC: u64 = 0x45e8_2623_fd7f_a614;
/// Major file version (`OffsetTable.MajorVersion`).
pub const MAJOR_VERSION: i32 = 50;
/// Minor file version (`OffsetTable.MinorVersion`).
pub const MINOR_VERSION: i32 = 0;

/// Size in bytes of the fixed header (magic + versions + guid).
const HEADER_SIZE: usize = 8 + 4 + 4 + 16;
/// Size in bytes of the serialized offset table (20 x i32).
const OFFSET_TABLE_SIZE: usize = 20 * 4;

// LineNumberTable standard / extended opcode constants (MonoSymbolTable.cs).
const DW_LNS_COPY: u8 = 1;
const DW_LNS_ADVANCE_PC: u8 = 2;
const DW_LNS_ADVANCE_LINE: u8 = 3;
const DW_LNS_SET_FILE: u8 = 4;
const DW_LNS_CONST_ADD_PC: u8 = 8;
const DW_LNE_END_SEQUENCE: u8 = 1;
const DW_LNE_MONO_NEGATE_IS_HIDDEN: u8 = 0x40;
const DW_LNE_MONO_EXTENSIONS_START: u8 = 0x40;
const DW_LNE_MONO_EXTENSIONS_END: u8 = 0x7f;

/// `MethodEntry.Flags` bit values.
const FLAGS_COLUMNS_INFO_INCLUDED: u32 = 1 << 1;
const FLAGS_END_INFO_INCLUDED: u32 = 1 << 2;

/// Default line-number-table encoding parameters (`LineNumberTable` defaults).
const DEFAULT_LINE_BASE: i32 = -1;
const DEFAULT_LINE_RANGE: i32 = 8;
const DEFAULT_OPCODE_BASE: i32 = 9;

/// The fixed-size directory of file sections (`OffsetTable`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffsetTable {
    pub total_file_size: i32,
    pub data_section_offset: i32,
    pub data_section_size: i32,
    pub compile_unit_count: i32,
    pub compile_unit_table_offset: i32,
    pub compile_unit_table_size: i32,
    pub source_count: i32,
    pub source_table_offset: i32,
    pub source_table_size: i32,
    pub method_count: i32,
    pub method_table_offset: i32,
    pub method_table_size: i32,
    pub type_count: i32,
    pub anonymous_scope_count: i32,
    pub anonymous_scope_table_offset: i32,
    pub anonymous_scope_table_size: i32,
    pub line_number_table_line_base: i32,
    pub line_number_table_line_range: i32,
    pub line_number_table_opcode_base: i32,
    /// Bitwise-or of `OffsetTable.Flags` (`IsAspxSource = 1`,
    /// `WindowsFileNames = 2`).
    pub file_flags: i32,
}

impl Default for OffsetTable {
    fn default() -> Self {
        OffsetTable {
            total_file_size: 0,
            data_section_offset: 0,
            data_section_size: 0,
            compile_unit_count: 0,
            compile_unit_table_offset: 0,
            compile_unit_table_size: 0,
            source_count: 0,
            source_table_offset: 0,
            source_table_size: 0,
            method_count: 0,
            method_table_offset: 0,
            method_table_size: 0,
            type_count: 0,
            anonymous_scope_count: 0,
            anonymous_scope_table_offset: 0,
            anonymous_scope_table_size: 0,
            line_number_table_line_base: DEFAULT_LINE_BASE,
            line_number_table_line_range: DEFAULT_LINE_RANGE,
            line_number_table_opcode_base: DEFAULT_OPCODE_BASE,
            file_flags: 0,
        }
    }
}

impl OffsetTable {
    fn read(r: &mut ByteReader) -> Result<Self> {
        Ok(OffsetTable {
            total_file_size: r.i32()?,
            data_section_offset: r.i32()?,
            data_section_size: r.i32()?,
            compile_unit_count: r.i32()?,
            compile_unit_table_offset: r.i32()?,
            compile_unit_table_size: r.i32()?,
            source_count: r.i32()?,
            source_table_offset: r.i32()?,
            source_table_size: r.i32()?,
            method_count: r.i32()?,
            method_table_offset: r.i32()?,
            method_table_size: r.i32()?,
            type_count: r.i32()?,
            anonymous_scope_count: r.i32()?,
            anonymous_scope_table_offset: r.i32()?,
            anonymous_scope_table_size: r.i32()?,
            line_number_table_line_base: r.i32()?,
            line_number_table_line_range: r.i32()?,
            line_number_table_opcode_base: r.i32()?,
            file_flags: r.i32()?,
        })
    }

    /// Serializes the table in field order; the writer back-patches it later.
    pub(crate) fn write(&self, w: &mut cecli_core::io::ByteWriter) {
        w.i32(self.total_file_size);
        w.i32(self.data_section_offset);
        w.i32(self.data_section_size);
        w.i32(self.compile_unit_count);
        w.i32(self.compile_unit_table_offset);
        w.i32(self.compile_unit_table_size);
        w.i32(self.source_count);
        w.i32(self.source_table_offset);
        w.i32(self.source_table_size);
        w.i32(self.method_count);
        w.i32(self.method_table_offset);
        w.i32(self.method_table_size);
        w.i32(self.type_count);
        w.i32(self.anonymous_scope_count);
        w.i32(self.anonymous_scope_table_offset);
        w.i32(self.anonymous_scope_table_size);
        w.i32(self.line_number_table_line_base);
        w.i32(self.line_number_table_line_range);
        w.i32(self.line_number_table_opcode_base);
        w.i32(self.file_flags);
    }
}

/// A registered source document (`SourceFileEntry`).
///
/// The 16-byte per-file GUID stored next to the checksum in the on-disk
/// payload is not surfaced; `hash` carries the MD5 checksum bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFileEntry {
    /// 1-based source id as stored in the source table.
    pub id: u32,
    /// File path (or URL) of the document.
    pub path: String,
    /// Checksum bytes (MD5 when produced by mcs), 16 bytes.
    pub hash: [u8; 16],
}

/// A compilation unit (`CompileUnitEntry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileUnitEntry {
    /// Source-file ids covered by this unit: `file_ids[0]` is the primary
    /// source, remaining ids are the `#include`-style additional files.
    pub file_ids: Vec<u32>,
}

/// A row of the method table (`MethodEntry` header fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodEntry {
    /// 1-based position within the (token-sorted) method table.
    pub row: u32,
    /// MethodDef token this entry annotates.
    pub token: Token,
    /// 1-based compile-unit index.
    pub compile_unit: u32,
    /// Namespace id recorded by the compiler (0 when unused).
    pub namespace_id: u32,
}

/// Decoded line-number table of one method.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MethodLines {
    /// IL offsets, one per sequence point, in table order.
    pub il_offsets: Vec<i32>,
    /// Source line numbers, parallel to `il_offsets`.
    ///
    /// The source file each point belongs to travels inside the encoded table
    /// via the `DW_LNS_set_file` opcode (the packed source-file bits of
    /// `MonoSymbolTable.LineNumberTable`) and is not surfaced here.
    pub line_numbers: Vec<i32>,
}

/// A local-variable record of one method (`LocalVariableEntry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVariableEntry {
    /// IL local slot index.
    pub index: i32,
    /// Local name.
    pub name: String,
    /// Enclosing code-block index (0 = method body root).
    pub block_index: i32,
}

/// Internal, fully-parsed method row.
#[derive(Debug)]
struct MethodRow {
    entry: MethodEntry,
    line_number_table_offset: usize,
    local_variable_table_offset: usize,
    flags: u32,
}

/// Lazy reader over an in-memory Mono MDB symbol file.
#[derive(Debug)]
pub struct MdbReader<'a> {
    data: &'a [u8],
    guid: [u8; 16],
    major_version: i32,
    minor_version: i32,
    ot: OffsetTable,
    sources: Vec<SourceFileEntry>,
    units: Vec<CompileUnitEntry>,
    methods: Vec<MethodRow>,
}

/// Reads one .NET 7-bit-encoded int (`Read7BitEncodedInt`), max 5 bytes.
fn read_leb128(r: &mut ByteReader) -> Result<i32> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    loop {
        let b = r.u8()?;
        // Bits shifted past 31 wrap exactly like the .NET implementation.
        result |= ((b & 0x7f) as u32).wrapping_shl(shift);
        if b & 0x80 == 0 {
            return Ok(result as i32);
        }
        shift += 7;
        if shift >= 35 {
            return Err(Error::bad_image("mdb: unterminated 7-bit encoded int"));
        }
    }
}

/// Byte size of a fixed-size-row table (`count * row_size`), rejecting
/// negative counts and any product that would overflow. Callers compare
/// this against the table extent's length.
fn row_count(count: i32, row_size: usize, what: &str) -> Result<usize> {
    let count = usize::try_from(count)
        .map_err(|_| Error::bad_image(format!("mdb: negative {what} count {count}")))?;
    count.checked_mul(row_size).ok_or_else(|| {
        Error::bad_image(format!("mdb: {what} count {count} overflows the table size"))
    })
}

/// Reads a length-prefixed UTF-8 string (`BinaryReader.ReadString`).
fn read_string<'a>(r: &mut ByteReader<'a>) -> Result<&'a str> {
    let len = read_leb128(r)?;
    if len < 0 {
        return Err(Error::bad_image("mdb: negative string length"));
    }
    let bytes = r.read_bytes(len as usize)?;
    std::str::from_utf8(bytes).map_err(|e| Error::bad_image(format!("mdb: bad string: {e}")))
}

impl<'a> MdbReader<'a> {
    /// Parses an MDB symbol file, validating magic, version, and all table
    /// offsets/payloads eagerly.
    pub fn open(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE + OFFSET_TABLE_SIZE {
            return Err(Error::bad_image(format!(
                "mdb: file too small ({}, need at least {})",
                bytes.len(),
                HEADER_SIZE + OFFSET_TABLE_SIZE
            )));
        }
        let mut r = ByteReader::new(bytes);
        let magic = r.u64()?;
        if magic != MAGIC {
            return Err(Error::bad_image(format!(
                "mdb: bad magic 0x{magic:016x}, expected 0x{MAGIC:016x}"
            )));
        }
        let major_version = r.i32()?;
        let minor_version = r.i32()?;
        if major_version < MAJOR_VERSION {
            return Err(Error::bad_image(format!(
                "mdb: symbol file has version {major_version} but {MAJOR_VERSION}+ is required"
            )));
        }
        let guid: [u8; 16] = r.read_bytes(16)?.try_into().unwrap();
        let ot = OffsetTable::read(&mut r)?;
        if ot.line_number_table_line_range <= 0 || ot.line_number_table_opcode_base <= 0 {
            return Err(Error::bad_image("mdb: invalid line-number-table encoding parameters"));
        }

        let sources = Self::read_source_table(bytes, &ot)?;
        let units = Self::read_compile_unit_table(bytes, &ot)?;
        let methods = Self::read_method_table(bytes, &ot)?;

        Ok(MdbReader {
            data: bytes,
            guid,
            major_version,
            minor_version,
            ot,
            sources,
            units,
            methods,
        })
    }

    fn checked_range(
        base: i32,
        size: i32,
        len: usize,
        what: &str,
    ) -> Result<std::ops::Range<usize>> {
        if base < 0 || size < 0 {
            return Err(Error::bad_image(format!("mdb: negative {what} extent")));
        }
        let start = base as usize;
        let end = start
            .checked_add(size as usize)
            .ok_or_else(|| Error::bad_image(format!("mdb: {what} extent overflows")))?;
        if end > len {
            return Err(Error::bad_image(format!(
                "mdb: {what} [{start},{end}) exceeds file size {len}"
            )));
        }
        Ok(start..end)
    }

    fn read_source_table(data: &'a [u8], ot: &OffsetTable) -> Result<Vec<SourceFileEntry>> {
        let range = Self::checked_range(
            ot.source_table_offset,
            ot.source_table_size,
            data.len(),
            "source table",
        )?;
        // Each row is exactly two i32s (`SourceFileEntry.Size == 8`). Negative
        // or oversized counts must not reach the arithmetic: `i32 as usize`
        // sign-extends, and the row-size multiply would overflow.
        let source_count = row_count(ot.source_count, 8, "source")?;
        if range.len() != source_count {
            return Err(Error::bad_image(format!(
                "mdb: source table size {} does not match count {}",
                range.len(),
                ot.source_count
            )));
        }
        let mut sources = Vec::with_capacity(source_count / 8);
        for row in range.step_by(8) {
            let mut r = ByteReader::at(data, row);
            let id = r.i32()?;
            let data_offset = r.i32()?;
            if data_offset < 0 || data_offset as usize >= data.len() {
                return Err(Error::bad_image(format!(
                    "mdb: source #{id} payload offset {data_offset} out of bounds"
                )));
            }
            let mut pr = ByteReader::at(data, data_offset as usize);
            let path = read_string(&mut pr)?.to_owned();
            let _guid = pr.read_bytes(16)?;
            let hash: [u8; 16] = pr.read_bytes(16)?.try_into().unwrap();
            // Trailing byte: auto-generated flag; ignored here.
            sources.push(SourceFileEntry { id: id as u32, path, hash });
        }
        Ok(sources)
    }

    fn read_compile_unit_table(data: &'a [u8], ot: &OffsetTable) -> Result<Vec<CompileUnitEntry>> {
        let range = Self::checked_range(
            ot.compile_unit_table_offset,
            ot.compile_unit_table_size,
            data.len(),
            "compile-unit table",
        )?;
        let unit_bytes = row_count(ot.compile_unit_count, 8, "compile-unit")?;
        if range.len() != unit_bytes {
            return Err(Error::bad_image(format!(
                "mdb: compile-unit table size {} does not match count {}",
                range.len(),
                ot.compile_unit_count
            )));
        }
        let mut units = Vec::with_capacity(unit_bytes / 8);
        for row in range.step_by(8) {
            let mut r = ByteReader::at(data, row);
            let _index = r.i32()?;
            let data_offset = r.i32()?;
            if data_offset < 0 || data_offset as usize >= data.len() {
                return Err(Error::bad_image(format!(
                    "mdb: compile-unit payload offset {data_offset} out of bounds"
                )));
            }
            let mut pr = ByteReader::at(data, data_offset as usize);
            // Payload: primary source idx, include-file idx list, namespace list.
            let primary = read_leb128(&mut pr)?;
            let include_count = read_leb128(&mut pr)?;
            if primary < 0 || include_count < 0 {
                return Err(Error::bad_image("mdb: malformed compile-unit payload"));
            }
            // Each include id costs at least one LEB128 byte, so the payload
            // length bounds a sane allocation.
            let cap = (include_count as usize).min(pr.remaining());
            let mut file_ids = Vec::with_capacity(cap + 1);
            file_ids.push(primary as u32);
            for _ in 0..include_count {
                let inc = read_leb128(&mut pr)?;
                if inc < 0 {
                    return Err(Error::bad_image("mdb: malformed compile-unit include"));
                }
                file_ids.push(inc as u32);
            }
            let namespace_count = read_leb128(&mut pr)?;
            if namespace_count < 0 {
                return Err(Error::bad_image("mdb: malformed namespace count"));
            }
            // Skip namespaces: name, index, parent, using-clause strings.
            for _ in 0..namespace_count {
                let _name = read_string(&mut pr)?;
                let _index = read_leb128(&mut pr)?;
                let _parent = read_leb128(&mut pr)?;
                let using_count = read_leb128(&mut pr)?;
                if using_count < 0 {
                    return Err(Error::bad_image("mdb: malformed using-clause count"));
                }
                for _ in 0..using_count {
                    let _clause = read_string(&mut pr)?;
                }
            }
            units.push(CompileUnitEntry { file_ids });
        }
        Ok(units)
    }

    fn read_method_table(data: &'a [u8], ot: &OffsetTable) -> Result<Vec<MethodRow>> {
        let range = Self::checked_range(
            ot.method_table_offset,
            ot.method_table_size,
            data.len(),
            "method table",
        )?;
        // Each row is exactly 12 bytes (`MethodEntry.Size`).
        let method_bytes = row_count(ot.method_count, 12, "method")?;
        if range.len() != method_bytes {
            return Err(Error::bad_image(format!(
                "mdb: method table size {} does not match count {}",
                range.len(),
                ot.method_count
            )));
        }
        let mut methods = Vec::with_capacity(method_bytes / 12);
        for (i, row) in range.step_by(12).enumerate() {
            let mut r = ByteReader::at(data, row);
            let token = r.i32()?;
            let data_offset = r.i32()?;
            let lnt_offset = r.i32()?;
            if data_offset < 0 || data_offset as usize >= data.len() {
                return Err(Error::bad_image(format!(
                    "mdb: method data offset {data_offset} out of bounds"
                )));
            }
            if !(0..data.len() as i64).contains(&(lnt_offset as i64)) {
                return Err(Error::bad_image(format!(
                    "mdb: method line-number-table offset {lnt_offset} out of bounds"
                )));
            }
            // Data payload: seven leb128 fields (`MethodEntry..ctor`).
            let mut pr = ByteReader::at(data, data_offset as usize);
            let cu_index = read_leb128(&mut pr)?;
            let local_variable_table_offset = read_leb128(&mut pr)?;
            let namespace_id = read_leb128(&mut pr)?;
            let _code_block_table_offset = read_leb128(&mut pr)?;
            let _scope_variable_table_offset = read_leb128(&mut pr)?;
            let _real_name_offset = read_leb128(&mut pr)?;
            let flags_raw = read_leb128(&mut pr)?;
            for v in [cu_index, local_variable_table_offset, namespace_id, flags_raw] {
                if v < 0 {
                    return Err(Error::bad_image("mdb: malformed method data payload"));
                }
            }
            methods.push(MethodRow {
                entry: MethodEntry {
                    row: (i + 1) as u32,
                    token: Token(token as u32),
                    compile_unit: cu_index as u32,
                    namespace_id: namespace_id as u32,
                },
                line_number_table_offset: lnt_offset as usize,
                local_variable_table_offset: local_variable_table_offset as usize,
                flags: flags_raw as u32,
            });
        }
        Ok(methods)
    }

    /// File format major version.
    pub fn major_version(&self) -> i32 {
        self.major_version
    }

    /// File format minor version.
    pub fn minor_version(&self) -> i32 {
        self.minor_version
    }

    /// Guid of the assembly this symbol file belongs to.
    pub fn guid(&self) -> [u8; 16] {
        self.guid
    }

    /// The raw offset table.
    pub fn offset_table(&self) -> &OffsetTable {
        &self.ot
    }

    /// Every registered source document, in table order.
    pub fn source_files(&self) -> Vec<SourceFileEntry> {
        self.sources.clone()
    }

    /// Every compile unit, in table order.
    pub fn compile_units(&self) -> Vec<CompileUnitEntry> {
        self.units.clone()
    }

    /// Every method entry, in table order (sorted by token).
    pub fn methods(&self) -> Vec<MethodEntry> {
        self.methods.iter().map(|m| m.entry.clone()).collect()
    }

    fn method_row(&self, row: u32) -> Option<&MethodRow> {
        if row == 0 {
            return None;
        }
        self.methods.get((row - 1) as usize)
    }

    /// Decodes the line-number table of method `row` (1-based, as returned by
    /// [`MdbReader::methods`]).
    ///
    /// Returns `Ok(None)` when the row does not exist or the method carries no
    /// line information.
    pub fn method_lines(&self, row: u32) -> Result<Option<MethodLines>> {
        let Some(m) = self.method_row(row) else {
            return Ok(None);
        };
        if m.line_number_table_offset == 0 {
            return Ok(None);
        }
        let entries = self.decode_line_number_table(m.line_number_table_offset, m.flags)?;
        Ok(Some(MethodLines {
            il_offsets: entries.iter().map(|e| e.offset).collect(),
            line_numbers: entries.iter().map(|e| e.row).collect(),
        }))
    }

    /// Reads the local-variable records of method `row` (1-based).
    ///
    /// Returns `Ok(None)` when the row does not exist or the method declares
    /// no local-variable table.
    pub fn locals(&self, row: u32) -> Result<Option<Vec<LocalVariableEntry>>> {
        let Some(m) = self.method_row(row) else {
            return Ok(None);
        };
        if m.local_variable_table_offset == 0 {
            return Ok(None);
        }
        let mut r = ByteReader::at(self.data, m.local_variable_table_offset);
        let count = read_leb128(&mut r)?;
        if count < 0 {
            return Err(Error::bad_image("mdb: malformed local-variable count"));
        }
        // Each entry costs at least two LEB128 bytes plus a name; cap the
        // allocation by the bytes actually remaining.
        let mut locals = Vec::with_capacity((count as usize).min(r.remaining() / 2));
        for _ in 0..count {
            let index = read_leb128(&mut r)?;
            let name = read_string(&mut r)?.to_owned();
            let block_index = read_leb128(&mut r)?;
            locals.push(LocalVariableEntry { index, name, block_index });
        }
        Ok(Some(locals))
    }

    /// Decodes a `LineNumberTable` stream (port of `LineNumberTable.DoRead`).
    fn decode_line_number_table(&self, offset: usize, flags: u32) -> Result<Vec<LntEntry>> {
        let line_base = self.ot.line_number_table_line_base;
        let line_range = self.ot.line_number_table_line_range;
        let opcode_base = self.ot.line_number_table_opcode_base;
        if opcode_base > 255 {
            return Err(Error::unsupported("mdb: line-number-table opcode base exceeds 255"));
        }
        let max_address_increment = (255 - opcode_base) / line_range;

        let mut r = ByteReader::at(self.data, offset);
        let mut entries: Vec<LntEntry> = Vec::new();

        let mut is_hidden = false;
        let mut modified = false;
        let mut stm_line: i32 = 1;
        let mut stm_offset: i32 = 0;
        let mut stm_file: u32 = 1;

        loop {
            let opcode = r.u8()?;

            if opcode == 0 {
                let size = r.u8()? as usize;
                let end_pos = r.position() + size;
                let ext = r.u8()?;
                if ext == DW_LNE_END_SEQUENCE {
                    if modified {
                        entries.push(LntEntry::new(stm_file, stm_line, stm_offset, is_hidden));
                    }
                    break;
                } else if ext == DW_LNE_MONO_NEGATE_IS_HIDDEN {
                    is_hidden = !is_hidden;
                    modified = true;
                } else if (DW_LNE_MONO_EXTENSIONS_START..=DW_LNE_MONO_EXTENSIONS_END).contains(&ext)
                {
                    // Reserved for future extensions; skip the payload.
                } else {
                    return Err(Error::bad_image(format!(
                        "mdb: unknown extended opcode {ext:#x} in line-number table"
                    )));
                }
                r.seek(end_pos)?;
                continue;
            } else if (opcode as i32) < opcode_base {
                match opcode {
                    DW_LNS_COPY => {
                        entries.push(LntEntry::new(stm_file, stm_line, stm_offset, is_hidden));
                        modified = false;
                    }
                    DW_LNS_ADVANCE_PC => {
                        stm_offset = stm_offset.wrapping_add(read_leb128(&mut r)?);
                        modified = true;
                    }
                    DW_LNS_ADVANCE_LINE => {
                        stm_line = stm_line.wrapping_add(read_leb128(&mut r)?);
                        modified = true;
                    }
                    DW_LNS_SET_FILE => {
                        let f = read_leb128(&mut r)?;
                        if f < 0 {
                            return Err(Error::bad_image("mdb: negative source-file index"));
                        }
                        stm_file = f as u32;
                        modified = true;
                    }
                    DW_LNS_CONST_ADD_PC => {
                        stm_offset = stm_offset.wrapping_add(max_address_increment);
                        modified = true;
                    }
                    _ => {
                        return Err(Error::bad_image(format!(
                            "mdb: unknown standard opcode {opcode:#x} in line-number table"
                        )));
                    }
                }
            } else {
                let special = opcode as i32 - opcode_base;
                stm_offset = stm_offset.wrapping_add(special / line_range);
                stm_line = stm_line.wrapping_add(line_base + special % line_range);
                entries.push(LntEntry::new(stm_file, stm_line, stm_offset, is_hidden));
                modified = false;
            }
        }

        // Optional column / end-position sections appended after the main
        // program (gated by MethodEntry flags).
        if flags & FLAGS_COLUMNS_INFO_INCLUDED != 0 {
            for e in &mut entries {
                if e.row >= 0 {
                    e.column = Some(read_leb128(&mut r)?);
                }
            }
        }
        if flags & FLAGS_END_INFO_INCLUDED != 0 {
            for e in &mut entries {
                let delta = read_leb128(&mut r)?;
                if delta == 0xff_ffff {
                    e.end_row = None;
                    e.end_column = None;
                } else {
                    e.end_row = Some(e.row + delta);
                    e.end_column = Some(read_leb128(&mut r)?);
                }
            }
        }

        Ok(entries)
    }
}

/// One decoded sequence point of a line-number table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LntEntry {
    pub file: u32,
    pub row: i32,
    pub offset: i32,
    pub column: Option<i32>,
    pub end_row: Option<i32>,
    pub end_column: Option<i32>,
    #[allow(dead_code)]
    pub is_hidden: bool,
}

impl LntEntry {
    pub(crate) fn new(file: u32, row: i32, offset: i32, is_hidden: bool) -> Self {
        LntEntry { file, row, offset, column: None, end_row: None, end_column: None, is_hidden }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::MdbWriter;

    fn sample_file(guid: [u8; 16]) -> Vec<u8> {
        let mut w = MdbWriter::new(guid);
        let s1 = w.add_source("a.cs");
        let s2 = w.add_source("b.cs");
        let cu = w.add_compile_unit(&[s1, s2]);
        w.add_method_lines(
            Token::new(cecli_core::TableIndex::MethodDef, 1),
            cu,
            &[(0, 10), (4, 11)],
            s1,
        );
        w.mark_sequence_points(
            Token::new(cecli_core::TableIndex::MethodDef, 2),
            cu,
            0,
            &[(0, 20, s1), (4, 30, s2), (8, 21, s1), (12, 31, s2)],
        );
        w.finalize()
    }

    #[test]
    fn rejects_bad_magic() {
        let good = sample_file([7u8; 16]);
        let mut bad = good.clone();
        bad[0] ^= 0xFF;
        assert!(MdbReader::open(&bad).is_err());
    }

    #[test]
    fn rejects_old_version() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC.to_le_bytes());
        buf.extend_from_slice(&49i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend_from_slice(&[0u8; OFFSET_TABLE_SIZE]);
        assert!(MdbReader::open(&buf).is_err());
    }

    #[test]
    fn rejects_truncated_files() {
        let good = sample_file([9u8; 16]);
        for cut in [0usize, 10, 31, 100, 112, good.len() / 2, good.len() - 1] {
            assert!(MdbReader::open(&good[..cut]).is_err(), "truncation at {cut} must be rejected");
        }
    }

    #[test]
    fn reads_real_fixture() {
        let path = cecli_core::fixtures_dir().join("simplemdb.exe.mdb");
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("missing fixture {}: {e}", path.display()));
        let reader = MdbReader::open(&bytes).expect("fixture should parse");
        assert_eq!(reader.major_version(), 50);
        assert_eq!(reader.methods().len(), 3);
        assert_eq!(reader.source_files().len(), 1);
        assert!(reader.source_files()[0].path.ends_with("hello.cs"));
        let lines = reader.method_lines(1).expect("decode").expect("present");
        assert!(!lines.il_offsets.is_empty());
        assert_eq!(lines.il_offsets.len(), lines.line_numbers.len());
        assert_eq!(reader.method_lines(99).unwrap(), None);
    }
}
