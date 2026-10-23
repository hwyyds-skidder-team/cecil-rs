//! Native MSF 7 PDB identity, DBI and CodeView readers.
//!
//! Parsing is handwritten and cross-platform: no WinAPI, DIA or external PDB
//! library is used. Managed and native procedures are retained separately;
//! rich debug information includes source checksums, columns, lexical scopes,
//! local names/slots, constants and imports. Native addresses are rebased using
//! section headers and OMAP when available. Unknown CodeView records are
//! skipped by their bounded length. Unsupported type/OEM/inlining payloads
//! remain opaque; native PDB emission is not supported.

use std::collections::HashMap;
use std::fmt;

use cecil_core::{Error, Result, Token};

use crate::native::msf::MsfImage;

#[path = "details.rs"]
mod details;
pub use details::{
    ConstantValue, FunctionDebugInfo, NativeConstant, NativeLocal, NativeScope, SourceDocument,
    SourceLine,
};

// ---------------------------------------------------------------------------
// CvInfo constants (port of the used subset of `CvInfo.cs`)
// ---------------------------------------------------------------------------

/// CodeView symbol record kinds actually consumed by this reader
/// (subset of `Microsoft.Cci.Pdb.SYM`).
mod sym {
    pub const S_END: u16 = 0x0006;
    pub const S_PUB32_ST: u16 = 0x1009;
    /// Native procedures are retained by the rich debug API, separately from
    /// the managed token map.
    pub const S_LPROC32_ST: u16 = 0x100a;
    pub const S_GPROC32_ST: u16 = 0x100b;
    /// Lexical block scopes (`S_BLOCK32`), opened between a proc and its
    /// terminator by real compilers.
    pub const S_BLOCK32_ST: u16 = 0x0207;
    pub const S_BLOCK32: u16 = 0x1103;
    pub const S_PUB32: u16 = 0x110e;
    pub const S_LPROC32: u16 = 0x110f;
    pub const S_GPROC32: u16 = 0x1110;
    pub const S_GMANPROC: u16 = 0x112a;
    pub const S_LMANPROC: u16 = 0x112b;

    /// True for managed-proc records which carry the extra `retReg: u16`
    /// field between `flags` and the name (`ManProcSym` vs `ProcSym32`).
    pub fn is_manproc(kind: u16) -> bool {
        matches!(kind, 0x101a | 0x101b | S_GMANPROC | S_LMANPROC)
    }

    pub fn is_pub32(kind: u16) -> bool {
        matches!(kind, S_PUB32 | S_PUB32_ST)
    }
}

/// C13 debug-subsection signatures (`DEBUG_S_SUBSECTION`).
mod debug_s_subsection {
    #[allow(dead_code)]
    pub const SYMBOLS: i32 = 0xf1;
    #[allow(dead_code)]
    pub const LINES: i32 = 0xf2;
    #[allow(dead_code)]
    pub const STRINGTABLE: i32 = 0xf3;
    pub const FILECHKSMS: i32 = 0xf4;
    #[allow(dead_code)]
    pub const FRAMEDATA: i32 = 0xf5;
}

// ---------------------------------------------------------------------------
// BitReader — replacement for Microsoft.Cci.Pdb.BitAccess over borrowed bytes
// ---------------------------------------------------------------------------

/// Little-endian cursor over a byte slice; mirrors the positioned reads of
/// `BitAccess` without copying.
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader { data, pos: 0 }
    }

    fn position(&self) -> usize {
        self.pos
    }

    fn set_position(&mut self, pos: usize) -> Result<()> {
        if pos > self.data.len() {
            return Err(Error::bad_image(format!(
                "native pdb: seek to {pos} past end of {}-byte buffer",
                self.data.len()
            )));
        }
        self.pos = pos;
        Ok(())
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn fill(&self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::bad_image(format!(
                "native pdb: truncated data at offset {} (need {n} bytes, {} left)",
                self.pos,
                self.remaining()
            )));
        }
        Ok(&self.data[self.pos..self.pos + n])
    }

    fn read_u8(&mut self) -> Result<u8> {
        let b = self.fill(1)?[0];
        self.pos += 1;
        Ok(b)
    }

    fn read_u16(&mut self) -> Result<u16> {
        let b = self.fill(2)?;
        self.pos += 2;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_i16(&mut self) -> Result<i16> {
        Ok(self.read_u16()? as i16)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let b = self.fill(4)?;
        self.pos += 4;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let data = self.fill(n)?;
        self.pos += n;
        Ok(data)
    }

    fn read_i32(&mut self) -> Result<i32> {
        Ok(self.read_u32()? as i32)
    }

    fn read_guid(&mut self) -> Result<[u8; 16]> {
        let b = self.fill(16)?;
        self.pos += 16;
        let mut guid = [0u8; 16];
        guid.copy_from_slice(b);
        Ok(guid)
    }

    fn align(&mut self, boundary: usize) {
        // Saturate at the end of the buffer: aligning past the last record
        // of a region must leave the reader empty, not past-the-end (a
        // later remaining() would underflow and panic).
        self.pos = (self.pos.div_ceil(boundary) * boundary).min(self.data.len());
    }

    /// Advance past a NUL-terminated UTF-8 string, returning it decoded.
    fn read_cstring(&mut self) -> Result<String> {
        let rest = &self.data[self.pos.min(self.data.len())..];
        match rest.iter().position(|&b| b == 0) {
            Some(end) => {
                let s = String::from_utf8_lossy(&rest[..end]).into_owned();
                self.pos += end + 1;
                Ok(s)
            }
            None => Err(Error::bad_image("native pdb: unterminated string in buffer")),
        }
    }
}

/// Port of `Microsoft.Cci.Pdb.BitSet`: size-prefixed bit vector.
struct BitSet {
    words: Vec<u32>,
}

impl BitSet {
    fn read(bits: &mut BitReader<'_>) -> Result<BitSet> {
        let count = bits.read_i32()?;
        if !(0..=0x0100_0000).contains(&count) {
            return Err(Error::bad_image(format!("native pdb: invalid bitset word count {count}")));
        }
        let available = bits.remaining() / 4;
        if count as usize > available {
            return Err(Error::bad_image(format!(
                "native pdb: bitset declares {count} words but only {available} fit"
            )));
        }
        let mut words = Vec::with_capacity(count as usize);
        for _ in 0..count {
            words.push(bits.read_u32()?);
        }
        Ok(BitSet { words })
    }

    fn set_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.words.iter().enumerate().flat_map(|(word_index, &word)| {
            (0..32).filter_map(move |bit| (word & (1 << bit) != 0).then_some(word_index * 32 + bit))
        })
    }
}

// ---------------------------------------------------------------------------
// DBI structures (ports of DbiHeader.cs / DbiModuleInfo.cs / DbiSecCon.cs /
// DbiDbgHdr.cs)
// ---------------------------------------------------------------------------

/// Port of `DbiHeader` (64 bytes at the start of the DBI stream).
#[derive(Debug, Clone)]
pub struct DbiHeader {
    pub sig: i32,
    pub ver: i32,
    pub age: i32,
    /// Global symbol stream index.
    pub gssym_stream: i16,
    pub vers: u16,
    /// Public symbol stream index.
    pub pssym_stream: i16,
    pub pdbver: u16,
    /// Symbol-record fast-link stream index.
    pub symrec_stream: i16,
    pub pdbver2: u16,
    pub gpmodi_size: i32,
    pub seccon_size: i32,
    pub secmap_size: i32,
    pub filinf_size: i32,
    pub tsmap_size: i32,
    pub mfc_index: i32,
    pub dbghdr_size: i32,
    pub ecinfo_size: i32,
    pub flags: u16,
    pub machine: u16,
    pub reserved: i32,
}

impl DbiHeader {
    fn read(bits: &mut BitReader<'_>) -> Result<DbiHeader> {
        Ok(DbiHeader {
            sig: bits.read_i32()?,
            ver: bits.read_i32()?,
            age: bits.read_i32()?,
            gssym_stream: bits.read_i16()?,
            vers: bits.read_u16()?,
            pssym_stream: bits.read_i16()?,
            pdbver: bits.read_u16()?,
            symrec_stream: bits.read_i16()?,
            pdbver2: bits.read_u16()?,
            gpmodi_size: bits.read_i32()?,
            seccon_size: bits.read_i32()?,
            secmap_size: bits.read_i32()?,
            filinf_size: bits.read_i32()?,
            tsmap_size: bits.read_i32()?,
            mfc_index: bits.read_i32()?,
            dbghdr_size: bits.read_i32()?,
            ecinfo_size: bits.read_i32()?,
            flags: bits.read_u16()?,
            machine: bits.read_u16()?,
            reserved: bits.read_i32()?,
        })
    }
}

/// Port of `DbiSecCon`: a module's section contribution (28 bytes).
#[derive(Debug, Clone, Default)]
pub struct DbiSecCon {
    pub section: i16,
    pub pad1: i16,
    pub offset: i32,
    pub size: i32,
    pub flags: u32,
    pub module: i16,
    pub pad2: i16,
    pub data_crc: u32,
    pub reloc_crc: u32,
}

impl DbiSecCon {
    fn read(bits: &mut BitReader<'_>) -> Result<DbiSecCon> {
        Ok(DbiSecCon {
            section: bits.read_i16()?,
            pad1: bits.read_i16()?,
            offset: bits.read_i32()?,
            size: bits.read_i32()?,
            flags: bits.read_u32()?,
            module: bits.read_i16()?,
            pad2: bits.read_i16()?,
            data_crc: bits.read_u32()?,
            reloc_crc: bits.read_u32()?,
        })
    }
}

/// Port of `DbiModuleInfo`: one entry of the DBI module list.
#[derive(Debug, Clone)]
pub struct DbiModuleInfo {
    pub opened: i32,
    pub seccon: DbiSecCon,
    pub flags: u16,
    /// Debug-data stream index for this module (`<= 0` means none).
    pub stream: i16,
    /// Size in bytes of the symbol region (measured from the start of the
    /// module stream, i.e. inclusive of the leading 4-byte signature).
    pub cb_syms: i32,
    pub cb_old_lines: i32,
    pub cb_lines: i32,
    pub files: i16,
    pub offsets: u32,
    pub ni_source: i32,
    pub ni_compiler: i32,
    pub module_name: String,
    pub object_name: String,
}

impl DbiModuleInfo {
    fn read(bits: &mut BitReader<'_>) -> Result<DbiModuleInfo> {
        let opened = bits.read_i32()?;
        let seccon = DbiSecCon::read(bits)?;
        let flags = bits.read_u16()?;
        let stream = bits.read_i16()?;
        let cb_syms = bits.read_i32()?;
        let cb_old_lines = bits.read_i32()?;
        let cb_lines = bits.read_i32()?;
        let files = bits.read_i16()?;
        let _pad1 = bits.read_i16()?;
        let offsets = bits.read_u32()?;
        let ni_source = bits.read_i32()?;
        let ni_compiler = bits.read_i32()?;
        let module_name = bits.read_cstring()?;
        let object_name = bits.read_cstring()?;
        bits.align(4);
        // Cecil deliberately ignores `opened`/`pad1` validation here.
        Ok(DbiModuleInfo {
            opened,
            seccon,
            flags,
            stream,
            cb_syms,
            cb_old_lines,
            cb_lines,
            files,
            offsets,
            ni_source,
            ni_compiler,
            module_name,
            object_name,
        })
    }
}

/// Port of `DbiDbgHdr`: the DBI optional (debug) header.
#[derive(Debug, Clone, Copy, Default)]
pub struct DbiDbgHdr {
    pub sn_fpo: u16,
    pub sn_exception: u16,
    pub sn_fixup: u16,
    pub sn_omap_to_src: u16,
    pub sn_omap_from_src: u16,
    /// Section-header stream index.
    pub sn_section_hdr: u16,
    /// Token-to-RID remap stream index (`0`/`0xffff` = absent).
    pub sn_token_rid_map: u16,
    pub sn_xdata: u16,
    pub sn_pdata: u16,
    pub sn_new_fpo: u16,
    pub sn_section_hdr_orig: u16,
}

// ---------------------------------------------------------------------------
// Public model
// ---------------------------------------------------------------------------

/// One mapped source line inside a function's line program.
///
/// `rva_delta` is the offset of the instruction relative to the start RVA of
/// the enclosing line block (`CV_LineSection.off`). Columns exist in the
/// on-disk format when `CV_LINES_HAVE_COLUMNS` is set; the full line and
/// column range is exposed through [`SourceLine`] in the additive rich API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineEntry {
    pub rva_delta: u32,
    pub line: u32,
    pub file: String,
}

/// A managed function recovered from native PDB symbols: its metadata token,
/// covered address range(s) and mapped source lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionLines {
    pub token: Token,
    pub name: String,
    /// Legacy managed `(IL base offset, procedure length)` coverage. The rich
    /// API distinguishes IL offsets from native RVAs explicitly.
    pub ranges: Vec<(u64, usize)>,
    pub lines: Vec<LineEntry>,
}

/// Selector for [`NativePdbReader::lines_for_function`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionKey {
    /// Look the function up by its metadata method token.
    Token(Token),
    /// Legacy managed address lookup: matches the procedure's IL base plus
    /// its code length. Native image RVAs are exposed by [`FunctionDebugInfo`]
    /// and [`SourceLine`] instead.
    Rva(u64),
}

/// Name-index payload of the info stream: upper-cased name -> stream-index
/// map plus version, signature, age, and GUID.
type NameIndex = (HashMap<String, u32>, u32, u32, u32, [u8; 16]);

/// PDB identity triple read from the info stream.
#[derive(Debug, Clone, Copy)]
pub struct PdbId {
    pub version: u32,
    pub signature: u32,
    pub age: u32,
}

/// Port of `PdbFile.LoadNameIndex`: parses the info stream, returning the
/// upper-cased name -> stream-index map plus version/signature/age/GUID.
fn load_name_index(bits: &mut BitReader<'_>) -> Result<NameIndex> {
    let mut string_budget = bits.remaining().saturating_mul(16);
    let ver = bits.read_i32()?; // 0..3 Version
    let sig = bits.read_i32()?; // 4..7 Signature
    let age = bits.read_i32()?; // 8..11 Age
    let guid = bits.read_guid()?; // 12..27 GUID

    let buf = bits.read_i32()?; // 28..31 Bytes of Strings
    if buf < 0 {
        return Err(Error::bad_image("native pdb: negative string-buffer size"));
    }
    let strings = bits.take(buf as usize)?;

    let cnt = bits.read_i32()?; // hash entry count
    let max = bits.read_i32()?; // maximum ni
    if cnt < 0 || max < 0 {
        return Err(Error::bad_image("native pdb: negative name-index sizes"));
    }

    let present = BitSet::read(bits)?;
    let deleted = BitSet::read(bits)?;
    let _ = deleted; // Cecil ignores the deleted bitset too.

    if cnt > max || cnt as usize > bits.remaining() / 8 {
        return Err(Error::bad_image(format!(
            "native pdb: name-index count {cnt} exceeds capacity {max} or entry bytes"
        )));
    }

    let mut result = HashMap::new();
    let mut seen = 0usize;
    // Serialized bit vectors omit trailing zero words. Hash-table capacity
    // therefore need not fit inside the present bitmap; iterate the encoded
    // set bits so a huge sparse capacity does not amplify parser work.
    for i in present.set_indices() {
        if i >= max as usize {
            return Err(Error::bad_image("native pdb: name-index bit exceeds capacity"));
        }
        let ns = bits.read_i32()?;
        let ni = bits.read_i32()?;
        if ns < 0 || ni < 0 {
            return Err(Error::bad_image("native pdb: negative name-index entry"));
        }
        let name = heap_string(strings, ns as usize)?;
        string_budget =
            string_budget.checked_sub(name.len().saturating_mul(4).saturating_add(32)).ok_or_else(
                || Error::bad_image("native pdb: name-index string allocation limit exceeded"),
            )?;
        result.insert(name.to_uppercase(), ni as u32);
        seen += 1;
    }
    if seen as i32 != cnt {
        return Err(Error::bad_image(format!(
            "native pdb: name-index count mismatch ({seen} != {cnt})"
        )));
    }
    Ok((result, ver as u32, sig as u32, age as u32, guid))
}

/// Port of `PdbFile.LoadNameStream`: parses the `/names` heap, returning both
/// the ni -> name lookup and the names in deterministic (bucket) order.
fn load_name_stream(bits: &mut BitReader<'_>) -> Result<(HashMap<u32, String>, Vec<String>)> {
    let mut string_budget = bits.remaining().saturating_mul(16);
    let sig = bits.read_u32()?; // 0..3 Signature
    let ver = bits.read_i32()?; // 4..7 Version
    let buf = bits.read_i32()?; // 8..11 Bytes of Strings
    if buf < 0 {
        return Err(Error::bad_image("native pdb: negative names buffer size"));
    }
    if sig != 0xef_fe_ef_fe || ver != 1 {
        return Err(Error::bad_image(format!(
            "native pdb: unsupported name stream (sig={sig:#x}, ver={ver})"
        )));
    }
    let strings = bits.take(buf as usize)?;

    let siz = bits.read_i32()?; // number of hash buckets
    if siz < 0 {
        return Err(Error::bad_image("native pdb: negative names bucket count"));
    }
    let mut map = HashMap::new();
    let mut ordered = Vec::new();
    // Each bucket is 4 bytes in the stream, so the remaining length bounds a
    // sane allocation; a hostile count would otherwise pre-allocate GBs
    // before the first read past the end fails.
    if siz as usize > bits.remaining() / 4 {
        return Err(Error::bad_image("native pdb: names bucket count exceeds stream"));
    }
    let bucket_cap = siz as usize;
    let mut seen_nis = Vec::with_capacity(bucket_cap);
    for _ in 0..siz {
        let ni = bits.read_i32()?;
        seen_nis.push(ni);
    }
    for ni in seen_nis {
        if ni != 0 {
            // Negative name indices are malformed and would overflow the
            // offset arithmetic below (`i32 as usize` sign-extends).
            if ni < 0 {
                return Err(Error::bad_image(format!("native pdb: negative name index {ni}")));
            }
            if map.contains_key(&(ni as u32)) {
                continue;
            }
            let name = heap_string(strings, ni as usize)?;
            string_budget = string_budget
                .checked_sub(name.len().saturating_mul(4).saturating_add(32))
                .ok_or_else(|| {
                    Error::bad_image("native pdb: names string allocation limit exceeded")
                })?;
            if map.insert(ni as u32, name.clone()).is_none() {
                ordered.push(name);
            }
        }
    }
    Ok((map, ordered))
}

fn heap_string(strings: &[u8], offset: usize) -> Result<String> {
    let rest = strings
        .get(offset..)
        .ok_or_else(|| Error::bad_image("native pdb: string offset outside heap"))?;
    let end = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| Error::bad_image("native pdb: unterminated heap string"))?;
    if end > 1_048_576 {
        return Err(Error::bad_image("native pdb: heap string exceeds limit"));
    }
    Ok(String::from_utf8_lossy(&rest[..end]).into_owned())
}

// ---------------------------------------------------------------------------
// NativePdbReader
// ---------------------------------------------------------------------------

/// Reader for native (Windows) PDB symbol information.
///
/// Everything is parsed eagerly in [`NativePdbReader::open`]; accessors
/// return cached results. Nothing borrows the input bytes: every retained
/// structure is owned, so the reader is valid for `'static` once opened.
#[derive(Clone)]
pub struct NativePdbReader {
    guid: [u8; 16],
    id: PdbId,
    /// `/names` heap names in bucket order (fallback for `source_files`).
    names_ordered: Vec<String>,
    dbi_header: DbiHeader,
    dbg_header: DbiDbgHdr,
    functions: Vec<FunctionLines>,
    publics: Vec<(String, u64)>,
    modules: Vec<DbiModuleInfo>,
    source_files: Vec<String>,
    function_debug_info: Vec<FunctionDebugInfo>,
    source_documents: Vec<SourceDocument>,
}

impl fmt::Debug for NativePdbReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativePdbReader")
            .field("id", &self.id)
            .field("guid", &format!("{:?}", self.guid))
            .field("modules", &self.modules.len())
            .field("functions", &self.functions.len())
            .field("publics", &self.publics.len())
            .field("source_files", &self.source_files.len())
            .finish()
    }
}

impl NativePdbReader {
    /// Opens a native PDB from its raw MSF image bytes, parsing the info
    /// stream, `/names` heap, DBI stream, all module symbol/line regions and
    /// the global-symbol stream. The returned reader owns every parsed
    /// structure; `pdb_bytes` is only borrowed for the duration of the call.
    pub fn open(pdb_bytes: &[u8]) -> Result<Self> {
        let image = MsfImage::parse(pdb_bytes)?;
        Self::from_image(&image)
    }

    /// Runs the full parse pipeline over an already-parsed MSF image.
    fn from_image(image: &MsfImage<'_>) -> Result<Self> {
        // --- Info stream (stream 1): name index + identity -----------------
        let info_bytes = image
            .stream(1)
            .ok_or_else(|| Error::bad_image("native pdb: missing PDB info stream"))?;
        let (name_index, ver, sig, age, guid) = load_name_index(&mut BitReader::new(info_bytes))?;

        // --- /names heap ----------------------------------------------------
        // Stripped/native PDBs may omit /names; C13 can carry a local string
        // table, and public-only files need no source-string heap at all.
        let (names, names_ordered) = if let Some(&names_idx) = name_index.get("/NAMES") {
            let names_bytes = image.stream(names_idx as usize).ok_or_else(|| {
                Error::bad_image(format!("native pdb: missing /names stream #{names_idx}"))
            })?;
            load_name_stream(&mut BitReader::new(names_bytes))?
        } else {
            (HashMap::new(), Vec::new())
        };

        // --- DBI stream (stream 3) ------------------------------------------
        let dbi_bytes =
            image.stream(3).ok_or_else(|| Error::bad_image("native pdb: missing DBI stream"))?;
        let (dbi_header, dbg_header, modules) = load_dbi_stream(&mut BitReader::new(dbi_bytes))?;

        let parsed = details::read(image, &modules, &dbg_header, &dbi_header, &names)?;
        let functions = parsed
            .functions
            .iter()
            .filter_map(|f| {
                f.token.map(|token| FunctionLines {
                    token,
                    name: f.name.clone(),
                    ranges: if f.lines.is_empty() {
                        Vec::new()
                    } else {
                        vec![(f.offset as u64, f.length as usize)]
                    },
                    lines: f
                        .lines
                        .iter()
                        .map(|line| LineEntry {
                            rva_delta: line.offset,
                            line: line.start_line,
                            file: line.file.clone(),
                        })
                        .collect(),
                })
            })
            .collect();
        let mut seen = std::collections::HashSet::new();
        let source_files = parsed
            .documents
            .iter()
            .filter_map(|document| {
                if seen.insert(document.name.clone()) {
                    Some(document.name.clone())
                } else {
                    None
                }
            })
            .collect();

        Ok(NativePdbReader {
            guid,
            id: PdbId { version: ver, signature: sig, age },
            names_ordered,
            dbi_header,
            dbg_header,
            modules,
            functions,
            publics: parsed.publics,
            source_files,
            function_debug_info: parsed.functions,
            source_documents: parsed.documents,
        })
    }

    /// `(GUID, version, signature, age)` identifying this PDB; GUID + age pair
    /// against the PE debug directory (the version/signature fields complete
    /// the info-stream header).
    pub fn pdb_id(&self) -> ([u8; 16], u32, u32, u32) {
        (self.guid, self.id.version, self.id.signature, self.id.age)
    }

    /// Source file names referenced by any module's FileChecksum subsections,
    /// in first-seen order across modules. Falls back to every string in the
    /// `/names` heap when no checksum subsection exists.
    pub fn source_files(&self) -> Vec<String> {
        if self.source_files.is_empty() {
            self.names_ordered.clone()
        } else {
            self.source_files.clone()
        }
    }

    /// All managed functions with their line mappings, sorted by
    /// (segment, rva, token) — Cecil's `byAddressAndToken` order.
    pub fn functions(&self) -> Result<Vec<FunctionLines>> {
        Ok(self.functions.clone())
    }

    /// Finds a function by its metadata method token.
    pub fn find_by_token(&self, tok: Token) -> Option<FunctionLines> {
        self.functions.iter().find(|f| f.token == tok).cloned()
    }

    /// All native and managed procedures with scopes and rich source lines.
    pub fn function_debug_info(&self) -> &[FunctionDebugInfo] {
        &self.function_debug_info
    }

    /// Rich debug information for a managed MethodDef token.
    pub fn debug_info_for_token(&self, token: Token) -> Option<&FunctionDebugInfo> {
        self.function_debug_info.iter().find(|f| f.token == Some(token))
    }

    /// Native procedures (type indices are never interpreted as method tokens).
    pub fn native_functions(&self) -> Vec<FunctionDebugInfo> {
        self.function_debug_info.iter().filter(|f| f.token.is_none()).cloned().collect()
    }

    pub fn source_documents(&self) -> &[SourceDocument] {
        &self.source_documents
    }

    pub fn modules(&self) -> &[DbiModuleInfo] {
        &self.modules
    }
    /// Resolves a managed function by token or legacy covered address and
    /// returns its mapped lines as `(IL base + offset, line, file)` triples.
    ///
    /// Managed procedure bases are not native image RVAs. Use
    /// [`Self::function_debug_info`] for native procedures and the optional
    /// rebased RVA on each [`SourceLine`]. Unresolvable keys yield an empty
    /// list.
    pub fn lines_for_function(&self, key: FunctionKey) -> Result<Vec<(u64, u32, String)>> {
        let func = match key {
            FunctionKey::Token(token) => self.find_by_token(token),
            FunctionKey::Rva(rva) => self
                .functions
                .iter()
                .find(|f| {
                    f.ranges.iter().any(|&(start, len)| rva >= start && rva - start < len as u64)
                })
                .cloned(),
        };
        let Some(func) = func else {
            return Ok(Vec::new());
        };
        let base = func.ranges.first().map_or(0, |&(start, _)| start);
        Ok(func
            .lines
            .into_iter()
            .map(|entry| (base + entry.rva_delta as u64, entry.line, entry.file))
            .collect())
    }

    /// Public symbols from the DBI symbol-record stream, including PDBs with
    /// modern GSI/PSI hash indices. Addresses use section-header/OMAP RVA
    /// mapping when available, and otherwise retain the section offset.
    pub fn publics(&self) -> Vec<(String, u64)> {
        self.publics.clone()
    }

    /// The parsed DBI header (version/age/stream indices/sizes).
    pub fn dbi_header(&self) -> &DbiHeader {
        &self.dbi_header
    }

    /// The parsed DBI optional debug header (subsection stream indices).
    pub fn dbi_dbg_header(&self) -> &DbiDbgHdr {
        &self.dbg_header
    }
}

/// Port of `PdbFile.LoadDbiStream`: parses the DBI header, module list,
/// skips the SectionContribution/SectionMap/Fileinfo/TSM/EC substreams and
/// reads the optional debug header.
fn load_dbi_stream(bits: &mut BitReader<'_>) -> Result<(DbiHeader, DbiDbgHdr, Vec<DbiModuleInfo>)> {
    let dh = DbiHeader::read(bits)?;

    let gpmodi = positive_size(dh.gpmodi_size, "gpmodi")?;
    let end = bits
        .position()
        .checked_add(gpmodi)
        .ok_or_else(|| Error::bad_image("native pdb: DBI module-list size overflow"))?;

    let module_bytes = bits.take(gpmodi)?;
    let mut module_bits = BitReader::new(module_bytes);
    let mut mod_list = Vec::new();
    while module_bits.remaining() > 0 {
        mod_list.push(DbiModuleInfo::read(&mut module_bits)?);
    }
    if bits.position() != end {
        return Err(Error::bad_image(format!(
            "native pdb: error reading DBI stream, pos={} != {end}",
            bits.position()
        )));
    }
    for size in [dh.seccon_size, dh.secmap_size, dh.filinf_size, dh.tsmap_size, dh.ecinfo_size] {
        bits.take(positive_size(size, "DBI substream")?)?;
    }

    let end = bits
        .position()
        .checked_add(positive_size(dh.dbghdr_size, "dbghdr")?)
        .ok_or_else(|| Error::bad_image("native pdb: DBI debug-header size overflow"))?;
    let mut optional = BitReader::new(bits.take(positive_size(dh.dbghdr_size, "dbghdr")?)?);
    let mut fields = [u16::MAX; 11];
    if !optional.remaining().is_multiple_of(2) {
        return Err(Error::bad_image("native pdb: odd DBI optional-header size"));
    }
    for field in &mut fields {
        if optional.remaining() == 0 {
            break;
        }
        *field = optional.read_u16()?;
    }
    let header = DbiDbgHdr {
        sn_fpo: fields[0],
        sn_exception: fields[1],
        sn_fixup: fields[2],
        sn_omap_to_src: fields[3],
        sn_omap_from_src: fields[4],
        sn_section_hdr: fields[5],
        sn_token_rid_map: fields[6],
        sn_xdata: fields[7],
        sn_pdata: fields[8],
        sn_new_fpo: fields[9],
        sn_section_hdr_orig: fields[10],
    };
    bits.set_position(end)?;

    Ok((dh, header, mod_list))
}

fn positive_size(v: i32, what: &str) -> Result<usize> {
    if v < 0 {
        Err(Error::bad_image(format!("native pdb: negative {what} size {v}")))
    } else {
        Ok(v as usize)
    }
}

// ---------------------------------------------------------------------------
// Tests: minimal symbol streams assembled into an MsfImage page by page
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn w16(out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn w32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn cstr(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }

    // -- synthetic MSF assembly ------------------------------------------

    /// Assembles streams into a little-endian MSF 7.00 image by hand:
    /// superblock in block 0, stream data blocks from block 4 up, then the
    /// directory blocks, then the directory-root blocks (which hold the
    /// directory's own block-index list).
    fn build_msf(streams: &[Vec<u8>]) -> Vec<u8> {
        const PAGE: usize = 512;
        let npages = |len: usize| len.div_ceil(PAGE);

        let mut total_stream_pages = 0usize;
        let mut stream_pages: Vec<Vec<u32>> = Vec::with_capacity(streams.len());
        let mut next_block: u32 = 4; // blocks 0..3 are reserved
        for s in streams {
            let n = npages(s.len());
            let mut pages = Vec::with_capacity(n);
            for _ in 0..n {
                pages.push(next_block);
                next_block += 1;
            }
            total_stream_pages += n;
            stream_pages.push(pages);
        }

        // Directory content: count, sizes, then per-stream block lists.
        let dir_size = 4 * (1 + streams.len() + total_stream_pages);
        let dir_pages = dir_size.div_ceil(PAGE);
        let root_pages = (dir_pages * 4).div_ceil(PAGE);
        let num_blocks = next_block as usize + dir_pages + root_pages;

        let dir_blocks: Vec<u32> = (next_block..next_block + dir_pages as u32).collect();
        let root_blocks: Vec<u32> =
            (next_block + dir_pages as u32..next_block + (dir_pages + root_pages) as u32).collect();

        let mut image = vec![0u8; num_blocks * PAGE];
        image[..32].copy_from_slice(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0");
        let mut put = |off: usize, v: u32| image[off..off + 4].copy_from_slice(&v.to_le_bytes());

        // Superblock.
        put(32, PAGE as u32); // page size
        put(36, 1); // free page map block
        put(40, num_blocks as u32); // pages used
        put(44, dir_size as u32); // directory size
        put(48, 0); // reserved
        for (i, r) in root_blocks.iter().enumerate() {
            put(52 + i * 4, *r);
        }

        // Stream data pages.
        for (s, pages) in streams.iter().zip(&stream_pages) {
            for (i, p) in pages.iter().enumerate() {
                let start = i * PAGE;
                let end = (start + PAGE).min(s.len());
                if start < s.len() {
                    let off = *p as usize * PAGE;
                    image[off..off + (end - start)].copy_from_slice(&s[start..end]);
                }
            }
        }

        // Directory content spread over its blocks.
        let mut dir = Vec::with_capacity(dir_size);
        w32(&mut dir, streams.len() as u32);
        for s in streams {
            w32(&mut dir, s.len() as u32);
        }
        for pages in &stream_pages {
            for p in pages {
                w32(&mut dir, *p);
            }
        }
        assert_eq!(dir.len(), dir_size);
        for (i, b) in dir_blocks.iter().enumerate() {
            let start = i * PAGE;
            let end = (start + PAGE).min(dir_size);
            let off = *b as usize * PAGE;
            image[off..off + (end - start)].copy_from_slice(&dir[start..end]);
        }

        // Root blocks list the directory's own blocks.
        let mut roots = vec![0u8; root_pages * PAGE];
        for (i, b) in dir_blocks.iter().enumerate() {
            roots[i * 4..i * 4 + 4].copy_from_slice(&b.to_le_bytes());
        }
        for r in &root_blocks {
            let off = *r as usize * PAGE;
            image[off..off + PAGE].copy_from_slice(&roots[..PAGE]);
        }

        image
    }

    #[test]
    fn rejects_bitset_count_larger_than_input_before_allocating() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x0100_0000u32.to_le_bytes());
        let mut bits = BitReader::new(&bytes);
        assert!(BitSet::read(&mut bits).is_err());
    }

    // -- stream builders ---------------------------------------------------

    const GUID: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    fn build_info_stream() -> Vec<u8> {
        let strings = b"/names\0";
        let mut out = Vec::new();
        w32(&mut out, 20000404); // version
        w32(&mut out, 1); // signature
        w32(&mut out, 2); // age
        out.extend_from_slice(&GUID);
        w32(&mut out, strings.len() as u32);
        out.extend_from_slice(strings);
        w32(&mut out, 1); // entry count
        w32(&mut out, 1); // maximum ni
        w32(&mut out, 1); // present bitset word count
        w32(&mut out, 1); // bit 0 set
        w32(&mut out, 1); // deleted bitset word count
        w32(&mut out, 0);
        w32(&mut out, 0); // string offset of "/names"
        w32(&mut out, 2); // -> stream 2
        out
    }

    fn build_names_stream() -> Vec<u8> {
        // Offset 0 in the /names heap is by convention an empty bucket slot,
        // so the strings start at 1.
        let strings = b"\0Foo.cs\0Bar.cs\0";
        let mut out = Vec::new();
        out.extend_from_slice(&0xef_fe_ef_fe_u32.to_le_bytes()); // signature
        w32(&mut out, 1); // version
        w32(&mut out, strings.len() as u32);
        out.extend_from_slice(strings);
        w32(&mut out, 2); // buckets
        w32(&mut out, 1); // ni of "Foo.cs"
        w32(&mut out, 8); // ni of "Bar.cs"
        out
    }

    /// Builds a proc record of the given kind. Managed procs carry the extra
    /// `retReg: u16` field between `flags` and the name.
    fn proc_record(kind: u16, name: &str, token: u32, off: u32, seg: u16) -> Vec<u8> {
        let mut rec = Vec::new();
        w16(&mut rec, kind);
        w32(&mut rec, 0); // parent
        w32(&mut rec, 0xffff); // end (absolute pointer; unused here)
        w32(&mut rec, 0); // next
        w32(&mut rec, 0x20); // proc length
        w32(&mut rec, 0); // dbg start
        w32(&mut rec, 0x20); // dbg end
        w32(&mut rec, token); // typind / metadata token
        w32(&mut rec, off);
        w16(&mut rec, seg);
        rec.push(0); // CV_PROCFLAGS
        if sym::is_manproc(kind) {
            w16(&mut rec, 0); // retReg (ManProcSym only)
        }
        cstr(&mut rec, name);
        // CodeView records are padded so the *total* record length (including
        // the leading size field) is a multiple of 4.
        while (rec.len() + 2) % 4 != 0 {
            rec.push(0);
        }
        let mut out = Vec::new();
        w16(&mut out, rec.len() as u16);
        out.extend_from_slice(&rec);
        out
    }

    fn end_record() -> Vec<u8> {
        let mut out = Vec::new();
        w16(&mut out, 2);
        w16(&mut out, sym::S_END);
        out
    }

    fn unknown_record() -> Vec<u8> {
        let mut rec = Vec::new();
        w16(&mut rec, 0x9999); // unrecognized kind: must be skipped by len
        rec.extend_from_slice(b"\xde\xad\xbe\xef");
        let mut out = Vec::new();
        w16(&mut out, rec.len() as u16);
        out.extend_from_slice(&rec);
        out
    }

    fn symbol_record(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        w16(&mut out, (2 + payload.len()) as u16);
        w16(&mut out, kind);
        out.extend_from_slice(payload);
        out
    }

    fn module_with_symbols(symbols: &[u8]) -> ModuleStream {
        let mut bytes = 4u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(symbols);
        ModuleStream { cb_syms: bytes.len() as i32, cb_lines: 0, bytes }
    }

    fn symbols_region(with_unknown: bool) -> Vec<u8> {
        let mut out = Vec::new();
        if with_unknown {
            out.extend_from_slice(&unknown_record());
        }
        out.extend_from_slice(&proc_record(sym::S_GMANPROC, "Foo", 0x0600_0001, 0x1000, 1));
        out.extend_from_slice(&end_record());
        out
    }

    fn file_checksum_subsection() -> Vec<u8> {
        // entry @0: "Foo.cs" (ni 1) with a 16-byte MD5 checksum
        let mut e1 = Vec::new();
        w32(&mut e1, 1);
        e1.push(16);
        e1.push(1); // MD5
        e1.extend_from_slice(&[0xaa; 16]);
        while e1.len() % 4 != 0 {
            e1.push(0);
        }
        // entry @e1.len(): "Bar.cs" (ni 8) without checksum bytes
        let mut e2 = Vec::new();
        w32(&mut e2, 8);
        e2.push(0);
        e2.push(0);
        while e2.len() % 4 != 0 {
            e2.push(0);
        }
        let mut body = e1;
        body.extend_from_slice(&e2);

        let mut sub = Vec::new();
        w32(&mut sub, debug_s_subsection::FILECHKSMS as u32);
        w32(&mut sub, body.len() as u32);
        sub.extend_from_slice(&body);
        sub
    }

    fn lines_subsection() -> Vec<u8> {
        let mut body = Vec::new();
        // CV_LineSection: off, sec, flags, cod
        w32(&mut body, 0x1000);
        w16(&mut body, 1);
        w16(&mut body, 0);
        w32(&mut body, 0x20);
        // CV_SourceFile: checksum offset index, line count, legacy linsiz
        w32(&mut body, 0);
        w32(&mut body, 2);
        w32(&mut body, 16);
        // CV_Line entries: offset, flags(line | deltaLineEnd<<24)
        w32(&mut body, 0);
        w32(&mut body, 5);
        w32(&mut body, 8);
        w32(&mut body, 10 | (3 << 24));

        let mut sub = Vec::new();
        w32(&mut sub, debug_s_subsection::LINES as u32);
        w32(&mut sub, body.len() as u32);
        sub.extend_from_slice(&body);
        sub
    }

    struct ModuleStream {
        bytes: Vec<u8>,
        cb_syms: i32,
        cb_lines: i32,
    }

    fn build_module_stream(with_lines: bool, with_unknown: bool) -> ModuleStream {
        let syms = symbols_region(with_unknown);
        let cb_syms = (4 + syms.len()) as i32;

        let mut out = Vec::new();
        w32(&mut out, 4); // module stream signature
        out.extend_from_slice(&syms);

        let mut cb_lines = 0i32;
        if with_lines {
            for sub in [file_checksum_subsection(), lines_subsection()] {
                cb_lines += sub.len() as i32;
                out.extend_from_slice(&sub);
            }
        }
        ModuleStream { bytes: out, cb_syms, cb_lines }
    }

    fn dbi_header_bytes(gpmodi_len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        w32(&mut out, (-1i32) as u32); // sig
        w32(&mut out, 19990903); // ver
        w32(&mut out, 2); // age
        w16(&mut out, 5); // gssymStream (globals)
        w16(&mut out, 0); // vers
        w16(&mut out, 0xffff); // pssymStream
        w16(&mut out, 0); // pdbver
        w16(&mut out, 0xffff); // symrecStream
        w16(&mut out, 0); // pdbver2
        w32(&mut out, gpmodi_len as u32); // gpmodiSize
        w32(&mut out, 0); // secconSize
        w32(&mut out, 0); // secmapSize
        w32(&mut out, 0); // filinfSize
        w32(&mut out, 0); // tsmapSize
        w32(&mut out, 0); // mfcIndex
        w32(&mut out, 0); // dbghdrSize (no optional header)
        w32(&mut out, 0); // ecinfoSize
        w16(&mut out, 0); // flags
        w16(&mut out, 0x8664); // machine
        w32(&mut out, 0); // reserved
        assert_eq!(out.len(), 64);
        out
    }

    fn module_info_entry(stream: i16, cb_syms: i32, cb_lines: i32) -> Vec<u8> {
        let mut out = Vec::new();
        w32(&mut out, 1); // opened
        out.extend_from_slice(&[0u8; 28]); // DbiSecCon
        w16(&mut out, 0); // flags
        w16(&mut out, stream as u16);
        w32(&mut out, cb_syms as u32);
        w32(&mut out, 0); // cbOldLines
        w32(&mut out, cb_lines as u32);
        w16(&mut out, 0); // files
        w16(&mut out, 0); // pad1
        w32(&mut out, 0); // offsets
        w32(&mut out, 0); // niSource
        w32(&mut out, 0); // niCompiler
        cstr(&mut out, "hello.obj");
        cstr(&mut out, "hello.obj");
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    fn globals_stream() -> Vec<u8> {
        let mut rec = Vec::new();
        w16(&mut rec, sym::S_PUB32);
        w32(&mut rec, 0x0000_0006); // fCode | fFunction
        w32(&mut rec, 0x2000);
        w16(&mut rec, 1);
        cstr(&mut rec, "pubFoo");
        let mut out = Vec::new();
        w16(&mut out, rec.len() as u16);
        out.extend_from_slice(&rec);
        out
    }

    fn assemble_pdb(mods: &[ModuleStream], globals: &[u8]) -> Vec<u8> {
        let info = build_info_stream();
        let names = build_names_stream();

        // Stream layout: 0 absent, 1 info, 2 names, 3 DBI, 4+ module streams,
        // then the globals stream last.
        let globals_slot = 4 + mods.len();
        let mut gpmodi = Vec::new();
        for (i, m) in mods.iter().enumerate() {
            gpmodi.extend_from_slice(&module_info_entry((4 + i) as i16, m.cb_syms, m.cb_lines));
        }
        let mut dbi = dbi_header_bytes(gpmodi.len());
        dbi.extend_from_slice(&gpmodi);

        let mut streams: Vec<Vec<u8>> = vec![Vec::new(), info, names, dbi];
        for m in mods {
            streams.push(m.bytes.clone());
        }
        streams.push(globals.to_vec());
        assert_eq!(globals_slot, streams.len() - 1);
        build_msf(&streams)
    }

    // -- acceptance tests --------------------------------------------------

    #[test]
    fn functions_lines_and_pdb_id_roundtrip() {
        let pdb = assemble_pdb(&[build_module_stream(true, false)], &globals_stream());
        let reader = NativePdbReader::open(&pdb).expect("open should succeed");

        let (guid, ver, sig, age) = reader.pdb_id();
        assert_eq!(guid, GUID);
        assert_eq!((ver, sig, age), (20000404, 1, 2));

        let funcs = reader.functions().expect("functions");
        assert_eq!(funcs.len(), 1);
        let f = &funcs[0];
        assert_eq!(f.token, Token(0x0600_0001));
        assert_eq!(f.name, "Foo");
        assert_eq!(f.ranges, vec![(0x1000u64, 0x20usize)]);
        assert_eq!(
            f.lines,
            vec![
                LineEntry { rva_delta: 0, line: 5, file: "Foo.cs".into() },
                LineEntry { rva_delta: 8, line: 10, file: "Foo.cs".into() },
            ]
        );
    }

    #[test]
    fn find_by_token_hits_and_misses() {
        let pdb = assemble_pdb(&[build_module_stream(true, false)], &globals_stream());
        let reader = NativePdbReader::open(&pdb).expect("open should succeed");

        let hit = reader.find_by_token(Token(0x0600_0001)).expect("token hit");
        assert_eq!(hit.lines.len(), 2);

        assert!(reader.find_by_token(Token(0x0600_0002)).is_none());
    }

    #[test]
    fn publics_walked_from_global_stream() {
        let pdb = assemble_pdb(&[build_module_stream(true, false)], &globals_stream());
        let reader = NativePdbReader::open(&pdb).expect("open should succeed");
        assert_eq!(reader.publics(), vec![("pubFoo".to_string(), 0x2000u64)]);
    }
    #[test]
    fn source_files_from_checksum_subsections() {
        let pdb = assemble_pdb(&[build_module_stream(true, false)], &globals_stream());
        let reader = NativePdbReader::open(&pdb).expect("open should succeed");
        assert_eq!(reader.source_files(), vec!["Foo.cs", "Bar.cs"]);
    }
    #[test]
    fn source_files_falls_back_to_names_heap_without_checksums() {
        let pdb = assemble_pdb(&[build_module_stream(false, false)], &globals_stream());
        let reader = NativePdbReader::open(&pdb).expect("open should succeed");

        // No FILECHKSMS subsection: every function still parses but has no
        // lines, and source files fall back to the /names heap.
        let funcs = reader.functions().expect("functions");
        assert_eq!(funcs.len(), 1);
        assert!(funcs[0].lines.is_empty());
        assert!(funcs[0].ranges.is_empty());
        assert_eq!(reader.source_files(), vec!["Foo.cs", "Bar.cs"]);
    }

    #[test]
    fn unknown_symbol_kinds_are_skipped_by_length() {
        let pdb = assemble_pdb(&[build_module_stream(true, true)], &globals_stream());
        let reader = NativePdbReader::open(&pdb).expect("unknown record must be skipped cleanly");
        let funcs = reader.functions().expect("functions");
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].lines.len(), 2);
    }

    #[test]
    fn corrupt_record_length_is_a_hard_error() {
        let mut m = build_module_stream(true, false);
        // Blow up the S_GPROC32 record length (byte offset 4: right after the
        // module-stream signature dword) so it overruns the region.
        m.bytes[4..6].copy_from_slice(&0xffffu16.to_le_bytes());

        let pdb = assemble_pdb(&[m], &globals_stream());
        let err = NativePdbReader::open(&pdb).expect_err("overrunning record length must fail");
        assert!(matches!(err, cecil_core::Error::BadImage(_)), "expected BadImage, got {err:?}");
    }

    #[test]
    fn undersized_record_length_is_a_hard_error() {
        let mut m = build_module_stream(true, false);
        // siz == 1 (< 2) is structurally impossible.
        m.bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        let pdb = assemble_pdb(&[m], &globals_stream());
        let err = NativePdbReader::open(&pdb).expect_err("undersized record length must fail");
        assert!(matches!(err, cecil_core::Error::BadImage(_)));
    }
    #[test]
    fn wrong_module_signature_is_a_hard_error() {
        let mut m = build_module_stream(true, false);
        m.bytes[0..4].copy_from_slice(&7u32.to_le_bytes()); // sig must be 4
        let pdb = assemble_pdb(&[m], &globals_stream());
        let err = NativePdbReader::open(&pdb).expect_err("bad module signature must fail");
        assert!(matches!(err, cecil_core::Error::BadImage(_)));
    }
    #[test]
    fn managed_non_primary_segment_is_supported() {
        let mut rec = proc_record(sym::S_GMANPROC, "Foo", 0x0600_0001, 0x1000, 2);
        let mut syms = Vec::new();
        syms.append(&mut rec);
        syms.extend_from_slice(&end_record());

        let mut m = build_module_stream(false, false);
        // Replace the symbols payload with our segment-2 variant and fix cbSyms.
        let mut bytes = Vec::new();
        w32(&mut bytes, 4);
        bytes.extend_from_slice(&syms);
        m.bytes = bytes;
        m.cb_syms = (4 + syms.len()) as i32;

        let pdb = assemble_pdb(&[m], &globals_stream());
        let reader = NativePdbReader::open(&pdb).expect("mixed images can use multiple segments");
        assert_eq!(reader.debug_info_for_token(Token(0x0600_0001)).unwrap().segment, 2);
    }
    #[test]
    fn multiple_functions_sorted_by_address_share_the_reader() {
        let mut m = build_module_stream(true, false);
        // Append a second function at a lower address directly into the
        // symbols region and grow cbSyms accordingly.
        let second = proc_record(sym::S_GMANPROC, "Bar", 0x0600_0002, 0x0800, 1);
        let insert_at = 4usize;
        let old_syms_end = 4 + (m.cb_syms as usize - 4);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&m.bytes[..insert_at]);
        bytes.extend_from_slice(&second);
        bytes.extend_from_slice(&end_record());
        bytes.extend_from_slice(&m.bytes[insert_at..old_syms_end]);
        bytes.extend_from_slice(&m.bytes[old_syms_end..]);
        m.bytes = bytes;
        m.cb_syms += (second.len() + end_record().len()) as i32;

        let pdb = assemble_pdb(&[m], &globals_stream());
        let reader = NativePdbReader::open(&pdb).expect("open should succeed");
        let funcs = reader.functions().expect("functions");

        assert_eq!(funcs.len(), 2);
        // Sorted by (segment, address): Bar @0x800 before Foo @0x1000.
        assert!(funcs[0].ranges.is_empty());
        assert!(funcs[0].lines.is_empty());
        assert_eq!(funcs[1].name, "Foo");
        assert_eq!(funcs[1].lines.len(), 2);
    }
    #[test]
    fn mixed_native_and_managed_procs_extract_managed_only() {
        // A native S_GPROC32 record sharing the managed proc's address: it
        // must be skipped by length (no token-map pollution) while the
        // managed record is extracted and receives its line program.
        let mut syms = Vec::new();
        syms.extend_from_slice(&proc_record(sym::S_GPROC32, "NativeFoo", 0x1100_0001, 0x1000, 1));
        syms.extend_from_slice(&end_record());
        syms.extend_from_slice(&proc_record(sym::S_GMANPROC, "Foo", 0x0600_0001, 0x1000, 1));
        syms.extend_from_slice(&end_record());

        let mut m = build_module_stream(false, false);
        let mut bytes = Vec::new();
        w32(&mut bytes, 4);
        bytes.extend_from_slice(&syms);
        for sub in [file_checksum_subsection(), lines_subsection()] {
            bytes.extend_from_slice(&sub);
            m.cb_lines += sub.len() as i32;
        }
        m.bytes = bytes;
        m.cb_syms = (4 + syms.len()) as i32;

        let pdb = assemble_pdb(&[m], &globals_stream());
        let reader = NativePdbReader::open(&pdb).expect("mixed image should open");
        let funcs = reader.functions().expect("functions");
        assert_eq!(funcs.len(), 1, "native proc must not be extracted");
        assert_eq!(funcs[0].token, Token(0x0600_0001));
        assert_eq!(funcs[0].name, "Foo");
        assert_eq!(funcs[0].lines.len(), 2);
        assert!(reader.find_by_token(Token(0x1100_0001)).is_none());
        let native = reader.native_functions();
        assert_eq!(native.len(), 1);
        assert_eq!(native[0].name, "NativeFoo");
        assert_eq!(native[0].token, None);
        assert_eq!(native[0].lines.len(), 2);
    }

    #[test]
    fn truncated_proc_region_is_a_hard_error() {
        // No S_END after the proc record: the symbol region ends right there.
        let syms = proc_record(sym::S_GMANPROC, "Foo", 0x0600_0001, 0x1000, 1);

        let mut m = build_module_stream(false, false);
        let mut bytes = Vec::new();
        w32(&mut bytes, 4);
        bytes.extend_from_slice(&syms);
        m.bytes = bytes;
        m.cb_syms = (4 + syms.len()) as i32;

        let pdb = assemble_pdb(&[m], &globals_stream());
        let err = NativePdbReader::open(&pdb).expect_err("missing S_END must fail");
        assert!(matches!(err, cecil_core::Error::BadImage(_)), "expected BadImage, got {err:?}");
    }

    #[test]
    fn proc_without_s_end_before_next_record_is_a_hard_error() {
        // Two procs back to back: the first one is never terminated.
        let mut syms = proc_record(sym::S_GMANPROC, "Foo", 0x0600_0001, 0x1000, 1);
        syms.extend_from_slice(&proc_record(sym::S_GMANPROC, "Bar", 0x0600_0002, 0x2000, 1));
        syms.extend_from_slice(&end_record());

        let mut m = build_module_stream(false, false);
        let mut bytes = Vec::new();
        w32(&mut bytes, 4);
        bytes.extend_from_slice(&syms);
        m.bytes = bytes;
        m.cb_syms = (4 + syms.len()) as i32;

        let pdb = assemble_pdb(&[m], &globals_stream());
        let err = NativePdbReader::open(&pdb).expect_err("missing S_END must fail");
        assert!(matches!(err, cecil_core::Error::BadImage(_)));
    }

    #[test]
    fn lines_for_function_resolves_by_token_and_rva() {
        let pdb = assemble_pdb(&[build_module_stream(true, false)], &globals_stream());
        let reader = NativePdbReader::open(&pdb).expect("open should succeed");

        let expected =
            vec![(0x1000u64, 5u32, "Foo.cs".to_string()), (0x1008u64, 10u32, "Foo.cs".to_string())];
        let by_token = reader
            .lines_for_function(FunctionKey::Token(Token(0x0600_0001)))
            .expect("token lookup");
        assert_eq!(by_token, expected);

        // Inside [0x1000, 0x1020): resolves to the same function.
        let by_rva = reader.lines_for_function(FunctionKey::Rva(0x1010)).expect("rva lookup");
        assert_eq!(by_rva, expected);

        // Outside any range / unknown token: empty result.
        assert!(reader.lines_for_function(FunctionKey::Rva(0x9000)).expect("rva miss").is_empty());
        assert!(reader
            .lines_for_function(FunctionKey::Token(Token(0x0600_00ff)))
            .expect("token miss")
            .is_empty());
    }

    #[test]
    fn real_mixed_native_pdb_preserves_native_and_managed_debug_information() {
        let bytes = include_bytes!("../../../../fixtures/MixedNativeCLI.pdb");
        let reader = NativePdbReader::open(bytes).expect("real mixed-mode PDB");
        assert_eq!(reader.functions().unwrap().len(), 77);
        assert_eq!(reader.native_functions().len(), 58);
        assert_eq!(reader.publics().len(), 336);
        assert!(reader.native_functions().iter().any(|function| function.rva.is_some()));
        assert!(reader.function_debug_info().iter().any(|function| !function.lines.is_empty()));
        assert!(!reader.source_documents().is_empty());
        assert!(reader
            .function_debug_info()
            .iter()
            .filter(|f| f.token.is_some())
            .flat_map(|f| &f.lines)
            .all(|line| line.rva.is_none()));
        assert!(reader
            .function_debug_info()
            .iter()
            .flat_map(|f| &f.scopes)
            .any(|scope| !scope.locals.is_empty()));
    }

    #[test]
    fn real_managed_native_pdb_fixture_corpus() {
        let fixtures: &[(&str, &[u8])] = &[
            ("CecilTest", include_bytes!("../../../../fixtures/CecilTest.pdb")),
            ("ComplexPdb", include_bytes!("../../../../fixtures/ComplexPdb.pdb")),
            ("test", include_bytes!("../../../../fixtures/test.pdb")),
            ("VBConsApp", include_bytes!("../../../../fixtures/VBConsApp.pdb")),
            ("AVbTest", include_bytes!("../../../../fixtures/AVbTest.pdb")),
            ("libpdb", include_bytes!("../../../../fixtures/libpdb.pdb")),
            ("longtypename", include_bytes!("../../../../fixtures/longtypename.pdb")),
            ("empty-iterator", include_bytes!("../../../../fixtures/empty-iterator.pdb")),
            ("EmptyRootNamespace", include_bytes!("../../../../fixtures/EmptyRootNamespace.pdb")),
            ("fsapp", include_bytes!("../../../../fixtures/fsapp.pdb")),
        ];
        for &(name, bytes) in fixtures {
            let reader =
                NativePdbReader::open(bytes).unwrap_or_else(|error| panic!("{name}: {error}"));
            assert!(!reader.function_debug_info().is_empty(), "{name}");
        }
    }

    #[test]
    fn full_columns_checksum_scopes_locals_constants_and_imports() {
        let mut symbols = proc_record(sym::S_GMANPROC, "Foo", 0x0600_0001, 0x1000, 1);
        let mut block = Vec::new();
        for value in [0u32, 0xffff, 0x10, 0x1004] {
            w32(&mut block, value);
        }
        w16(&mut block, 1);
        cstr(&mut block, "inner");
        symbols.extend_from_slice(&symbol_record(sym::S_BLOCK32, &block));
        let mut local = Vec::new();
        w32(&mut local, 3);
        w32(&mut local, 0x1100_0001);
        w32(&mut local, 0x1004);
        w16(&mut local, 1);
        w16(&mut local, 4);
        cstr(&mut local, "answer");
        symbols.extend_from_slice(&symbol_record(0x1120, &local));
        let mut constant = Vec::new();
        w32(&mut constant, 0x1100_0002);
        w16(&mut constant, 0x8003);
        w32(&mut constant, (-42i32) as u32);
        cstr(&mut constant, "negative");
        symbols.extend_from_slice(&symbol_record(0x112d, &constant));
        symbols.extend_from_slice(&symbol_record(0x1124, b"System.Collections\0"));
        symbols.extend_from_slice(&end_record());
        symbols.extend_from_slice(&end_record());
        let mut module = module_with_symbols(&symbols);
        let checksum = file_checksum_subsection();
        let mut lines = lines_subsection();
        lines[14..16].copy_from_slice(&1u16.to_le_bytes());
        lines[28..32].copy_from_slice(&36u32.to_le_bytes());
        lines[36..40].copy_from_slice(&(5u32 | 0x8000_0000).to_le_bytes());
        for column in [2u16, 9, 3, 15] {
            w16(&mut lines, column);
        }
        let payload_len = (lines.len() - 8) as u32;
        lines[4..8].copy_from_slice(&payload_len.to_le_bytes());
        module.cb_lines = (checksum.len() + lines.len()) as i32;
        module.bytes.extend_from_slice(&checksum);
        module.bytes.extend_from_slice(&lines);
        let reader = NativePdbReader::open(&assemble_pdb(&[module], &[])).unwrap();
        let function = reader.debug_info_for_token(Token(0x0600_0001)).unwrap();
        assert_eq!(function.scopes.len(), 2);
        let scope = &function.scopes[1];
        assert_eq!((scope.parent, scope.offset, scope.length), (Some(0), 4, 16));
        assert_eq!(
            scope.locals,
            vec![NativeLocal {
                name: "answer".into(),
                index: Some(3),
                type_index: 0x1100_0001,
                flags: 4
            }]
        );
        assert_eq!(scope.constants[0].value, ConstantValue::Signed(-42));
        assert_eq!(scope.imports, ["System.Collections"]);
        assert_eq!((function.lines[0].start_column, function.lines[0].end_column), (2, 9));
        assert!(function.lines[0].is_statement);
        assert_eq!((function.lines[1].start_line, function.lines[1].end_line), (10, 13));
        assert_eq!(reader.source_documents()[0].checksum, vec![0xaa; 16]);
    }

    #[test]
    fn short_proc_record_cannot_consume_following_record() {
        let mut symbols = symbol_record(sym::S_GMANPROC, &[0; 8]);
        symbols.extend_from_slice(&proc_record(sym::S_GMANPROC, "Foo", 0x0600_0001, 0x1000, 1));
        symbols.extend_from_slice(&end_record());
        assert!(
            NativePdbReader::open(&assemble_pdb(&[module_with_symbols(&symbols)], &[])).is_err()
        );
    }

    #[test]
    fn malformed_pub32_records_return_errors_without_panicking() {
        for size in 0..11 {
            let data = symbol_record(sym::S_PUB32, &vec![0; size]);
            let mut dbi = dbi_header_bytes(0);
            dbi[20..22].copy_from_slice(&5u16.to_le_bytes());
            let bytes = build_msf(&[
                Vec::new(),
                build_info_stream(),
                build_names_stream(),
                dbi,
                Vec::new(),
                data,
            ]);
            assert!(NativePdbReader::open(&bytes).is_err());
        }
    }

    #[test]
    fn c13_lengths_checked_even_without_matching_function() {
        let mut module = build_module_stream(true, false);
        // Remove all procs so malformed unassociated lines still need validation.
        let old_symbols = module.cb_syms as usize;
        module.bytes.drain(4..old_symbols);
        module.cb_syms = 4;
        let lines_start = 4 + file_checksum_subsection().len();
        module.bytes[lines_start + 24..lines_start + 28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(NativePdbReader::open(&assemble_pdb(&[module], &[])).is_err());
    }

    #[test]
    fn name_offsets_and_terminators_are_confined_to_heap() {
        let mut info = build_info_stream();
        // name string begins at 32; give an index into the hash table instead.
        let entry = info.len() - 8;
        info[entry..entry + 4].copy_from_slice(&7u32.to_le_bytes());
        assert!(load_name_index(&mut BitReader::new(&info)).is_err());
        let mut names = build_names_stream();
        names[26] = b'X'; // remove Bar.cs terminator, next hash bytes contain zeros.
        assert!(load_name_stream(&mut BitReader::new(&names)).is_err());
    }

    #[test]
    fn named_stream_hash_capacity_can_exceed_its_sparse_bitmap() {
        for capacity in [100u32, i32::MAX as u32] {
            let mut info = build_info_stream();
            let capacity_offset = 32 + b"/names\0".len() + 4;
            info[capacity_offset..capacity_offset + 4].copy_from_slice(&capacity.to_le_bytes());
            let (names, ..) = load_name_index(&mut BitReader::new(&info)).unwrap();
            assert_eq!(names.get("/NAMES"), Some(&2));
        }
        let mut info = build_info_stream();
        let present_word_offset = 32 + b"/names\0".len() + 12;
        info[present_word_offset..present_word_offset + 4].copy_from_slice(&2u32.to_le_bytes());
        assert!(load_name_index(&mut BitReader::new(&info)).is_err());
    }

    #[test]
    fn native_rvas_use_section_headers_and_omap_with_modern_symbol_records() {
        let mut symbols = proc_record(0x1147, "NativeId", 0x1001, 0x30, 2);
        // Inline sites are bounded scope frames; their terminators must not
        // close the native procedure containing them.
        symbols.extend_from_slice(&symbol_record(0x114d, &[0; 12]));
        symbols.extend_from_slice(&symbol_record(0x114e, &[]));
        symbols.extend_from_slice(&symbol_record(0x114f, &[]));
        let module = module_with_symbols(&symbols);
        let gpmodi = module_info_entry(4, module.cb_syms, 0);
        let mut dbi = dbi_header_bytes(gpmodi.len());
        dbi[20..22].copy_from_slice(&5u16.to_le_bytes()); // real symbol-record stream
        dbi[48..52].copy_from_slice(&22u32.to_le_bytes());
        dbi.extend_from_slice(&gpmodi);
        let mut debug_header = [u16::MAX; 11];
        debug_header[4] = 7; // OMAP from source
        debug_header[5] = 6; // section headers
        debug_header[10] = 6; // original section headers
        for index in debug_header {
            w16(&mut dbi, index);
        }
        let mut sections = vec![0; 80];
        sections[12..16].copy_from_slice(&0x1000u32.to_le_bytes());
        sections[52..56].copy_from_slice(&0x2000u32.to_le_bytes());
        let mut omap = Vec::new();
        for value in [0x2000u32, 0x5000, 0x2100, 0] {
            w32(&mut omap, value);
        }
        let mut public = Vec::new();
        w32(&mut public, 6);
        w32(&mut public, 0x30);
        w16(&mut public, 2);
        cstr(&mut public, "PublicId");
        let pdb = build_msf(&[
            Vec::new(),
            build_info_stream(),
            build_names_stream(),
            dbi,
            module.bytes,
            symbol_record(sym::S_PUB32, &public),
            sections,
            omap,
        ]);
        let reader = NativePdbReader::open(&pdb).unwrap();
        assert_eq!(reader.native_functions()[0].rva, Some(0x5030));
        assert_eq!(reader.publics(), [("PublicId".to_string(), 0x5030)]);
        assert!(reader.functions().unwrap().is_empty());
    }

    #[test]
    fn old_st_proc_names_are_length_prefixed() {
        let mut record = proc_record(sym::S_LPROC32_ST, "OldNative", 0x1001, 0x1000, 1);
        // Fixed native fields occupy 35 bytes after kind. Replace first name
        // byte with the ST byte length, and retain the full original name.
        let name_offset = 2 + 2 + 35;
        record.insert(name_offset, 9);
        let size = (record.len() - 2) as u16;
        record[..2].copy_from_slice(&size.to_le_bytes());
        record.extend_from_slice(&end_record());
        let reader =
            NativePdbReader::open(&assemble_pdb(&[module_with_symbols(&record)], &[])).unwrap();
        assert_eq!(reader.native_functions()[0].name, "OldNative");
    }

    #[test]
    fn native_pdb_without_names_uses_module_c13_string_table() {
        let mut info = Vec::new();
        for value in [20000404u32, 1, 2] {
            w32(&mut info, value);
        }
        info.extend_from_slice(&GUID);
        // One empty heap string followed by an empty named-stream hash map.
        w32(&mut info, 1);
        info.push(0);
        for _ in 0..4 {
            w32(&mut info, 0);
        }
        let mut symbols = proc_record(sym::S_GPROC32, "Native", 0x1001, 0x1000, 1);
        symbols.extend_from_slice(&end_record());
        let mut module = module_with_symbols(&symbols);
        let mut string_table = Vec::new();
        w32(&mut string_table, 0xf3);
        w32(&mut string_table, 8);
        string_table.extend_from_slice(b"\0Foo.cs\0");
        let mut checksums = file_checksum_subsection();
        // Keep only the Foo.cs checksum so every index refers to the local table.
        checksums.truncate(8 + 24);
        checksums[4..8].copy_from_slice(&24u32.to_le_bytes());
        let lines = lines_subsection();
        module.cb_lines = (string_table.len() + checksums.len() + lines.len()) as i32;
        module.bytes.extend_from_slice(&string_table);
        module.bytes.extend_from_slice(&checksums);
        module.bytes.extend_from_slice(&lines);
        let gpmodi = module_info_entry(4, module.cb_syms, module.cb_lines);
        let mut dbi = dbi_header_bytes(gpmodi.len());
        // Optional headers may include only older fields; absent fields must
        // remain 0xffff rather than reading into following bytes.
        dbi[48..52].copy_from_slice(&2u32.to_le_bytes());
        dbi.extend_from_slice(&gpmodi);
        w16(&mut dbi, u16::MAX);
        let reader =
            NativePdbReader::open(&build_msf(&[Vec::new(), info, Vec::new(), dbi, module.bytes]))
                .unwrap();
        assert_eq!(reader.native_functions()[0].lines[0].file, "Foo.cs");
        assert_eq!(reader.dbi_dbg_header().sn_section_hdr, u16::MAX);
    }

    #[test]
    fn module_c13_string_offsets_do_not_alias_global_names() {
        let mut symbols = proc_record(sym::S_GPROC32, "Native", 0x1001, 0x1000, 1);
        symbols.extend_from_slice(&end_record());
        let mut module = module_with_symbols(&symbols);
        let mut strings = Vec::new();
        w32(&mut strings, 0xf3);
        w32(&mut strings, 16);
        strings.extend_from_slice(b"\0LocalA\0LocalB\0\0");
        let checksums = file_checksum_subsection();
        let lines = lines_subsection();
        module.cb_lines = (strings.len() + checksums.len() + lines.len()) as i32;
        module.bytes.extend_from_slice(&strings);
        module.bytes.extend_from_slice(&checksums);
        module.bytes.extend_from_slice(&lines);
        // Both tables have valid but different names at offsets 1 and 8.
        let reader = NativePdbReader::open(&assemble_pdb(&[module], &[])).unwrap();
        assert_eq!(reader.source_files(), ["LocalA", "LocalB"]);
        assert_eq!(reader.native_functions()[0].lines[0].file, "LocalA");
    }

    #[test]
    fn module_c13_string_offsets_must_be_valid_in_the_local_table() {
        let mut module = build_module_stream(true, false);
        let mut strings = Vec::new();
        w32(&mut strings, 0xf3);
        w32(&mut strings, 4);
        strings.extend_from_slice(b"\0A\0\0");
        module.cb_lines += strings.len() as i32;
        module.bytes.extend_from_slice(&strings);
        // Offset 8 exists in /names but lies outside this module's table.
        assert!(NativePdbReader::open(&assemble_pdb(&[module], &[])).is_err());
    }

    #[test]
    fn sampled_real_native_pdb_corruption_never_panics() {
        let original = include_bytes!("../../../../fixtures/MixedNativeCLI.pdb");
        for length in (0..4096).step_by(31).chain((4096..original.len()).step_by(16384)) {
            assert!(NativePdbReader::open(&original[..length]).is_err(), "truncated at {length}");
        }
        let mut state = 0x7435_992fu32;
        for _ in 0..96 {
            let mut image = original.to_vec();
            for _ in 0..4 {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                let index = state as usize % image.len();
                image[index] ^= 0xff;
            }
            let _ = NativePdbReader::open(&image);
        }
    }
}
