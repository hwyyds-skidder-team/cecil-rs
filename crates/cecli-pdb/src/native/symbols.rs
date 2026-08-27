//! Native (Windows) PDB CodeView symbol layer.
//!
//! Port of the symbol-reading subset of Mono.Cecil's
//! `symbols/pdb/Microsoft.Cci.Pdb/*.cs`, layered on top of the MSF container
//! ([`crate::native::msf::MsfImage`]). Reads:
//!
//! * the PDB **info stream** (stream 1): version/signature/age/GUID plus the
//!   named-stream index (`LoadNameIndex`),
//! * the `/names` string heap stream (`LoadNameStream`),
//! * the **DBI stream** (stream 3): [`DbiHeader`], per-module [`DbiModuleInfo`]
//!   records (with their [`DbiSecCon`] section contributions) and the optional
//!   [`DbiDbgHdr`](DbiDbgHdr) debug header,
//! * per-module **debug streams**: CodeView symbol records (managed procs
//!   `S_GMANPROC`/`S_LMANPROC` only — native `S_GPROC32`/`S_LPROC32`,
//!   incl. `_ST`, are parsed-and-skipped so unmanaged symbols on mixed
//!   images never pollute the token map) and C13 line
//!   subsections (`DEBUG_S_LINES`, `DEBUG_S_FILECHKSMS`),
//! * the DBI **global symbol stream** (`S_PUB32`) for public symbols.
//!
//! # Ported CvInfo items
//!
//! `SYM` subset (S_END, S_OEM, S_PUB32(_ST), S_GPROC32/S_LPROC32
//! (parsed-and-skipped), S_GMANPROC/S_LMANPROC), `ProcSym32`, `ManProcSym`,
//! `PubSym32`,
//! `CV_PUBSYMFLAGS`, `CV_LineSection`, `CV_SourceFile`, `CV_Line`,
//! `CV_Line_Flags`, `CV_Column` (parsed-and-skipped, see below),
//! `CV_FileCheckSum`, `DEBUG_S_SUBSECTION`, `CV_LINES_HAVE_COLUMNS`.
//!
//! # Documented skips (every unported Cci.Pdb item)
//!
//! The reader exposes only what [`NativePdbReader`]'s API surface needs;
//! everything else from Microsoft.Cci.Pdb is either ported above or skipped
//! here explicitly — no silent omissions:
//!
//! * `MsfDirectory`, `PdbFileHeader`, `DataStream`, `PdbReader`, `BitAccess` —
//!   replaced wholesale by [`crate::native::msf::MsfImage`] + a local
//!   little-endian cursor ([`BitReader`]).
//! * `BitSet` — ported inline as [`BitSet`] (name-index present/deleted maps).
//! * `IntHashTable` — replaced by `std::collections::HashMap`.
//! * `PdbScope`, `PdbSlot`, `PdbConstant`, `PdbLines`, `PdbLine`,
//!   `PdbSource`, `PdbTokenLine` — lexical scopes, locals slots, constants,
//!   per-file line groupings and token-to-source mappings are richer than this
//!   reader's flat `FunctionLines`/`LineEntry` model; their inputs are parsed
//!   but not retained.
//! * Custom metadata (`ReadMD2CustomMetadata`, `PdbSynchronizationInformation`,
//!   using-counts, iterator scopes) — Roslyn-specific OEM (`S_OEM` +
//!   msilMetaData GUID) payloads; unknown record kinds are skipped by length,
//!   mirroring Cecil's default branch.
//! * `LoadTokenToSourceInfo` ("TokenSourceLineInfo" modules / TSLI) — modules
//!   with that name are skipped entirely, as Cecil's caller does when the
//!   mapping is unused.
//! * `SRCSRV` / `SOURCELINK` named streams and injected source information
//!   (`/SRC/FILES/*`, `LoadInjectedSourceInformation`) — source-server and
//!   source-link blobs are not exposed; checksum entries resolve to plain file
//!   names only.
//! * `SymDocumentType_Text` GUID — only used for injected-source lookups above.
//! * Global/public symbol **hash streams** (GSI) — modern (VC7+) globals and
//!   publics streams carry only the `0xffffffff`-signed hash tables with no
//!   inline CV records; enumerating their `S_PUB32` entries requires the
//!   cross-stream hash machinery Cecil never implemented. [`load_publics`]
//!   therefore walks legacy inline-record layouts best-effort and yields an
//!   empty list for hash-only streams.
//! * `FrameData` / `FRAMEDATA_FLAGS` / `XFixupData` (`DEBUG_S_FRAMEDATA`
//!   subsections), `ManProcSymMips`, `DatasSym32`, `AnnotationSym`, and every
//!   other `CvInfo.cs` struct — never consulted by Cecil's managed-function
//!   path; skipped by record/subsection length.
//!
//! # Malformed-input policy
//!
//! Unknown symbol kinds and unknown C13 subsection types are skipped by record
//! length (Cecil behavior). A record whose length overruns its containing
//! region, an undersized (`< 2`) record length, or truncated fixed-size
//! structures produce [`Error::BadImage`]. A procedure whose segment differs
//! from 1 or that carries a non-zero parent/next link errors out exactly like
//! Cecil's `PdbDebugException`. Scopes nest: managed/native procs and
//! `S_BLOCK32` lexical blocks each open a scope closed by `S_END`, so a
//! function's terminator may be preceded by interleaved block records (real
//! compiler output); a symbol region that ends with a scope still open is a
//! [`Error::BadImage`] (truncated region, Cecil `PdbFunction` ctor behavior).

use std::collections::HashMap;
use std::fmt;

use cecli_core::{Error, Result, Token};

use crate::native::msf::MsfImage;

// ---------------------------------------------------------------------------
// CvInfo constants (port of the used subset of `CvInfo.cs`)
// ---------------------------------------------------------------------------

/// CodeView symbol record kinds actually consumed by this reader
/// (subset of `Microsoft.Cci.Pdb.SYM`).
mod sym {
    pub const S_END: u16 = 0x0006;
    pub const S_PUB32_ST: u16 = 0x1009;
    /// Native (unmanaged) proc kinds: walked past by length during function
    /// extraction — accepting them would pollute the managed token map on
    /// mixed images (Cecil parity).
    pub const S_LPROC32_ST: u16 = 0x100a;
    pub const S_GPROC32_ST: u16 = 0x100b;
    /// Lexical block scopes (`S_BLOCK32`), opened between a proc and its
    /// terminator by real compilers.
    pub const S_BLOCK32_ST: u16 = 0x1003;
    pub const S_BLOCK32: u16 = 0x1103;
    pub const S_PUB32: u16 = 0x110e;
    pub const S_LPROC32: u16 = 0x110f;
    pub const S_GPROC32: u16 = 0x1110;
    pub const S_GMANPROC: u16 = 0x112a;
    pub const S_LMANPROC: u16 = 0x112b;

    /// True for managed-proc records which carry the extra `retReg: u16`
    /// field between `flags` and the name (`ManProcSym` vs `ProcSym32`).
    /// These are the ONLY proc kinds accepted for function extraction.
    pub fn is_manproc(kind: u16) -> bool {
        matches!(kind, S_GMANPROC | S_LMANPROC)
    }

    /// Records that open a scope closed by `S_END`: every proc kind plus
    /// lexical blocks (`S_BLOCK32`). Scope nesting is what makes a proc's
    /// terminator findable amid interleaved block records.
    pub fn is_scope_opener(kind: u16) -> bool {
        matches!(
            kind,
            S_GMANPROC
                | S_LMANPROC
                | S_GPROC32
                | S_LPROC32
                | S_GPROC32_ST
                | S_LPROC32_ST
                | S_BLOCK32
                | S_BLOCK32_ST
        )
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

/// `CV_Line_Flags.linenumStart` mask: line where the statement starts.
const LINENUM_START_MASK: u32 = 0x00ff_ffff;
/// `CV_Line_Flags.deltaLineEnd` shift/mask: delta to the statement end line.
const DELTA_LINE_END_SHIFT: u32 = 24;
const DELTA_LINE_END_MASK: u32 = 0x7f;
/// `CV_LINES_HAVE_COLUMNS`: line entries are followed by column entries.
const CV_LINES_HAVE_COLUMNS: u16 = 0x0001;

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
        self.pos = self.pos.div_ceil(boundary) * boundary;
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
        let mut words = Vec::with_capacity(count as usize);
        for _ in 0..count {
            words.push(bits.read_u32()?);
        }
        Ok(BitSet { words })
    }

    fn is_set(&self, index: usize) -> bool {
        let word = index / 32;
        match self.words.get(word) {
            Some(w) => w & (1 << (index % 32)) != 0,
            None => false,
        }
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

impl DbiDbgHdr {
    fn read(bits: &mut BitReader<'_>) -> Result<DbiDbgHdr> {
        Ok(DbiDbgHdr {
            sn_fpo: bits.read_u16()?,
            sn_exception: bits.read_u16()?,
            sn_fixup: bits.read_u16()?,
            sn_omap_to_src: bits.read_u16()?,
            sn_omap_from_src: bits.read_u16()?,
            sn_section_hdr: bits.read_u16()?,
            sn_token_rid_map: bits.read_u16()?,
            sn_xdata: bits.read_u16()?,
            sn_pdata: bits.read_u16()?,
            sn_new_fpo: bits.read_u16()?,
            sn_section_hdr_orig: bits.read_u16()?,
        })
    }
}

// ---------------------------------------------------------------------------
// Public model
// ---------------------------------------------------------------------------

/// One mapped source line inside a function's line program.
///
/// `rva_delta` is the offset of the instruction relative to the start RVA of
/// the enclosing line block (`CV_LineSection.off`). Columns exist in the
/// on-disk format when `CV_LINES_HAVE_COLUMNS` is set — they are parsed (and
/// correctly skipped) but intentionally not exposed in v1; room is left to add
/// `start_column`/`end_column` here without breaking callers.
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
    /// `(start rva, length in bytes)` pairs, one per matched
    /// `DEBUG_S_LINES` line section. As in Cecil, `CV_LineSection.off`/`.sec`
    /// are treated directly as the function's RVA/segment coordinates.
    pub ranges: Vec<(u64, usize)>,
    pub lines: Vec<LineEntry>,
}

/// Selector for [`NativePdbReader::lines_for_function`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionKey {
    /// Look the function up by its metadata method token.
    Token(Token),
    /// Look the function up by an RVA inside one of its address ranges.
    Rva(u64),
}

// ---------------------------------------------------------------------------
// Internal parse models
// ---------------------------------------------------------------------------

/// A `ProcSym32`/`ManProcSym` record before line assignment.
#[derive(Debug, Clone)]
struct RawFunction {
    token: u32,
    name: String,
    segment: u16,
    address: u32,
    /// `(start rva, length in bytes)` pairs, one per matched
    /// `DEBUG_S_LINES` line section.
    ranges: Vec<(u64, usize)>,
    lines: Vec<LineEntry>,
}
// ---------------------------------------------------------------------------
// Stream parsers (ports of the PdbFile.cs static methods)
// ---------------------------------------------------------------------------

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
    let ver = bits.read_i32()?; // 0..3 Version
    let sig = bits.read_i32()?; // 4..7 Signature
    let age = bits.read_i32()?; // 8..11 Age
    let guid = bits.read_guid()?; // 12..27 GUID

    let buf = bits.read_i32()?; // 28..31 Bytes of Strings
    if buf < 0 {
        return Err(Error::bad_image("native pdb: negative string-buffer size"));
    }
    let beg = bits.position();
    let nxt = beg + buf as usize;
    bits.set_position(nxt)?;

    let cnt = bits.read_i32()?; // hash entry count
    let max = bits.read_i32()?; // maximum ni
    if cnt < 0 || max < 0 {
        return Err(Error::bad_image("native pdb: negative name-index sizes"));
    }

    let present = BitSet::read(bits)?;
    let deleted = BitSet::read(bits)?;
    let _ = deleted; // Cecil ignores the deleted bitset too.

    let mut result = HashMap::new();
    let mut seen = 0usize;
    for i in 0..max as usize {
        if present.is_set(i) {
            let ns = bits.read_i32()?;
            let ni = bits.read_i32()?;
            if ns < 0 || ni < 0 {
                return Err(Error::bad_image("native pdb: negative name-index entry"));
            }
            let saved = bits.position();
            bits.set_position(beg + ns as usize)?;
            let name = bits.read_cstring()?;
            bits.set_position(saved)?;
            result.insert(name.to_uppercase(), ni as u32);
            seen += 1;
        }
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
    let beg = bits.position();
    let nxt = beg + buf as usize;
    bits.set_position(nxt)?;

    let siz = bits.read_i32()?; // number of hash buckets
    if siz < 0 {
        return Err(Error::bad_image("native pdb: negative names bucket count"));
    }
    let mut map = HashMap::new();
    let mut ordered = Vec::new();
    let mut seen_nis = Vec::with_capacity(siz as usize);
    for _ in 0..siz {
        let ni = bits.read_i32()?;
        seen_nis.push(ni);
    }
    for ni in seen_nis {
        if ni != 0 {
            let saved = bits.position();
            bits.set_position(beg + ni as usize)?;
            let name = bits.read_cstring()?;
            bits.set_position(saved)?;
            if map.insert(ni as u32, name.clone()).is_none() {
                ordered.push(name);
            }
        }
    }
    Ok((map, ordered))
}

/// Reads `(len: u16, kind: u16)` envelopes until `limit`, invoking `f` with
/// the kind and a cursor positioned right after the kind field. Returns the
/// position just past the last record. Unknown kinds must be skipped by the
/// caller via the returned `stop`; this helper enforces Cecil's corrupt-length
/// policy: undersized or region-overrunning lengths are hard errors.
fn walk_records(
    bits: &mut BitReader<'_>,
    limit: usize,
    mut f: impl FnMut(&mut BitReader<'_>, u16, usize /*stop*/) -> Result<()>,
) -> Result<()> {
    while bits.position() < limit {
        let siz = bits.read_u16()? as usize;
        let star = bits.position();
        if siz < 2 {
            return Err(Error::bad_image(format!(
                "native pdb: corrupt symbol record length {siz} at offset {star}"
            )));
        }
        let stop = star + siz;
        if stop > limit {
            return Err(Error::bad_image(format!(
                "native pdb: symbol record at offset {star} overruns region"
            )));
        }
        let rec = bits.read_u16()?;
        f(bits, rec, star + siz)?;
        bits.set_position(stop.max(bits.position()))?;
    }
    Ok(())
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
        let names_idx = *name_index.get("/NAMES").ok_or_else(|| {
            Error::bad_image(
                "native pdb: could not find the '/names' stream: the PDB may be \
                 a public-symbol file instead of a private symbol file",
            )
        })?;
        let names_bytes = image.stream(names_idx as usize).ok_or_else(|| {
            Error::bad_image(format!("native pdb: missing /names stream #{names_idx}"))
        })?;
        let (names, names_ordered) = load_name_stream(&mut BitReader::new(names_bytes))?;

        // --- DBI stream (stream 3) ------------------------------------------
        let dbi_bytes =
            image.stream(3).ok_or_else(|| Error::bad_image("native pdb: missing DBI stream"))?;
        let (dbi_header, dbg_header, modules) = load_dbi_stream(&mut BitReader::new(dbi_bytes))?;

        // --- Functions from each module --------------------------------------
        let mut raw_functions: Vec<(RawFunction, usize)> = Vec::new(); // func + owning module idx
        let mut module_checksums: Vec<HashMap<u32, String>> = Vec::with_capacity(modules.len());
        let mut source_files: Vec<String> = Vec::new();
        let mut seen_sources: std::collections::HashSet<String> = std::collections::HashSet::new();

        for (mi, info) in modules.iter().enumerate() {
            let mut checks = HashMap::new();
            if info.stream > 0 {
                let stream_idx = info.stream as usize;
                let data = image.stream(stream_idx).ok_or_else(|| {
                    Error::bad_image(format!(
                        "native pdb: module '{}' references missing stream #{stream_idx}",
                        info.module_name
                    ))
                })?;
                // Modules named "TokenSourceLineInfo" carry TSLI OEM records
                // only; Cecil skips them when no token mapping is requested.
                if info.module_name != "TokenSourceLineInfo" {
                    let funcs = load_funcs_from_dbi_module(data, info)?;
                    for func in funcs {
                        raw_functions.push((func, mi));
                    }
                }
                // FileChecksum subsections live in the same C13 region as the
                // line programs (ReadSourceFileInfo).
                let limit = (info.cb_syms + info.cb_old_lines + info.cb_lines) as usize;
                if limit <= data.len() && info.cb_lines > 0 {
                    let mut bits = BitReader::new(data);
                    bits.set_position((info.cb_syms + info.cb_old_lines) as usize)?;
                    read_source_file_info(
                        &mut bits,
                        limit,
                        &names,
                        &mut checks,
                        &mut source_files,
                        &mut seen_sources,
                    )?;
                }
            }
            module_checksums.push(checks);
        }

        // Sort globally by (segment, address, token) — port of
        // `Array.Sort(funcs, PdbFunction.byAddressAndToken)` before line load.
        raw_functions.sort_by(|a, b| {
            let fa = &a.0;
            let fb = &b.0;
            fa.segment
                .cmp(&fb.segment)
                .then(fa.address.cmp(&fb.address))
                .then(fa.token.cmp(&fb.token))
        });

        // --- Assign line programs (port of LoadManagedLines) ----------------
        let sorted: Vec<RawFunction> = raw_functions.into_iter().map(|(f, _)| f).collect();
        let functions = assign_lines(sorted, &modules, image, &module_checksums)?;

        // --- Token RID remap (snTokenRidMap) ---------------------------------
        let functions = apply_token_rid_map(functions, image, &dbg_header)?
            .into_iter()
            .map(|f| FunctionLines {
                token: Token(f.token),
                name: f.name,
                ranges: f.ranges,
                lines: f.lines,
            })
            .collect();

        // --- Publics (public/global symbol streams) --------------------------
        let mut publics = Vec::new();
        for stream_idx in [dbi_header.pssym_stream, dbi_header.gssym_stream] {
            if stream_idx > 0 {
                if let Some(bytes) = image.stream(stream_idx as usize) {
                    publics = load_publics(bytes);
                    if !publics.is_empty() {
                        break;
                    }
                }
            }
        }

        Ok(NativePdbReader {
            guid,
            id: PdbId { version: ver, signature: sig, age },
            names_ordered,
            dbi_header,
            dbg_header,
            modules,
            functions,
            publics,
            source_files,
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
    /// Resolves a function by token or covered RVA and returns its mapped
    /// source lines as absolute `(rva, line, file)` triples.
    ///
    /// Every matched `DEBUG_S_LINES` section starts at the function's own
    /// address ([`assign_lines`] matches on exact `(segment, offset)`), so a
    /// single base RVA converts each stored `rva_delta`. Unresolvable keys
    /// yield an empty list.
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

    /// Public symbols as `(name, rva)` pairs, walked best-effort from the DBI
    /// public/global symbol streams (`S_PUB32` records). Modern GSI hash-only
    /// streams carry no inline records and yield an empty list (see
    /// [`load_publics`]). Like Cecil, the recorded `off`
    /// field is returned as the RVA; non-primary segments are not rebased.
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
    let mut header = DbiDbgHdr::default();

    let gpmodi = positive_size(dh.gpmodi_size, "gpmodi")?;
    let end = bits
        .position()
        .checked_add(gpmodi)
        .ok_or_else(|| Error::bad_image("native pdb: DBI module-list size overflow"))?;

    let mut mod_list = Vec::new();
    while bits.position() < end {
        mod_list.push(DbiModuleInfo::read(bits)?);
    }
    if bits.position() != end {
        return Err(Error::bad_image(format!(
            "native pdb: error reading DBI stream, pos={} != {end}",
            bits.position()
        )));
    }
    for size in [dh.seccon_size, dh.secmap_size, dh.filinf_size, dh.tsmap_size, dh.ecinfo_size] {
        bits.set_position(bits.position() + positive_size(size, "DBI substream")?)?;
    }

    let end = bits
        .position()
        .checked_add(positive_size(dh.dbghdr_size, "dbghdr")?)
        .ok_or_else(|| Error::bad_image("native pdb: DBI debug-header size overflow"))?;
    if dh.dbghdr_size > 0 {
        header = DbiDbgHdr::read(bits)?;
    }
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

/// Port of `PdbFunction.LoadManagedFunctions` + the proc-record branch of
/// `PdbFunction`'s constructor: walks `[4, cb_syms)` collecting managed
/// `S_GMANPROC`/`S_LMANPROC` records only — native `S_GPROC32`/`S_LPROC32`
/// (incl. `_ST`) records are skipped by length so unmanaged symbols on mixed
/// images never enter the token map. Unknown kinds are skipped by length;
/// nested scope contents are never descended into because scanning simply
/// continues at the next record.
fn load_managed_functions(data: &[u8], cb_syms: i32) -> Result<Vec<RawFunction>> {
    if cb_syms < 4 {
        return Ok(Vec::new());
    }
    let limit = cb_syms as usize;
    if limit > data.len() {
        return Err(Error::bad_image(format!(
            "native pdb: module symbol size {limit} exceeds stream of {} bytes",
            data.len()
        )));
    }
    let mut bits = BitReader::new(data);
    let sig = {
        bits.set_position(0)?;
        bits.read_i32()?
    };
    if sig != 4 {
        return Err(Error::bad_image(format!(
            "native pdb: invalid module debug signature (sig={sig})"
        )));
    }
    bits.set_position(4)?;

    let mut funcs = Vec::new();
    // Scope-depth walk, mirroring Cecil's symbol-stack handling in
    // `PdbFile.LoadManagedFunctions`: managed procs, native procs and
    // lexical blocks each open a scope closed by an S_END record. Real
    // compilers interleave S_BLOCK32 scopes (locals, `using`) between a
    // proc and its terminator, so the function's S_END is the one that
    // closes the scope the proc opened — not necessarily the immediately
    // following record.
    let mut depth: usize = 0;
    let mut open_func: Option<String> = None;
    walk_records(&mut bits, limit, |bits, rec, stop| {
        if rec == sym::S_END {
            if depth > 0 {
                depth -= 1;
                if depth == 0 {
                    open_func = None;
                }
            }
            return Ok(());
        }
        // Scope openers: any proc kind or lexical block. Native procs are
        // walked past by length (Cecil parity) but still count for depth so
        // their own S_END cannot close an enclosing managed function.
        if sym::is_scope_opener(rec) {
            depth += 1;
            if depth > 1 || !sym::is_manproc(rec) {
                return Ok(()); // nested proc or native/block scope: skip body
            }
        } else if !sym::is_manproc(rec) {
            return Ok(()); // skip-by-len (Cecil default branch)
        }
        let parent = bits.read_u32()?;
        let _end = bits.read_u32()?;
        let next = bits.read_u32()?;
        let _len = bits.read_u32()?;
        let _dbg_start = bits.read_u32()?;
        let _dbg_end = bits.read_u32()?;
        let token = bits.read_u32()?;
        let off = bits.read_u32()?;
        let seg = bits.read_u16()?;
        let _flags = bits.read_u8()?;
        if sym::is_manproc(rec) {
            let _ret_reg = bits.read_u16()?;
        }
        let name = bits.read_cstring()?;
        bits.set_position(stop)?;

        // Faithful ports of Cecil's PdbDebugException guards.
        if seg != 1 {
            return Err(Error::bad_image(format!(
                "native pdb: function '{name}' segment is {seg}, not 1"
            )));
        }
        if parent != 0 || next != 0 {
            return Err(Error::bad_image(format!(
                "native pdb: function '{name}' parent={parent}, next={next}"
            )));
        }
        open_func = Some(name.clone());
        funcs.push(RawFunction {
            token,
            name,
            segment: seg,
            address: off,
            ranges: Vec::new(),
            lines: Vec::new(),
        });
        Ok(())
    })?;
    if let Some(name) = open_func.take() {
        return Err(Error::bad_image(format!(
            "native pdb: truncated module symbol region: function '{name}' has no S_END"
        )));
    }
    Ok(funcs)
}

/// Port of `PdbFile.LoadFuncsFromDbiModule`.
fn load_funcs_from_dbi_module(data: &[u8], info: &DbiModuleInfo) -> Result<Vec<RawFunction>> {
    load_managed_functions(data, info.cb_syms)
}

/// Port of `PdbFile.ReadSourceFileInfo`: collects the FileChecksum
/// subsection, keyed by entry offset within the subsection payload (that
/// offset is what `CV_SourceFile.index` refers to).
fn read_source_file_info(
    bits: &mut BitReader<'_>,
    limit: usize,
    names: &HashMap<u32, String>,
    checks: &mut HashMap<u32, String>,
    source_files: &mut Vec<String>,
    seen: &mut std::collections::HashSet<String>,
) -> Result<()> {
    while bits.position() < limit {
        let sig = bits.read_i32()?;
        let siz = bits.read_i32()?;
        if siz < 0 {
            return Err(Error::bad_image("native pdb: negative subsection size"));
        }
        let place = bits.position();
        let end_sym = place + siz as usize;
        if end_sym > limit {
            return Err(Error::bad_image("native pdb: C13 subsection overruns module line region"));
        }
        if sig == debug_s_subsection::FILECHKSMS {
            while bits.position() < end_sym {
                let ni_offset = (bits.position() - place) as u32;
                let name_idx = bits.read_u32()?;
                let chk_len = bits.read_u8()?;
                let _chk_type = bits.read_u8()?;
                let name = match names.get(&name_idx) {
                    Some(n) => n.clone(),
                    None => {
                        return Err(Error::bad_image(format!(
                            "native pdb: checksum entry references unknown /names offset {name_idx}"
                        )))
                    }
                };
                checks.insert(ni_offset, name.clone());
                if seen.insert(name.clone()) {
                    source_files.push(name);
                }
                bits.set_position(bits.position() + chk_len as usize)?;
                bits.align(4);
            }
        }
        bits.set_position(end_sym)?;
    }
    Ok(())
}

/// Port of `PdbFile.LoadManagedLines`: sorts nothing itself (callers pass the
/// already-sorted array); walks `DEBUG_S_LINES` subsections of every module
/// and attaches line entries to the matching unassigned function.
fn assign_lines(
    mut funcs: Vec<RawFunction>,
    modules: &[DbiModuleInfo],
    image: &MsfImage<'_>,
    module_checksums: &[HashMap<u32, String>],
) -> Result<Vec<RawFunction>> {
    for (mi, info) in modules.iter().enumerate() {
        if info.stream <= 0 || info.cb_lines <= 0 {
            continue;
        }
        if info.module_name == "TokenSourceLineInfo" {
            continue;
        }
        let data = image.stream(info.stream as usize).ok_or_else(|| {
            Error::bad_image(format!(
                "native pdb: module '{}' references missing stream #{}",
                info.module_name, info.stream
            ))
        })?;
        let begin = (info.cb_syms + info.cb_old_lines) as usize;
        let limit = begin + info.cb_lines as usize;
        if limit > data.len() {
            return Err(Error::bad_image(format!(
                "native pdb: module '{}' line region [{begin},{limit}) exceeds stream of {} bytes",
                info.module_name,
                data.len()
            )));
        }
        let mut bits = BitReader::new(data);
        bits.set_position(begin)?;
        let checks = &module_checksums[mi];

        while bits.position() < limit {
            let sig = bits.read_i32()?;
            let siz = bits.read_i32()?;
            if siz < 0 {
                return Err(Error::bad_image("native pdb: negative subsection size"));
            }
            let end_sym = bits.position() + siz as usize;
            if end_sym > limit {
                return Err(Error::bad_image(
                    "native pdb: C13 subsection overruns module line region",
                ));
            }

            if sig == debug_s_subsection::LINES {
                let sec_off = bits.read_u32()?;
                let sec_sec = bits.read_u16()?;
                let sec_flags = bits.read_u16()?;
                let cod = bits.read_u32()?;

                // FindFunction + duplicate-address resolution: pick the first
                // function at (sec, off) without lines yet, else skip.
                let start = partition_point(&funcs, sec_sec, sec_off);
                let mut target: Option<usize> = None;
                let mut idx = start;
                while idx < funcs.len()
                    && funcs[idx].segment == sec_sec
                    && funcs[idx].address == sec_off
                {
                    if funcs[idx].lines.is_empty() && funcs[idx].ranges.is_empty() {
                        target = Some(idx);
                        break;
                    }
                    idx += 1;
                }
                let Some(func_index) = target else {
                    bits.set_position(end_sym)?;
                    continue;
                };
                funcs[func_index].ranges.push((sec_off as u64, cod as usize));

                // Count blocks first (Cecil does two passes so it can
                // preallocate; we push instead, but still validate the layout
                // in the counting pass).
                let beg_sym = bits.position();
                validate_line_blocks(&mut bits, end_sym, sec_flags)?;
                bits.set_position(beg_sym)?;

                while bits.position() < end_sym {
                    let file_index = bits.read_u32()?;
                    let count = bits.read_u32()?;
                    let linsiz = bits.read_u32()?; // payload size; superseded by count-derived stride
                    let _ = linsiz;
                    let has_columns = sec_flags & CV_LINES_HAVE_COLUMNS != 0;
                    let line_stride = if has_columns { 12 } else { 8 };
                    let payload = (count as usize)
                        .checked_mul(line_stride)
                        .ok_or_else(|| Error::bad_image("native pdb: line payload overflow"))?;
                    if bits.position() + payload > end_sym {
                        return Err(Error::bad_image("native pdb: line block overruns subsection"));
                    }

                    let file = match checks.get(&file_index) {
                        Some(f) => f.clone(),
                        None => {
                            return Err(Error::bad_image(format!(
                            "native pdb: line block references missing checksum entry {file_index}"
                        )))
                        }
                    };

                    let plin = bits.position();
                    let pcol = plin + 8 * count as usize;
                    for i in 0..count as usize {
                        bits.set_position(plin + 8 * i)?;
                        let offset = bits.read_u32()?;
                        let flags = bits.read_u32()?;
                        let line_begin = flags & LINENUM_START_MASK;
                        let _delta = (flags >> DELTA_LINE_END_SHIFT) & DELTA_LINE_END_MASK;
                        if has_columns {
                            bits.set_position(pcol + 4 * i)?;
                            let _col_start = bits.read_u16()?;
                            let _col_end = bits.read_u16()?;
                        }
                        funcs[func_index].lines.push(LineEntry {
                            rva_delta: offset,
                            line: line_begin,
                            file: file.clone(),
                        });
                    }
                    bits.set_position(plin + payload)?;
                }
            }
            bits.set_position(end_sym)?;
        }
    }
    Ok(funcs)
}

/// First index whose key is >= (seg, off); equal-range start for duplicates.
fn partition_point(funcs: &[RawFunction], seg: u16, off: u32) -> usize {
    funcs.partition_point(|f| (f.segment, f.address) < (seg, off))
}

/// Counting pass over `CV_SourceFile` blocks validating strides.
fn validate_line_blocks(bits: &mut BitReader<'_>, end_sym: usize, sec_flags: u16) -> Result<()> {
    let has_columns = sec_flags & CV_LINES_HAVE_COLUMNS != 0;
    while bits.position() < end_sym {
        let _index = bits.read_u32()?;
        let count = bits.read_u32()?;
        let linsiz = bits.read_u32()?;
        let stride = if has_columns { 12 } else { 8 };
        let expected = (count as usize) * stride;
        let _ = linsiz; // legacy field; Cecil also derives the stride from count+flags
        bits.set_position(bits.position() + expected)?;
    }
    Ok(())
}

/// Port of the token remapping tail of `PdbFile.LoadFunctions`: rewrites
/// MethodDef tokens through the `snTokenRidMap` stream when present.
fn apply_token_rid_map(
    mut funcs: Vec<RawFunction>,
    image: &MsfImage<'_>,
    dbg: &DbiDbgHdr,
) -> Result<Vec<RawFunction>> {
    if dbg.sn_token_rid_map == 0 || dbg.sn_token_rid_map == 0xffff {
        return Ok(funcs);
    }
    let data = image.stream(dbg.sn_token_rid_map as usize).ok_or_else(|| {
        Error::bad_image(format!(
            "native pdb: missing token RID map stream #{}",
            dbg.sn_token_rid_map
        ))
    })?;
    let rid_map: Vec<u32> =
        data.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)).collect();
    for func in &mut funcs {
        let rid = (func.token & 0x00ff_ffff) as usize;
        let new_rid = *rid_map.get(rid).ok_or_else(|| {
            Error::bad_image(format!(
                "native pdb: token {:#010x} outside RID map of {} entries",
                func.token,
                rid_map.len()
            ))
        })?;
        func.token = 0x0600_0000 | new_rid;
    }
    Ok(funcs)
}

/// Walks the DBI global/public-symbol streams collecting `S_PUB32` records.
///
/// Modern (VC7+) globals and publics streams are pure GSI hash structures:
/// they start with the `0xffffffff` signature header and contain bucket
/// tables only, with no inline CV records addressable without the
/// cross-stream hash machinery that Cecil never implemented. Such streams
/// yield an empty result here. Legacy streams whose bytes start directly
/// with CV record envelopes (and publics streams preceded by the fixed
/// PublicsStreamHeader) are walked best-effort; walking stops silently at
/// the hash trailer or at any envelope that does not parse, mirroring the
/// skip-by-length tolerance used elsewhere.
fn load_publics(data: &[u8]) -> Vec<(String, u64)> {
    let end = data.len();
    if end >= 4 && data[0] == 0xff && data[1] == 0xff && data[2] == 0xff && data[3] == 0xff {
        return Vec::new(); // modern GSI hash-only stream
    }
    // Legacy publics streams may prefix the records with the 7-dword
    // PublicsStreamHeader; try both offsets.
    for start in [0usize, 28] {
        let mut pos = start;
        let mut found = Vec::new();
        while pos + 2 <= end {
            let siz = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            let star = pos + 2;
            if siz < 2 || star + siz > end {
                break; // hash trailer or malformed tail: stop softly
            }
            let kind = u16::from_le_bytes([data[star], data[star + 1]]);
            if sym::is_pub32(kind) {
                // flags u32 + off u32 + seg u16 + NUL-terminated name.
                if let Some(name_bytes) = data[star + 12..star + siz].split(|&b| b == 0).next() {
                    // kind(2) + flags(4) precede off; seg(2) + name follow.
                    let off = u32::from_le_bytes([
                        data[star + 6],
                        data[star + 7],
                        data[star + 8],
                        data[star + 9],
                    ]);
                    let name = String::from_utf8_lossy(name_bytes).into_owned();
                    found.push((name, off as u64));
                }
            }
            pos = star + siz;
        }
        if !found.is_empty() {
            return found;
        }
    }
    Vec::new()
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
        assert!(matches!(err, cecli_core::Error::BadImage(_)), "expected BadImage, got {err:?}");
    }

    #[test]
    fn undersized_record_length_is_a_hard_error() {
        let mut m = build_module_stream(true, false);
        // siz == 1 (< 2) is structurally impossible.
        m.bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        let pdb = assemble_pdb(&[m], &globals_stream());
        let err = NativePdbReader::open(&pdb).expect_err("undersized record length must fail");
        assert!(matches!(err, cecli_core::Error::BadImage(_)));
    }
    #[test]
    fn wrong_module_signature_is_a_hard_error() {
        let mut m = build_module_stream(true, false);
        m.bytes[0..4].copy_from_slice(&7u32.to_le_bytes()); // sig must be 4
        let pdb = assemble_pdb(&[m], &globals_stream());
        let err = NativePdbReader::open(&pdb).expect_err("bad module signature must fail");
        assert!(matches!(err, cecli_core::Error::BadImage(_)));
    }
    #[test]
    fn non_primary_segment_is_rejected_like_cecil() {
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
        let err =
            NativePdbReader::open(&pdb).expect_err("segment != 1 must fail like PdbDebugException");
        assert!(matches!(err, cecli_core::Error::BadImage(_)));
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
        assert!(matches!(err, cecli_core::Error::BadImage(_)), "expected BadImage, got {err:?}");
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
        assert!(matches!(err, cecli_core::Error::BadImage(_)));
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
}
