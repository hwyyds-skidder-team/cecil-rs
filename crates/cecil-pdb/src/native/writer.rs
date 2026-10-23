//! Handwritten native PDB builder. Existing type streams can be retained while
//! procedure, scope and line information is rebuilt from the public model.

use std::collections::{BTreeMap, HashMap, HashSet};

use cecil_core::{io::ByteWriter, Error, Result};

use super::codeview_writer::{
    encode_module, encode_module_with_procedure_types, encode_publics, EncodedModule,
};
use super::msf::MsfImage;
use super::msf_writer::write_msf;
use super::{FunctionDebugInfo, NativePdbReader, SourceDocument};

const INVALID_STREAM: u16 = u16::MAX;
const INFO_VERSION: u32 = 20000404;
const DBI_VERSION: u32 = 19990903;

/// Builds an MSF7 native PDB without OS debug APIs or an external PDB library.
/// New models support primitive local types. [`Self::from_pdb`] preserves the
/// original TPI/IPI and their referenced streams so existing type indices remain
/// meaningful, including native procedure signatures. Procedure types absent
/// from a newly constructed model are emitted as `T_NOTYPE`.
#[derive(Debug, Clone)]
pub struct NativePdbBuilder {
    guid: [u8; 16],
    signature: u32,
    age: u32,
    machine: u16,
    streams: Vec<Option<Vec<u8>>>,
    optional: [u16; 11],
    module_names: Vec<(String, String)>,
    functions: Vec<FunctionDebugInfo>,
    documents: Vec<SourceDocument>,
    publics: Vec<(String, u16, u32, u32)>,
    named_streams: BTreeMap<String, u32>,
    section_headers: Option<Vec<u8>>,
    type_range: Option<(u32, u32)>,
    procedure_types: HashMap<(usize, u16, u32, String), u32>,
}

impl Default for NativePdbBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NativePdbBuilder {
    pub fn new() -> Self {
        Self {
            guid: [0; 16],
            signature: 0,
            age: 1,
            machine: 0x14c,
            streams: vec![None, None, Some(empty_types()), None, Some(empty_types())],
            optional: [INVALID_STREAM; 11],
            module_names: Vec::new(),
            functions: Vec::new(),
            documents: Vec::new(),
            publics: Vec::new(),
            named_streams: BTreeMap::new(),
            section_headers: None,
            type_range: None,
            procedure_types: HashMap::new(),
        }
    }

    /// Reconstructs modeled debug information, retaining the original type,
    /// type-hash, section/OMAP and other opaque streams at their old indices.
    /// Unsupported symbol records are not reconstructed in rebuilt modules.
    pub fn from_pdb(bytes: &[u8]) -> Result<Self> {
        let image = MsfImage::parse(bytes)?;
        let reader = NativePdbReader::open(bytes)?;
        let (guid, _, signature, age) = reader.pdb_id();
        let mut streams: Vec<Option<Vec<u8>>> = (0..image.stream_count())
            .map(|index| image.stream(index).map(<[u8]>::to_vec))
            .collect();
        streams.resize(streams.len().max(5), None);
        if streams[2].is_none() {
            streams[2] = Some(empty_types());
        }
        if streams[4].is_none() {
            streams[4] = Some(empty_types());
        }
        let type_range = streams[2].as_ref().and_then(|stream| {
            if stream.len() < 20 {
                return None;
            }
            Some((
                u32::from_le_bytes(stream[8..12].try_into().unwrap()),
                u32::from_le_bytes(stream[12..16].try_into().unwrap()),
            ))
        });
        let header = reader.dbi_dbg_header();
        let optional = [
            header.sn_fpo,
            header.sn_exception,
            header.sn_fixup,
            header.sn_omap_to_src,
            header.sn_omap_from_src,
            header.sn_section_hdr,
            INVALID_STREAM,
            header.sn_xdata,
            header.sn_pdata,
            header.sn_new_fpo,
            header.sn_section_hdr_orig,
        ];
        let publics = raw_publics(&image, reader.dbi_header().symrec_stream as u16)?;
        let procedure_types = raw_procedure_types(&image, reader.modules())?;
        Ok(Self {
            guid,
            signature,
            age,
            machine: reader.dbi_header().machine,
            streams,
            optional,
            module_names: reader
                .modules()
                .iter()
                .map(|module| (module.module_name.clone(), module.object_name.clone()))
                .collect(),
            functions: reader.function_debug_info().to_vec(),
            documents: reader.source_documents().to_vec(),
            publics,
            named_streams: read_named_streams(image.stream(1).unwrap())?,
            section_headers: None,
            type_range,
            procedure_types,
        })
    }

    pub fn identity(&self) -> ([u8; 16], u32, u32) {
        (self.guid, self.signature, self.age)
    }
    pub fn set_identity(&mut self, guid: [u8; 16], signature: u32, age: u32) {
        self.guid = guid;
        self.signature = signature;
        self.age = age;
    }
    pub fn set_machine(&mut self, machine: u16) {
        self.machine = machine;
    }
    /// Sets image section headers, in the standard 40-byte COFF layout.
    /// This replaces any original OMAP transform with direct image mapping.
    pub fn set_section_headers(&mut self, headers: &[u8]) -> Result<()> {
        if !headers.len().is_multiple_of(40) || headers.len() / 40 > u16::MAX as usize {
            return Err(Error::argument("invalid native PDB section-header stream"));
        }
        self.section_headers = Some(headers.to_vec());
        self.optional[3] = INVALID_STREAM;
        self.optional[4] = INVALID_STREAM;
        self.optional[10] = INVALID_STREAM;
        Ok(())
    }
    pub fn clear_functions(&mut self) {
        self.functions.clear();
    }
    pub fn clear_documents(&mut self) {
        self.documents.clear();
    }
    pub fn clear_publics(&mut self) {
        self.publics.clear();
    }
    pub fn add_document(&mut self, document: SourceDocument) -> Result<()> {
        validate_name(&document.name)?;
        if let Some(existing) = self.documents.iter().find(|d| d.name == document.name) {
            if existing == &document {
                return Ok(());
            }
            return Err(Error::argument(
                "conflicting native PDB source checksums for one filename",
            ));
        }
        self.documents.push(document);
        Ok(())
    }
    pub fn add_function(&mut self, function: FunctionDebugInfo) -> Result<()> {
        validate_name(&function.name)?;
        if function.module_index >= u16::MAX as usize {
            return Err(Error::argument("native PDB module index exceeds DBI range"));
        }
        self.functions.push(function);
        Ok(())
    }
    pub fn add_public(&mut self, name: &str, segment: u16, offset: u32, flags: u32) -> Result<()> {
        validate_name(name)?;
        if segment == 0 {
            return Err(Error::argument("native PDB public has a zero segment"));
        }
        if flags & !0xf != 0 {
            return Err(Error::argument("unsupported native PDB public flags"));
        }
        self.publics.push((name.to_owned(), segment, offset, flags));
        Ok(())
    }

    pub fn finalize(mut self) -> Result<Vec<u8>> {
        if self.age == 0 || self.age > i32::MAX as u32 {
            return Err(Error::argument("native PDB age is outside the supported positive range"));
        }
        let mut known: HashSet<String> =
            self.documents.iter().map(|doc| doc.name.clone()).collect();
        for function in &self.functions {
            for scope in &function.scopes {
                for ty in scope
                    .locals
                    .iter()
                    .map(|local| local.type_index)
                    .chain(scope.constants.iter().map(|constant| constant.type_index))
                {
                    let metadata_type = function.token.is_some()
                        && matches!(ty >> 24, 0x01 | 0x02 | 0x11 | 0x1b)
                        && ty & 0x00ff_ffff != 0;
                    if ty >= 0x1000
                        && !metadata_type
                        && !self.type_range.is_some_and(|(start, end)| ty >= start && ty < end)
                    {
                        return Err(Error::unsupported(format!(
                            "native PDB local type index {ty:#x} in {} needs a retained TPI stream",
                            function.name
                        )));
                    }
                }
            }
            for line in &function.lines {
                if known.insert(line.file.clone()) {
                    validate_name(&line.file)?;
                    self.documents.push(SourceDocument {
                        name: line.file.clone(),
                        checksum_kind: 0,
                        checksum: Vec::new(),
                    });
                }
            }
        }
        let mut groups: BTreeMap<usize, Vec<FunctionDebugInfo>> = BTreeMap::new();
        for function in self.functions {
            groups.entry(function.module_index).or_default().push(function);
        }
        // Empty source-only PDBs still need a module for C13 document records.
        if groups.is_empty() && !self.documents.is_empty() {
            groups.insert(0, Vec::new());
        }
        let module_count =
            groups.keys().next_back().map_or(0, |last| last + 1).max(self.module_names.len());
        if module_count > u16::MAX as usize {
            return Err(Error::argument("native PDB module count exceeds DBI range"));
        }
        let mut encoded = Vec::with_capacity(module_count);
        let mut module_streams = Vec::with_capacity(module_count);
        for index in 0..module_count {
            let functions = groups.get(&index).map_or(&[][..], Vec::as_slice);
            let types: Vec<u32> = functions
                .iter()
                .map(|function| {
                    self.procedure_types
                        .get(&(index, function.segment, function.offset, function.name.clone()))
                        .copied()
                        .unwrap_or(0)
                })
                .collect();
            let module = if types.iter().all(|&ty| ty == 0) {
                encode_module(functions, &self.documents)?
            } else {
                encode_module_with_procedure_types(functions, &self.documents, &types)?
            };
            module_streams.push(append_stream(&mut self.streams, module.bytes.clone())?);
            encoded.push(module);
        }
        if let Some(headers) = self.section_headers {
            self.optional[5] = append_stream(&mut self.streams, headers)?;
        }
        let strings = encoded.first().map_or_else(|| vec![0], |m| m.string_table.clone());
        let names_index = append_stream(&mut self.streams, names_stream(&strings)?)?;
        self.named_streams.insert("/names".into(), names_index as u32);
        let mut symbols = encode_publics(&self.publics)?;
        let mut public_records = record_entries(&symbols)?;
        let public_hash = hash_stream(&public_records)?;
        let mut psi = ByteWriter::new();
        psi.u32(word(public_hash.len(), "public hash size")?);
        psi.u32(word(
            public_records
                .len()
                .checked_mul(4)
                .ok_or_else(|| Error::argument("public address map overflows"))?,
            "public address map",
        )?);
        psi.zeros(20);
        psi.bytes(&public_hash);
        public_records
            .sort_by(|a, b| (a.segment, a.address, &a.name).cmp(&(b.segment, b.address, &b.name)));
        for public in &public_records {
            psi.u32(public.offset);
        }
        let psi_index = append_stream(&mut self.streams, psi.into_vec())?;
        let mut globals = Vec::new();
        for (index, module) in encoded.iter().enumerate() {
            append_procedure_refs(
                &module.bytes[..module.symbols_size as usize],
                index,
                &mut symbols,
                &mut globals,
            )?;
        }
        let gsi_index = append_stream(&mut self.streams, hash_stream(&globals)?)?;
        let record_index = append_stream(&mut self.streams, symbols)?;
        let dbi = build_dbi(
            self.age,
            self.machine,
            (gsi_index, psi_index, record_index),
            &encoded,
            &module_streams,
            &self.module_names,
            &self.optional,
        )?;
        self.streams[3] = Some(dbi);
        self.streams[1] =
            Some(info_stream(self.guid, self.signature, self.age, &self.named_streams)?);
        write_msf(&self.streams, 4096)
    }
}

fn append_stream(streams: &mut Vec<Option<Vec<u8>>>, bytes: Vec<u8>) -> Result<u16> {
    let index = u16::try_from(streams.len())
        .ok()
        .filter(|v| *v != INVALID_STREAM)
        .ok_or_else(|| Error::unsupported("native PDB stream count exceeds DBI indices"))?;
    streams.push(Some(bytes));
    Ok(index)
}

fn validate_name(name: &str) -> Result<()> {
    if name.as_bytes().contains(&0) || name.len() > 1_048_576 {
        return Err(Error::argument("native PDB name contains NUL or exceeds length limit"));
    }
    Ok(())
}
fn word(value: usize, what: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::argument(format!("native PDB {what} exceeds u32")))
}
fn signed_word(value: usize, what: &str) -> Result<u32> {
    if value > i32::MAX as usize {
        return Err(Error::argument(format!("native PDB {what} exceeds i32")));
    }
    Ok(value as u32)
}

fn empty_types() -> Vec<u8> {
    let mut output = ByteWriter::new();
    for value in [20040203, 56, 0x1000, 0x1000, 0] {
        output.u32(value);
    }
    output.u16(INVALID_STREAM);
    output.u16(INVALID_STREAM);
    output.u32(4);
    output.u32(0x1000);
    output.zeros(24);
    output.into_vec()
}

fn info_stream(
    guid: [u8; 16],
    signature: u32,
    age: u32,
    names: &BTreeMap<String, u32>,
) -> Result<Vec<u8>> {
    let mut output = ByteWriter::new();
    output.u32(INFO_VERSION);
    output.u32(signature);
    output.u32(age);
    output.bytes(&guid);
    let mut strings = Vec::new();
    let capacity =
        names.len().checked_mul(2).and_then(|v| v.checked_add(1)).unwrap_or(usize::MAX).max(8);
    if capacity > i32::MAX as usize {
        return Err(Error::argument("native PDB named-stream count exceeds range"));
    }
    let mut buckets = vec![None; capacity];
    for (name, &index) in names {
        validate_name(name)?;
        let offset = word(strings.len(), "named-stream strings")?;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        let mut slot = (hash_v1(name.as_bytes()) as u16 as usize) % capacity;
        while buckets[slot].is_some() {
            slot = (slot + 1) % capacity;
        }
        buckets[slot] = Some((offset, index));
    }
    output.u32(word(strings.len(), "named-stream strings")?);
    output.bytes(&strings);
    output.u32(word(names.len(), "named-stream count")?);
    output.u32(capacity as u32);
    let words = capacity.div_ceil(32);
    output.u32(words as u32);
    for index in 0..words {
        let mut bits = 0;
        for bit in 0..32 {
            if buckets.get(index * 32 + bit).is_some_and(Option::is_some) {
                bits |= 1 << bit;
            }
        }
        output.u32(bits);
    }
    output.u32(0);
    for (offset, index) in buckets.into_iter().flatten() {
        output.u32(offset);
        output.u32(index);
    }
    output.u32(20091201); // VC110: explicitly advertises the IPI stream.
    Ok(output.into_vec())
}

fn names_stream(strings: &[u8]) -> Result<Vec<u8>> {
    let mut entries = Vec::new();
    let mut at = 1usize;
    while at < strings.len() {
        let len = strings[at..]
            .iter()
            .position(|v| *v == 0)
            .ok_or_else(|| Error::argument("unterminated native PDB name table"))?;
        entries.push((at as u32, &strings[at..at + len]));
        at += len + 1;
    }
    let capacity = entries
        .len()
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| Error::argument("native PDB name table capacity overflows"))?;
    let mut buckets = vec![0u32; capacity];
    for &(offset, bytes) in &entries {
        let mut slot = hash_v1(bytes) as usize % capacity;
        while buckets[slot] != 0 {
            slot = (slot + 1) % capacity;
        }
        buckets[slot] = offset;
    }
    let mut output = ByteWriter::new();
    output.u32(0xeffe_effe);
    output.u32(1);
    output.u32(word(strings.len(), "/names bytes")?);
    output.bytes(strings);
    output.u32(word(capacity, "/names buckets")?);
    for bucket in buckets {
        output.u32(bucket);
    }
    output.u32(word(entries.len(), "/names count")?);
    Ok(output.into_vec())
}

fn hash_v1(bytes: &[u8]) -> u32 {
    let mut result = 0;
    let (chunks, tail) = bytes.as_chunks::<4>();
    for chunk in chunks {
        result ^= u32::from_le_bytes(*chunk);
    }
    if tail.len() >= 2 {
        result ^= u16::from_le_bytes([tail[0], tail[1]]) as u32;
    }
    if tail.len() % 2 == 1 {
        result ^= tail[tail.len() - 1] as u32;
    }
    result |= 0x2020_2020;
    result ^= result >> 11;
    result ^ (result >> 16)
}

#[derive(Clone)]
struct HashEntry {
    name: String,
    offset: u32,
    segment: u16,
    address: u32,
}

fn record_entries(bytes: &[u8]) -> Result<Vec<HashEntry>> {
    let mut output = Vec::new();
    let mut at = 0usize;
    while at < bytes.len() {
        let size = read_u16(bytes, at)? as usize + 2;
        let record = bytes
            .get(
                at..at
                    .checked_add(size)
                    .ok_or_else(|| Error::argument("public record range overflows"))?,
            )
            .ok_or_else(|| Error::argument("truncated emitted public record"))?;
        if read_u16(record, 2)? != 0x110e {
            return Err(Error::argument("invalid emitted public record kind"));
        }
        output.push(HashEntry {
            name: read_name(record, 14)?,
            offset: word(at, "public record offset")?,
            segment: read_u16(record, 12)?,
            address: read_u32(record, 8)?,
        });
        at += size;
    }
    Ok(output)
}

fn hash_stream(entries: &[HashEntry]) -> Result<Vec<u8>> {
    // Empty GSI/PSI tables end at the hash header: no bucket bitmap follows.
    if entries.is_empty() {
        let mut output = ByteWriter::new();
        output.u32(u32::MAX);
        output.u32(0xeffe_0000u32.wrapping_add(19990810));
        output.zeros(8);
        return Ok(output.into_vec());
    }
    let mut sorted: Vec<_> = entries.iter().collect();
    sorted.sort_by(|a, b| {
        let bucket = |v: &HashEntry| hash_v1(v.name.as_bytes()) % 4096;
        bucket(a)
            .cmp(&bucket(b))
            .then_with(|| a.name.len().cmp(&b.name.len()))
            .then_with(|| {
                if a.name.is_ascii() && b.name.is_ascii() {
                    a.name
                        .bytes()
                        .map(|c| c.to_ascii_lowercase())
                        .cmp(b.name.bytes().map(|c| c.to_ascii_lowercase()))
                } else {
                    a.name.cmp(&b.name)
                }
            })
            .then_with(|| a.offset.cmp(&b.offset))
    });
    let mut bitmap = [0u32; 129];
    let mut starts = Vec::new();
    let mut previous = None;
    for (index, entry) in sorted.iter().enumerate() {
        let bucket = hash_v1(entry.name.as_bytes()) as usize % 4096;
        if previous != Some(bucket) {
            bitmap[bucket / 32] |= 1 << (bucket % 32);
            starts.push(word(
                index
                    .checked_mul(12)
                    .ok_or_else(|| Error::argument("symbol hash offset overflows"))?,
                "symbol hash offset",
            )?);
            previous = Some(bucket);
        }
    }
    let mut output = ByteWriter::new();
    output.u32(u32::MAX);
    output.u32(0xeffe_0000u32.wrapping_add(19990810));
    output.u32(word(
        entries
            .len()
            .checked_mul(8)
            .ok_or_else(|| Error::argument("symbol hash size overflows"))?,
        "symbol hash size",
    )?);
    output.u32(word((bitmap.len() + starts.len()) * 4, "symbol bucket size")?);
    for entry in sorted {
        output.u32(
            entry
                .offset
                .checked_add(1)
                .ok_or_else(|| Error::argument("symbol hash record offset overflows"))?,
        );
        output.u32(1);
    }
    for bits in bitmap {
        output.u32(bits);
    }
    for start in starts {
        output.u32(start);
    }
    Ok(output.into_vec())
}

fn append_procedure_refs(
    module: &[u8],
    index: usize,
    symbols: &mut Vec<u8>,
    globals: &mut Vec<HashEntry>,
) -> Result<()> {
    let mut at = 4usize;
    while at < module.len() {
        let size = read_u16(module, at)? as usize + 2;
        let record = module
            .get(at..at + size)
            .ok_or_else(|| Error::argument("invalid emitted module record"))?;
        let kind = read_u16(record, 2)?;
        if matches!(kind, 0x1110 | 0x110f | 0x112a | 0x112b) {
            let name = read_name(record, if matches!(kind, 0x112a | 0x112b) { 41 } else { 39 })?;
            let offset = word(symbols.len(), "global record offset")?;
            let mut output = ByteWriter::new();
            output.u16(0);
            output.u16(if matches!(kind, 0x110f | 0x112b) { 0x1127 } else { 0x1125 });
            output.u32(hash_v1(name.as_bytes()));
            output.u32(word(at, "procedure symbol offset")?);
            output.u16(
                u16::try_from(index + 1)
                    .map_err(|_| Error::argument("procedure module reference overflows"))?,
            );
            output.bytes(name.as_bytes());
            output.u8(0);
            output.align(4);
            let mut bytes = output.into_vec();
            let len = u16::try_from(bytes.len() - 2)
                .map_err(|_| Error::argument("procedure reference name exceeds CodeView record"))?;
            bytes[..2].copy_from_slice(&len.to_le_bytes());
            symbols.extend_from_slice(&bytes);
            globals.push(HashEntry { name, offset, segment: 0, address: 0 });
        }
        at += size;
    }
    Ok(())
}

fn build_dbi(
    age: u32,
    machine: u16,
    streams: (u16, u16, u16),
    modules: &[EncodedModule],
    indices: &[u16],
    names: &[(String, String)],
    optional: &[u16; 11],
) -> Result<Vec<u8>> {
    let (gsi, psi, symbols) = streams;
    let mut modi = ByteWriter::new();
    for (index, (module, &stream)) in modules.iter().zip(indices).enumerate() {
        modi.u32(0);
        modi.u16(INVALID_STREAM);
        modi.u16(0);
        modi.zeros(24);
        modi.u16(0);
        modi.u16(stream);
        modi.u32(module.symbols_size);
        modi.u32(0);
        modi.u32(module.c13_size);
        modi.u16(
            u16::try_from(module.files.len())
                .map_err(|_| Error::argument("too many files in native PDB module"))?,
        );
        modi.u16(0);
        modi.zeros(12);
        let fallback = format!("cecil-module-{index}");
        let (name, object) = names
            .get(index)
            .map_or((fallback.as_str(), fallback.as_str()), |(a, b)| (a.as_str(), b.as_str()));
        validate_name(name)?;
        validate_name(object)?;
        modi.bytes(name.as_bytes());
        modi.u8(0);
        modi.bytes(object.as_bytes());
        modi.u8(0);
        modi.align(4);
    }
    let file_count: usize = modules.iter().map(|module| module.files.len()).sum();
    let mut files = ByteWriter::new();
    files.u16(modules.len() as u16);
    files.u16(file_count as u16);
    for index in 0..modules.len() {
        files.u16(index as u16);
    }
    for module in modules {
        files.u16(module.files.len() as u16);
    }
    let mut strings = Vec::new();
    let mut file_offsets = HashMap::new();
    for module in modules {
        for file in &module.files {
            let offset = if let Some(&offset) = file_offsets.get(file) {
                offset
            } else {
                let offset = word(strings.len(), "DBI filenames")?;
                strings.extend_from_slice(file.as_bytes());
                strings.push(0);
                file_offsets.insert(file, offset);
                offset
            };
            files.u32(offset);
        }
    }
    files.bytes(&strings);
    files.align(4);
    // Zero EC name indices still refer to the empty string. Include its
    // standard PDB string table so independent readers can resolve them.
    let ec_names = names_stream(&[0])?;
    let mut output = ByteWriter::new();
    output.u32(u32::MAX);
    output.u32(DBI_VERSION);
    output.u32(age);
    output.u16(gsi);
    output.u16(0x8e00);
    output.u16(psi);
    output.u16(0);
    output.u16(symbols);
    output.u16(0);
    output.u32(signed_word(modi.len(), "DBI modules")?);
    output.u32(0);
    output.u32(0);
    output.u32(signed_word(files.len(), "DBI files")?);
    output.u32(0);
    output.u32(0);
    output.u32(22);
    output.u32(word(ec_names.len(), "DBI EC names")?);
    output.u16(0);
    output.u16(machine);
    output.u32(0);
    output.bytes(modi.as_slice());
    output.bytes(files.as_slice());
    output.bytes(&ec_names);
    for index in optional {
        output.u16(*index);
    }
    Ok(output.into_vec())
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16> {
    let data =
        bytes.get(at..at + 2).ok_or_else(|| Error::bad_image("truncated native PDB field"))?;
    Ok(u16::from_le_bytes(data.try_into().unwrap()))
}
fn read_u32(bytes: &[u8], at: usize) -> Result<u32> {
    let data =
        bytes.get(at..at + 4).ok_or_else(|| Error::bad_image("truncated native PDB field"))?;
    Ok(u32::from_le_bytes(data.try_into().unwrap()))
}
fn read_name(bytes: &[u8], at: usize) -> Result<String> {
    let data = bytes.get(at..).ok_or_else(|| Error::bad_image("truncated native PDB name"))?;
    let len = data
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| Error::bad_image("unterminated native PDB name"))?;
    Ok(String::from_utf8_lossy(&data[..len]).into_owned())
}

fn raw_publics(image: &MsfImage<'_>, stream: u16) -> Result<Vec<(String, u16, u32, u32)>> {
    let mut output = Vec::new();
    let Some(bytes) = image.stream(stream as usize) else { return Ok(output) };
    let mut at = 0usize;
    while at < bytes.len() {
        let size = read_u16(bytes, at)? as usize + 2;
        let record = bytes
            .get(at..at + size)
            .ok_or_else(|| Error::bad_image("truncated native public record"))?;
        if read_u16(record, 2)? == 0x110e {
            output.push((
                read_name(record, 14)?,
                read_u16(record, 12)?,
                read_u32(record, 8)?,
                read_u32(record, 4)?,
            ));
        }
        at += size;
    }
    Ok(output)
}

fn raw_procedure_types(
    image: &MsfImage<'_>,
    modules: &[super::symbols::DbiModuleInfo],
) -> Result<HashMap<(usize, u16, u32, String), u32>> {
    let mut ids = HashMap::new();
    if let Some(ipi) = image.stream(4).filter(|bytes| bytes.len() >= 56) {
        let start = read_u32(ipi, 4)? as usize;
        let end = start
            .checked_add(read_u32(ipi, 16)? as usize)
            .ok_or_else(|| Error::bad_image("native PDB IPI range overflows"))?;
        let records = ipi
            .get(start..end)
            .ok_or_else(|| Error::bad_image("truncated native PDB IPI records"))?;
        let mut at = 0;
        let mut index = read_u32(ipi, 8)?;
        while at < records.len() {
            let size = read_u16(records, at)? as usize + 2;
            let record = records
                .get(at..at + size)
                .ok_or_else(|| Error::bad_image("truncated native PDB IPI record"))?;
            if matches!(read_u16(record, 2)?, 0x1601 | 0x1602) {
                ids.insert(index, read_u32(record, 8)?);
            }
            at += size;
            index = index
                .checked_add(1)
                .ok_or_else(|| Error::bad_image("native PDB IPI index overflows"))?;
        }
    }
    let mut types = HashMap::new();
    for (index, module) in modules.iter().enumerate() {
        let Some(bytes) = image.stream(module.stream as u16 as usize) else { continue };
        let symbols = bytes
            .get(
                ..usize::try_from(module.cb_syms)
                    .map_err(|_| Error::bad_image("negative native PDB symbol size"))?,
            )
            .ok_or_else(|| Error::bad_image("truncated native PDB module symbols"))?;
        let mut at = 4;
        while at < symbols.len() {
            let size = read_u16(symbols, at)? as usize + 2;
            let record = symbols
                .get(at..at + size)
                .ok_or_else(|| Error::bad_image("truncated native PDB procedure record"))?;
            let kind = read_u16(record, 2)?;
            if matches!(kind, 0x100a | 0x100b | 0x110f | 0x1110 | 0x1146 | 0x1147) {
                let mut ty = read_u32(record, 28)?;
                if matches!(kind, 0x1146 | 0x1147) {
                    ty = ids.get(&ty).copied().unwrap_or(0);
                }
                let name =
                    if kind < 0x1100 {
                        let len = *record.get(39).ok_or_else(|| {
                            Error::bad_image("truncated native PDB procedure name")
                        })? as usize;
                        String::from_utf8_lossy(record.get(40..40 + len).ok_or_else(|| {
                            Error::bad_image("truncated native PDB procedure name")
                        })?)
                        .into_owned()
                    } else {
                        read_name(record, 39)?
                    };
                types.insert((index, read_u16(record, 36)?, read_u32(record, 32)?, name), ty);
            }
            at += size;
        }
    }
    Ok(types)
}

fn read_named_streams(bytes: &[u8]) -> Result<BTreeMap<String, u32>> {
    let strings_size = read_u32(bytes, 28)? as usize;
    let strings = bytes
        .get(32..32 + strings_size)
        .ok_or_else(|| Error::bad_image("truncated named-stream strings"))?;
    let mut at = 32 + strings_size;
    let size = read_u32(bytes, at)? as usize;
    at += 8;
    let words = read_u32(bytes, at)? as usize;
    at += 4;
    let bitmap = bytes
        .get(at..at + words * 4)
        .ok_or_else(|| Error::bad_image("truncated named-stream bitmap"))?;
    at += words * 4;
    let deleted = read_u32(bytes, at)? as usize;
    at += 4 + deleted * 4;
    let mut result = BTreeMap::new();
    for index in 0..words {
        for bit in 0..32 {
            if read_u32(bitmap, index * 4)? & (1 << bit) == 0 {
                continue;
            }
            let name_offset = read_u32(bytes, at)? as usize;
            let stream = read_u32(bytes, at + 4)?;
            at += 8;
            result.insert(read_name(strings, name_offset)?, stream);
        }
    }
    if result.len() != size {
        return Err(Error::bad_image("invalid duplicate named-stream entries"));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_public_only_native_pdbs_reopen() {
        let empty = NativePdbBuilder::new().finalize().unwrap();
        NativePdbReader::open(&empty).unwrap();
        let mut builder = NativePdbBuilder::new();
        builder.set_identity([7; 16], 4, 2);
        builder.add_public("alpha", 1, 0x44, 2).unwrap();
        let bytes = builder.finalize().unwrap();
        let reader = NativePdbReader::open(&bytes).unwrap();
        assert_eq!(reader.pdb_id(), ([7; 16], INFO_VERSION, 4, 2));
        assert_eq!(reader.publics(), vec![("alpha".into(), 0x44)]);
    }

    #[test]
    fn reconstructed_pdb_retains_type_streams_and_modeled_procedures() {
        let path = cecil_core::fixtures_dir().join("MixedNativeCLI.pdb");
        let original = std::fs::read(path).unwrap();
        let before = NativePdbReader::open(&original).unwrap();
        let bytes = NativePdbBuilder::from_pdb(&original).unwrap().finalize().unwrap();
        let after = NativePdbReader::open(&bytes).unwrap();
        assert_eq!(after.function_debug_info(), before.function_debug_info());
        assert_eq!(after.source_documents(), before.source_documents());
        assert_eq!(after.publics(), before.publics());
        assert_eq!(after.modules().len(), before.modules().len());
        let original = MsfImage::parse(&original).unwrap();
        let written = MsfImage::parse(&bytes).unwrap();
        assert_eq!(written.stream(2), original.stream(2));
        assert_eq!(written.stream(4), original.stream(4));
        let old_types = raw_procedure_types(&original, before.modules()).unwrap();
        assert!(old_types.values().any(|&ty| ty >= 0x1000));
        assert_eq!(raw_procedure_types(&written, after.modules()).unwrap(), old_types);
    }

    #[test]
    fn model_validation_rejects_invalid_names_and_unknown_type_indices() {
        let mut builder = NativePdbBuilder::new();
        assert!(builder.add_public("bad\0name", 1, 0, 0).is_err());
        assert!(builder.set_section_headers(&[0; 39]).is_err());
        builder.set_identity([0; 16], 0, 0);
        assert!(builder.finalize().is_err());
        let mut builder = NativePdbBuilder::new();
        builder
            .add_function(FunctionDebugInfo {
                token: None,
                name: "unknown_type".into(),
                module_index: 0,
                segment: 1,
                offset: 0,
                length: 1,
                rva: None,
                lines: Vec::new(),
                scopes: vec![super::super::NativeScope {
                    parent: None,
                    offset: 0,
                    length: 1,
                    locals: vec![super::super::NativeLocal {
                        name: "x".into(),
                        index: None,
                        type_index: 0x1000,
                        flags: 0,
                    }],
                    constants: Vec::new(),
                    imports: Vec::new(),
                }],
            })
            .unwrap();
        assert!(builder.finalize().is_err());
    }

    #[test]
    fn empty_symbol_hash_contains_only_its_header() {
        let hash = hash_stream(&[]).unwrap();
        assert_eq!(hash.len(), 16);
        assert_eq!(read_u32(&hash, 8).unwrap(), 0);
        assert_eq!(read_u32(&hash, 12).unwrap(), 0);
    }

    #[test]
    fn all_real_native_pdbs_retain_modeled_records() {
        for name in [
            "AVbTest.pdb",
            "CecilTest.pdb",
            "ComplexPdb.pdb",
            "EmptyRootNamespace.pdb",
            "MixedNativeCLI.pdb",
            "VBConsApp.pdb",
            "empty-iterator.pdb",
            "fsapp.pdb",
            "libpdb.pdb",
            "longtypename.pdb",
            "test.pdb",
        ] {
            let original = std::fs::read(cecil_core::fixtures_dir().join(name)).unwrap();
            let before = NativePdbReader::open(&original).unwrap();
            let bytes = NativePdbBuilder::from_pdb(&original).unwrap().finalize().unwrap();
            let after = NativePdbReader::open(&bytes).unwrap();
            assert_eq!(after.function_debug_info(), before.function_debug_info(), "{name}");
            assert_eq!(after.source_documents(), before.source_documents(), "{name}");
            assert_eq!(after.publics(), before.publics(), "{name}");
            assert_eq!(after.modules().len(), before.modules().len(), "{name}");
        }
    }
}
