//! Writer for the Mono MDB debug-information format.
//!
//! Port of `Mono.CompilerServices.SymbolWriter.MonoSymbolWriter` plus the
//! emission halves of `SourceMethodBuilder`, `LineNumberTable.Write`,
//! `MethodEntry.WriteData` and `MonoSymbolFile.Write`. The output layout
//! mirrors [`crate::reader::MdbReader`] expectations exactly: header,
//! back-patched [`OffsetTable`](crate::reader::OffsetTable), data section
//! (sources, compile units, methods), then the method / source /
//! compile-unit tables, sorted deterministically by method token.

use cecli_core::io::ByteWriter;
use cecli_core::{Error, Result, Token};

use crate::reader::{OffsetTable, MAGIC, MAJOR_VERSION, MINOR_VERSION};


/// `MethodEntry.Flags.ColumnsInfoIncluded`: this writer always emits the
/// trailing column section, mirroring `SourceMethodBuilder.DefineMethod`.
const FLAGS_COLUMNS_INFO_INCLUDED: u32 = 1 << 1;

// LineNumberTable opcodes used by the encoder.
const DW_LNS_ADVANCE_PC: u8 = 2;
const DW_LNS_ADVANCE_LINE: u8 = 3;
const DW_LNS_SET_FILE: u8 = 4;
const DW_LNS_CONST_ADD_PC: u8 = 8;

#[derive(Debug, Clone)]
struct LineEntry {
    file: u32,
    row: i32,
    /// Always `-1`; columns carry no information through this writer.
    column: i32,
    offset: i32,
}

#[derive(Debug, Clone)]
struct LocalVariable {
    index: i32,
    name: String,
    block_index: i32,
}

#[derive(Debug, Clone)]
struct MethodData {
    token: Token,
    compile_unit: u32,
    namespace_id: i32,
    lines: Vec<LineEntry>,
    locals: Vec<LocalVariable>,
}

/// Builder producing Mono MDB symbol files readable by
/// [`crate::reader::MdbReader`] (and mcs/mono itself).
///
/// The roundtrip is the spec: every byte layout follows
/// `MonoSymbolFile.Write`.
#[derive(Debug, Clone)]
pub struct MdbWriter {
    guid: [u8; 16],
    sources: Vec<String>,
    /// `(primary source id, include-file ids)` per compile unit.
    compile_units: Vec<(u32, Vec<u32>)>,
    methods: Vec<MethodData>,
}

impl MdbWriter {
    /// Creates a builder bound to `guid`, the module guid the resulting file
    /// belongs to (`ModuleVersionId`).
    pub fn new(guid: [u8; 16]) -> Self {
        MdbWriter {
            guid,
            sources: Vec::new(),
            compile_units: Vec::new(),
            methods: Vec::new(),
        }
    }

    /// Registers a source document and returns its 1-based id.
    ///
    /// Paths are deduplicated: registering the same path again returns the
    /// existing id without adding a table row.
    pub fn add_source(&mut self, path: &str) -> u32 {
        if let Some(i) = self.sources.iter().position(|p| p == path) {
            return (i + 1) as u32;
        }
        self.sources.push(path.to_owned());
        self.sources.len() as u32
    }

    /// Defines a compilation unit over `files` and returns its 1-based id.
    ///
    /// `files[0]` is the unit's primary source; any further ids are include
    /// files. An empty slice yields a unit with primary source id 0.
    pub fn add_compile_unit(&mut self, files: &[u32]) -> u32 {
        let primary = files.first().copied().unwrap_or(0);
        self.compile_units.push((primary, files.iter().skip(1).copied().collect()));
        self.compile_units.len() as u32
    }

    /// Adds line-number sequence points for one method.
    ///
    /// Every point in `entries` (IL offset, source line) is attributed to
    /// `source`. Duplicate offsets follow the compiler rule: a later point at
    /// the same IL offset replaces the previous one only when its location
    /// sorts higher, and never produces two rows.
    pub fn add_method_lines(
        &mut self,
        method: Token,
        cu: u32,
        entries: &[(i32, i32)],
        source: u32,
    ) {
        let points: Vec<(i32, i32, u32)> = entries
            .iter()
            .map(|&(offset, line)| (offset, line, source))
            .collect();
        self.mark_sequence_points(method, cu, 0, &points);
    }

    /// Full-form variant of [`MdbWriter::add_method_lines`] where every
    /// point carries its own source-file id, enabling line tables that span
    /// multiple documents, plus an explicit namespace id.
    pub fn mark_sequence_points(
        &mut self,
        method: Token,
        cu: u32,
        namespace_id: i32,
        points: &[(i32, i32, u32)],
    ) {
        let m = match self.methods.iter_mut().find(|m| m.token == method) {
            Some(m) => m,
            None => {
                self.methods.push(MethodData {
                    token: method,
                    compile_unit: cu,
                    namespace_id,
                    lines: Vec::new(),
                    locals: Vec::new(),
                });
                self.methods.last_mut().unwrap()
            }
        };

        // Port of SourceMethodBuilder.MarkSequencePoint: same-offset points
        // never duplicate; they overwrite when they sort higher. Unlike C#,
        // which only compares against the previously appended point (its
        // callers emit non-decreasing offsets), any existing entry with the
        // same offset participates so unsorted caller input dedups too.
        for &(offset, row, file) in points {
            match m.lines.iter_mut().rev().find(|l| l.offset == offset) {
                Some(prev) => {
                    if (row, -1) > (prev.row, prev.column) {
                        *prev = LineEntry {
                            file,
                            row,
                            column: -1,
                            offset,
                        };
                    }
                }
                None => m.lines.push(LineEntry {
                    file,
                    row,
                    column: -1,
                    offset,
                }),
            }
        }
        // CheckLineNumberTable demands non-decreasing offsets; sort stably so
        // finalize stays infallible even for unsorted caller input.
        m.lines.sort_by_key(|l| l.offset);
    }

    /// Attaches a local-variable record to the method registered under
    /// `method`. Fails when no such method exists yet.
    pub fn add_local_variable(
        &mut self,
        method: Token,
        index: i32,
        name: &str,
        block_index: i32,
    ) -> Result<()> {
        match self.methods.iter_mut().find(|m| m.token == method) {
            Some(m) => {
                m.locals.push(LocalVariable {
                    index,
                    name: name.to_owned(),
                    block_index,
                });
                Ok(())
            }
            None => Err(Error::argument(format!(
                "mdb: cannot define local `{name}` on unknown method token {method}"
            ))),
        }
    }

    /// Serializes header, tables and payloads into the final MDB byte stream.
    pub fn finalize(self) -> Vec<u8> {
        let guid = self.guid;
        let sources = self.sources;
        let compile_units = self.compile_units;

        // Methods are stored token-sorted, indices assigned 1..n
        // (MonoSymbolFile.Write).
        let mut methods = self.methods;
        methods.sort_by_key(|m| m.token.0);

        let mut w = ByteWriter::new();

        // Magic number and file version.
        w.u64(MAGIC);
        w.i32(MAJOR_VERSION);
        w.i32(MINOR_VERSION);
        w.bytes(&guid);

        // Reserve the offset table; back-patched below.
        let offset_table_offset = w.position();
        OffsetTable::default().write(&mut w);

        //
        // Data sections: sources, compile units, methods.
        //
        let data_section_offset = w.position() as i32;

        let mut source_data_offsets = vec![0i32; sources.len()];
        for (i, name) in sources.iter().enumerate() {
            source_data_offsets[i] = w.position() as i32;
            write_string(&mut w, name);
            // File guid and checksum: unknown here, stored as zeroes just
            // like SourceFileEntry.WriteData does on checksum failure.
            w.zeros(16);
            w.zeros(16);
            w.u8(0); // auto-generated flag
        }

        let mut unit_data_offsets = vec![0i32; compile_units.len()];
        for (i, (primary, includes)) in compile_units.iter().enumerate() {
            unit_data_offsets[i] = w.position() as i32;
            write_leb128(&mut w, *primary as i32);
            write_leb128(&mut w, includes.len() as i32);
            for inc in includes {
                write_leb128(&mut w, *inc as i32);
            }
            write_leb128(&mut w, 0); // namespace count
        }

        struct FixedMethod {
            token: Token,
            data_offset: i32,
            lnt_offset: i32,
        }
        let mut fixed_methods = Vec::with_capacity(methods.len());
        for m in &methods {
            let local_variable_table_offset = w.position() as i32;
            write_leb128(&mut w, m.locals.len() as i32);
            for local in &m.locals {
                write_leb128(&mut w, local.index);
                write_string(&mut w, &local.name);
                write_leb128(&mut w, local.block_index);
            }

            let code_block_table_offset = w.position() as i32;
            write_leb128(&mut w, 0); // code blocks unsupported through this API

            let scope_variable_table_offset = w.position() as i32;
            write_leb128(&mut w, 0); // scope variables unsupported through this API

            // No real name: RealNameOffset stays 0.
            let flags = FLAGS_COLUMNS_INFO_INCLUDED;
            let line_number_table_offset = w.position() as i32;
            encode_line_number_table(&mut w, &m.lines, flags);

            let data_offset = w.position() as i32;
            write_leb128(&mut w, m.compile_unit as i32);
            write_leb128(&mut w, local_variable_table_offset);
            write_leb128(&mut w, m.namespace_id);
            write_leb128(&mut w, code_block_table_offset);
            write_leb128(&mut w, scope_variable_table_offset);
            write_leb128(&mut w, 0); // real-name offset
            write_leb128(&mut w, flags as i32);

            fixed_methods.push(FixedMethod {
                token: m.token,
                data_offset,
                lnt_offset: line_number_table_offset,
            });
        }
        let data_section_size = w.position() as i32 - data_section_offset;

        //
        // Method index table (12 bytes per row, token-sorted).
        //
        let method_table_offset = w.position() as i32;
        for fm in &fixed_methods {
            w.i32(fm.token.0 as i32);
            w.i32(fm.data_offset);
            w.i32(fm.lnt_offset);
        }
        let method_table_size = w.position() as i32 - method_table_offset;

        //
        // Source table.
        //
        let source_table_offset = w.position() as i32;
        for (i, off) in source_data_offsets.iter().enumerate() {
            w.i32(i as i32 + 1);
            w.i32(*off);
        }
        let source_table_size = w.position() as i32 - source_table_offset;

        //
        // Compile-unit table.
        //
        let compile_unit_table_offset = w.position() as i32;
        for (i, off) in unit_data_offsets.iter().enumerate() {
            w.i32(i as i32 + 1);
            w.i32(*off);
        }
        let compile_unit_table_size = w.position() as i32 - compile_unit_table_offset;

        //
        // Anonymous-scope table (empty through this API).
        //
        let anonymous_scope_table_offset = w.position() as i32;

        //
        // Fixup and rewrite the offset table.
        //
        let total_file_size = w.position() as i32;
        let ot = OffsetTable {
            total_file_size,
            data_section_offset,
            data_section_size,
            compile_unit_count: compile_units.len() as i32,
            compile_unit_table_offset,
            compile_unit_table_size,
            source_count: sources.len() as i32,
            source_table_offset,
            source_table_size,
            method_count: methods.len() as i32,
            method_table_offset,
            method_table_size,
            type_count: 0,
            anonymous_scope_count: 0,
            anonymous_scope_table_offset,
            anonymous_scope_table_size: 0,
            ..OffsetTable::default()
        };
        let fields = [
            ot.total_file_size,
            ot.data_section_offset,
            ot.data_section_size,
            ot.compile_unit_count,
            ot.compile_unit_table_offset,
            ot.compile_unit_table_size,
            ot.source_count,
            ot.source_table_offset,
            ot.source_table_size,
            ot.method_count,
            ot.method_table_offset,
            ot.method_table_size,
            ot.type_count,
            ot.anonymous_scope_count,
            ot.anonymous_scope_table_offset,
            ot.anonymous_scope_table_size,
            ot.line_number_table_line_base,
            ot.line_number_table_line_range,
            ot.line_number_table_opcode_base,
            ot.file_flags,
        ];
        for (k, f) in fields.iter().enumerate() {
            w.patch_u32_at(offset_table_offset + k * 4, *f as u32);
        }

        w.into_vec()
    }
}

/// .NET `BinaryWriter.Write(string)`: 7-bit length prefix + UTF-8 bytes.
fn write_string(w: &mut ByteWriter, s: &str) {
    write_leb128(w, s.len() as i32);
    w.bytes(s.as_bytes());
}

/// .NET `BinaryWriter.Write7BitEncodedInt`.
fn write_leb128(w: &mut ByteWriter, value: i32) {
    let mut v = value as u32;
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        w.u8(b);
        if v == 0 {
            break;
        }
    }
}

/// Encodes a line-number table (port of `LineNumberTable.Write`).
///
/// Uses the default encoding parameters (`LineBase = -1`, `LineRange = 8`,
/// `OpcodeBase = 9`), which are also what the offset table advertises. The
/// source file of each point travels as the `DW_LNS_set_file` operand.
fn encode_line_number_table(w: &mut ByteWriter, lines: &[LineEntry], flags: u32) {
    const LINE_BASE: i32 = -1;
    const LINE_RANGE: i32 = 8;
    const OPCODE_BASE: i32 = 9;
    let max_address_increment = (255 - OPCODE_BASE) / LINE_RANGE;

    let mut last_line: i32 = 1;
    let mut last_offset: i32 = 0;
    let mut last_file: u32 = 1;

    for e in lines {
        let line_inc = e.row - last_line;
        let mut offset_inc = e.offset - last_offset;

        if e.file != last_file {
            w.u8(DW_LNS_SET_FILE);
            write_leb128(w, e.file as i32);
            last_file = e.file;
        }

        // Hidden sequence points are never produced by this writer, so no
        // DW_LNE_MONO_negate_is_hidden transitions are emitted.

        if offset_inc >= max_address_increment {
            if offset_inc < 2 * max_address_increment {
                w.u8(DW_LNS_CONST_ADD_PC);
                offset_inc -= max_address_increment;
            } else {
                w.u8(DW_LNS_ADVANCE_PC);
                write_leb128(w, offset_inc);
                offset_inc = 0;
            }
        }

        if line_inc < LINE_BASE || line_inc >= LINE_BASE + LINE_RANGE {
            w.u8(DW_LNS_ADVANCE_LINE);
            write_leb128(w, line_inc);
            if offset_inc != 0 {
                w.u8(DW_LNS_ADVANCE_PC);
                write_leb128(w, offset_inc);
            }
            w.u8(1); // DW_LNS_copy
        } else {
            let opcode = line_inc - LINE_BASE + LINE_RANGE * offset_inc + OPCODE_BASE;
            w.u8(opcode as u8);
        }

        last_line = e.row;
        last_offset = e.offset;
    }

    w.u8(0);
    w.u8(1);
    w.u8(1); // DW_LNE_end_sequence

    if flags & FLAGS_COLUMNS_INFO_INCLUDED != 0 {
        for e in lines {
            if e.row >= 0 {
                write_leb128(w, e.column);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::MdbReader;

    fn method(table: u8, rid: u32) -> Token {
        Token(((table as u32) << 24) | rid)
    }

    /// Acceptance scenario: 2 sources, 1 compile unit, 3 methods with
    /// interleaved line tables including multiple files per method.
    #[test]
    fn full_roundtrip() {
        let guid = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut w = MdbWriter::new(guid);
        let s1 = w.add_source("src/first.cs");
        let s2 = w.add_source("src/second.cs");
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        let cu = w.add_compile_unit(&[s1, s2]);

        let m1 = method(0x06, 1);
        let m2 = method(0x06, 2);
        let m3 = method(0x06, 3);
        // Register methods out of token order to prove finalize sorts them.
        w.add_method_lines(m1, cu, &[(0, 10), (4, 11), (8, 12)], s1);
        w.mark_sequence_points(
            m2,
            cu,
            0,
            &[(0, 20, s1), (4, 30, s2), (8, 21, s1), (12, 31, s2)],
        );
        w.add_method_lines(m3, cu, &[(0, 40), (2, 41), (100, 42)], s2);

        let bytes = w.finalize();
        let r = MdbReader::open(&bytes).expect("roundtrip file must parse");

        assert_eq!(r.guid(), guid);
        assert_eq!(r.major_version(), MAJOR_VERSION);

        let sources = r.source_files();
        assert_eq!(
            sources,
            vec![
                crate::reader::SourceFileEntry {
                    id: 1,
                    path: "src/first.cs".into(),
                    hash: [0; 16]
                },
                crate::reader::SourceFileEntry {
                    id: 2,
                    path: "src/second.cs".into(),
                    hash: [0; 16]
                },
            ]
        );

        let units = r.compile_units();
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].file_ids, vec![s1, s2]);

        let methods = r.methods();
        assert_eq!(methods.len(), 3);
        assert_eq!(methods[0].row, 1);
        assert_eq!(methods[0].token, m1);
        assert_eq!(methods[1].token, m2);
        assert_eq!(methods[2].token, m3);
        assert!(methods.iter().all(|m| m.compile_unit == cu as u32));

        let l1 = r.method_lines(1).unwrap().unwrap();
        assert_eq!(l1.il_offsets, vec![0, 4, 8]);
        assert_eq!(l1.line_numbers, vec![10, 11, 12]);

        let l2 = r.method_lines(2).unwrap().unwrap();
        assert_eq!(l2.il_offsets, vec![0, 4, 8, 12]);
        assert_eq!(l2.line_numbers, vec![20, 30, 21, 31]);

        let l3 = r.method_lines(3).unwrap().unwrap();
        assert_eq!(l3.il_offsets, vec![0, 2, 100]);
        assert_eq!(l3.line_numbers, vec![40, 41, 42]);

        assert_eq!(r.method_lines(4).unwrap(), None);
    }

    #[test]
    fn source_dedup() {
        let mut w = MdbWriter::new([0; 16]);
        assert_eq!(w.add_source("a.cs"), 1);
        assert_eq!(w.add_source("b.cs"), 2);
        assert_eq!(w.add_source("a.cs"), 1);
        let bytes = w.finalize();
        let r = MdbReader::open(&bytes).unwrap();
        assert_eq!(r.source_files().len(), 2);
    }

    #[test]
    fn locals_roundtrip() {
        let mut w = MdbWriter::new([5; 16]);
        let s = w.add_source("a.cs");
        let cu = w.add_compile_unit(&[s]);
        let m = method(0x06, 7);
        w.add_method_lines(m, cu, &[(0, 1)], s);
        w.add_local_variable(m, 0, "count", 0).unwrap();
        w.add_local_variable(m, 1, "name", 1).unwrap();
        assert!(w.add_local_variable(method(0x06, 8), 0, "x", 0).is_err());

        let bytes = w.finalize();
        let r = MdbReader::open(&bytes).unwrap();
        let locals = r.locals(1).unwrap().unwrap();
        assert_eq!(locals.len(), 2);
        assert_eq!(locals[0].index, 0);
        assert_eq!(locals[0].name, "count");
        assert_eq!(locals[1].block_index, 1);
    }

    #[test]
    fn duplicate_offsets_dedup() {
        let mut w = MdbWriter::new([0; 16]);
        let s = w.add_source("a.cs");
        let cu = w.add_compile_unit(&[s]);
        let m = method(0x06, 1);
        // Same offset twice: higher row wins, only one entry survives.
        w.add_method_lines(m, cu, &[(4, 5), (0, 1), (4, 9)], s);
        let bytes = w.finalize();
        let r = MdbReader::open(&bytes).unwrap();
        let lines = r.method_lines(1).unwrap().unwrap();
        assert_eq!(lines.il_offsets, vec![0, 4]);
        assert_eq!(lines.line_numbers, vec![1, 9]);
    }
}
