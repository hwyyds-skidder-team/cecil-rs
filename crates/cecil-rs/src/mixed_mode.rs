//! Token-preserving editing of PE images containing native code.
//!
//! Native machine code, imports, TLS, relocations, exception tables, vtable
//! fixups and existing RVAs stay in place. Changed managed bodies and metadata
//! are appended in a new section. Existing definitions and signatures retain
//! their tokens. New references/signatures and top-level helper definitions
//! may be appended without changing tokens referenced by native code.

use std::sync::Arc;

use cecil_cil::{Instruction, MethodBody, Operand, OperandType};
use cecil_core::io::{ByteReader, ByteWriter};
use cecil_core::{Error, Result, TableIndex as T, Token};
use cecil_metadata::MetadataReader;

use crate::assembly::{AssemblyNameDefinition, SymbolOutput, WriteParameters};
use crate::model::types::*;
use crate::module_def::Module;

#[path = "mixed_metadata.rs"]
mod metadata;
use metadata::MetadataEditor;

/// Original bytes and model identity retained for a mixed-mode module.
/// The immutable snapshot prevents unsafe edits from silently losing native
/// payload or changing tokens referenced by native code.
#[derive(Debug, Clone, PartialEq)]
pub struct NativeImage {
    bytes: Vec<u8>,
    original: Module,
    assembly: Option<AssemblyNameDefinition>,
    mixed_mode: bool,
}

impl NativeImage {
    /// Original PE bytes, including native sections and any overlay.
    pub fn original_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Module {
    /// Whether this module retains a native image for token-preserving writes.
    pub fn is_mixed_mode(&self) -> bool {
        self.native_image.as_ref().is_some_and(|image| image.mixed_mode)
            || !self.native_method_rvas.is_empty()
            || self.native_entry_point_rva.is_some()
    }

    /// Entry RVA of a native/OPTIL method; these methods have no IL body.
    pub fn native_method_rva(&self, id: MethodId) -> Option<u64> {
        self.native_method_rvas.get(&id).copied()
    }
}

pub(crate) fn capture(
    module: &mut Module,
    image: &cecil_pe::Image,
    md: &MetadataReader<'_>,
    assembly: Option<&AssemblyNameDefinition>,
) -> Result<()> {
    let previous = module.native_image.clone();
    if previous.is_none() {
        module.native_entry_point_rva = image.native_entry_point_rva();
        module.native_method_rvas.clear();
        for rid in 1..=md.row_count(T::MethodDef) {
            let rva = md.column(T::MethodDef, rid, 0)?;
            let code_type = md.column(T::MethodDef, rid, 1)? & 3;
            if rva != 0 && code_type != 0 {
                module.native_method_rvas.insert(MethodId(rid - 1), rva);
            }
        }
    }
    if image.has_native_payload()
        || !module.native_method_rvas.is_empty()
        || module.native_entry_point_rva.is_some()
        || !module.read_diagnostics.is_empty()
        || previous.is_some()
    {
        let mut original = if let Some(previous) = &previous {
            // Loading deferred bodies must not bless edits made to the model
            // since the original read. Only body-resolution state changes.
            let mut original = previous.original.clone();
            // Resolve against the pristine metadata model. The current model
            // can contain injected native/abstract bodies or changed method
            // flags; copying its bodies would silently bless those edits.
            let (_, mut ctx) = crate::read::module_reader::read_module_with_metadata(
                image,
                md,
                &crate::read::context::ReadOptions::default(),
            )?;
            crate::read::instructions::resolve_bodies_opts(
                &mut original,
                &mut ctx,
                md,
                image,
                true,
            )?;
            original
        } else {
            module.clone()
        };
        original.native_image = None;
        original.debug = None;
        original.native_debug = None;
        module.native_image = Some(Arc::new(NativeImage {
            bytes: image.raw().to_vec(),
            original,
            assembly: previous.as_ref().map_or_else(|| assembly.cloned(), |p| p.assembly.clone()),
            mixed_mode: image.has_native_payload()
                || !module.native_method_rvas.is_empty()
                || module.native_entry_point_rva.is_some(),
        }));
    }
    Ok(())
}

fn unsupported(message: &str) -> Error {
    Error::Unsupported(format!("mixed-mode writer: {message}"))
}

struct NameEdit {
    table: T,
    rid: u32,
    column: usize,
    value: String,
}

/// Edits names in the normalized clone so full model comparison catches every
/// unhandled metadata mutation, including token topology and native method flags.
fn normalize_names(current: &mut Module, original: &Module) -> Result<Vec<NameEdit>> {
    let mut edits = Vec::new();
    fn name(edits: &mut Vec<NameEdit>, t: T, rid: usize, col: usize, now: &mut String, old: &str) {
        if now != old {
            edits.push(NameEdit { table: t, rid: rid as u32, column: col, value: now.clone() });
            *now = old.to_string();
        }
    }
    name(&mut edits, T::Module, 1, 1, &mut current.name, &original.name);
    if current.types.len() < original.types.len()
        || current.methods.len() < original.methods.len()
        || current.fields.len() < original.fields.len()
        || current.properties.len() != original.properties.len()
        || current.events.len() != original.events.len()
        || current.generic_parameters.len() != original.generic_parameters.len()
    {
        return Err(unsupported("existing definitions cannot be removed or reordered"));
    }
    for (i, (now, old)) in current.types.iter_mut().zip(&original.types).enumerate() {
        name(&mut edits, T::TypeDef, i + 1, 1, &mut now.name, &old.name);
        name(&mut edits, T::TypeDef, i + 1, 2, &mut now.namespace, &old.namespace);
    }
    for (i, (now, old)) in current.methods.iter_mut().zip(&original.methods).enumerate() {
        name(&mut edits, T::MethodDef, i + 1, 3, &mut now.name, &old.name);
        // Parameter names are normalized separately using actual Param rows.
        if now.parameters.len() != old.parameters.len() {
            return Err(unsupported("changing method parameters is unsupported"));
        }
        now.body = None; // Bodies are checked and encoded separately, including NaN literals.
        for (p, q) in now.parameters.iter_mut().zip(&old.parameters) {
            p.name = q.name.clone();
        }
        now.return_parameter.name = old.return_parameter.name.clone();
    }
    for (i, (now, old)) in current.fields.iter_mut().zip(&original.fields).enumerate() {
        name(&mut edits, T::Field, i + 1, 1, &mut now.name, &old.name);
    }
    for (i, (now, old)) in current.properties.iter_mut().zip(&original.properties).enumerate() {
        name(&mut edits, T::Property, i + 1, 1, &mut now.name, &old.name);
    }
    for (i, (now, old)) in current.events.iter_mut().zip(&original.events).enumerate() {
        name(&mut edits, T::Event, i + 1, 1, &mut now.name, &old.name);
    }
    for (i, (now, old)) in
        current.generic_parameters.iter_mut().zip(&original.generic_parameters).enumerate()
    {
        name(&mut edits, T::GenericParam, i + 1, 3, &mut now.name, &old.name);
    }
    current.guid = original.guid;
    current.debug = None;
    current.native_debug = None;
    current.native_image = None;
    Ok(edits)
}

fn collect_param_names(
    module: &Module,
    original: &Module,
    md: &MetadataReader<'_>,
    names: &mut Vec<NameEdit>,
) -> Result<()> {
    // Match the reader's first-owner policy for overlapping ParamList runs.
    // Each physical row is visited once; repeated hostile ranges cannot make
    // parameter renaming quadratic. Duplicate sequences retain the final row.
    let count = md.row_count(T::Param) as usize;
    let mut next: Vec<usize> = (0..=count).collect();
    fn unclaimed(next: &mut [usize], mut row: usize) -> usize {
        let mut root = row;
        while next[root] != root {
            root = next[root];
        }
        while next[row] != row {
            let parent = next[row];
            next[row] = root;
            row = parent;
        }
        root
    }
    let mut rows = std::collections::HashMap::new();
    for (i, method) in original.methods.iter().enumerate() {
        let start = md.column(T::MethodDef, i as u32 + 1, 5)? as usize;
        let end = if i + 1 < original.methods.len() {
            md.column(T::MethodDef, i as u32 + 2, 5)? as usize
        } else {
            count + 1
        };
        let mut row = unclaimed(&mut next, start.max(1).saturating_sub(1).min(count));
        let limit = end.saturating_sub(1).min(count);
        while row < limit {
            let rid = row as u32 + 1;
            let sequence = md.column(T::Param, rid, 1)? as usize;
            if sequence <= method.parameters.len() {
                rows.insert((i, sequence), rid);
            }
            let following = unclaimed(&mut next, row + 1);
            next[row] = following;
            row = following;
        }
    }
    for (i, (now, old)) in module.methods.iter().zip(&original.methods).enumerate() {
        for (sequence, (a, b)) in
            std::iter::once((&now.return_parameter.name, &old.return_parameter.name))
                .chain(now.parameters.iter().zip(&old.parameters).map(|(a, b)| (&a.name, &b.name)))
                .enumerate()
        {
            if a == b {
                continue;
            }
            let rid = rows.get(&(i, sequence)).copied().ok_or_else(|| {
                unsupported(
                    "naming a parameter without an existing Param row requires a new metadata row",
                )
            })?;
            names.push(NameEdit { table: T::Param, rid, column: 2, value: a.clone() });
        }
    }
    Ok(())
}

fn normalize_constants(current: &mut Module, original: &mut Module) -> Result<()> {
    fn constant(a: &mut Option<ConstantValue>, b: &mut Option<ConstantValue>) -> Result<()> {
        let equal = match (&*a, &*b) {
            (Some(ConstantValue::F32(a)), Some(ConstantValue::F32(b))) => {
                a.to_bits() == b.to_bits()
            }
            (Some(ConstantValue::F64(a)), Some(ConstantValue::F64(b))) => {
                a.to_bits() == b.to_bits()
            }
            (a, b) => a == b,
        };
        if !equal {
            return Err(unsupported("changing metadata constants is unsupported"));
        }
        *a = None;
        *b = None;
        Ok(())
    }
    for (a, b) in current.fields.iter_mut().zip(&mut original.fields) {
        constant(&mut a.constant, &mut b.constant)?;
    }
    for (a, b) in current.properties.iter_mut().zip(&mut original.properties) {
        constant(&mut a.constant, &mut b.constant)?;
    }
    for (a, b) in current.methods.iter_mut().zip(&mut original.methods) {
        constant(&mut a.constant, &mut b.constant)?;
        constant(&mut a.return_parameter.constant, &mut b.return_parameter.constant)?;
        for (a, b) in a.parameters.iter_mut().zip(&mut b.parameters) {
            constant(&mut a.constant, &mut b.constant)?;
        }
    }
    Ok(())
}

struct TokenOperands<'a, 'm> {
    values: Vec<(OperandType, ROperand, Operand)>,
    catches: Vec<(TypeDesc, Token)>,
    metadata: &'a MetadataEditor<'m>,
}

impl TokenOperands<'_, '_> {
    fn operand(&self, kind: OperandType, value: &ROperand, us: &mut Vec<u8>) -> Result<Operand> {
        let matches_kind = match value {
            ROperand::Type(_) => matches!(kind, OperandType::InlineType | OperandType::InlineTok),
            ROperand::Method(_) => {
                matches!(kind, OperandType::InlineMethod | OperandType::InlineTok)
            }
            ROperand::Field(_) => matches!(kind, OperandType::InlineField | OperandType::InlineTok),
            ROperand::CallSite(_) => kind == OperandType::InlineSig,
            ROperand::String(_) | ROperand::UserString(_) => kind == OperandType::InlineString,
            _ => true,
        };
        if !matches_kind {
            return Err(Error::argument("IL operand does not match opcode token kind"));
        }
        if let ROperand::Token(token) = value {
            self.metadata.validate_il_token(kind, *token)?;
        }
        if let Some((_, _, raw)) = self.values.iter().find(|(k, v, _)| *k == kind && v == value) {
            return Ok(raw.clone());
        }
        Ok(match value {
            ROperand::None => Operand::None,
            ROperand::Int8(v) => Operand::Int8(*v),
            ROperand::Int32(v) => Operand::Int32(*v),
            ROperand::Int64(v) => Operand::Int64(*v),
            ROperand::Float32(v) => Operand::Float32(*v),
            ROperand::Float64(v) => Operand::Float64(*v),
            ROperand::Branch(v) => Operand::Branch(*v),
            ROperand::Switch(v) => Operand::Switch(v.clone()),
            ROperand::Var(v) => Operand::Var(*v),
            ROperand::Rva(v) => Operand::Rva(*v),
            ROperand::Type(TypeDesc::Def(id)) => {
                Operand::Token(self.definition_token(T::TypeDef, id.0)?)
            }
            ROperand::Method(MethodRef::Def(id)) => {
                Operand::Token(self.definition_token(T::MethodDef, id.0)?)
            }
            ROperand::Field(FieldRef::Def(id)) => {
                Operand::Token(self.definition_token(T::Field, id.0)?)
            }
            ROperand::Token(token) => {
                let table = token
                    .try_table()
                    .ok_or_else(|| unsupported("new raw operand has unknown token table"))?;
                if token.rid() == 0 || token.rid() > self.metadata.row_count(table) {
                    return Err(unsupported(
                        "new raw operand token references an absent metadata row",
                    ));
                }
                Operand::Token(*token)
            }
            ROperand::UserString(index) => {
                if *index >= 0x0100_0000 || *index as usize >= us.len() {
                    return Err(unsupported(
                        "new user-string operand references an absent heap entry",
                    ));
                }
                let mut reader = ByteReader::new(&us[*index as usize..]);
                let length = reader.compressed_u32()? as usize;
                reader.read_bytes(length)?;
                Operand::UserString(*index)
            }
            ROperand::String(value) => {
                if us.is_empty() {
                    us.push(0);
                }
                let offset = u32::try_from(us.len())
                    .map_err(|_| unsupported("user-string heap is too large"))?;
                if offset >= 0x0100_0000 {
                    return Err(unsupported("user-string heap exceeds token capacity"));
                }
                let mut writer = ByteWriter::new();
                let length = value
                    .encode_utf16()
                    .count()
                    .checked_mul(2)
                    .and_then(|v| v.checked_add(1))
                    .and_then(|v| u32::try_from(v).ok())
                    .filter(|v| *v <= 0x1fff_ffff)
                    .ok_or_else(|| unsupported("user string is too large"))?;
                writer.compressed_u32(length);
                let mut special = false;
                for unit in value.encode_utf16() {
                    special |= unit > 0xff || matches!(unit, 1..=8 | 14..=31 | 39 | 127);
                    writer.u16(unit);
                }
                writer.u8(u8::from(special));
                us.extend_from_slice(writer.as_slice());
                Operand::UserString(offset)
            }
            ROperand::Type(ty) => Operand::Token(self.metadata.type_token(ty)?),
            ROperand::Method(method) => Operand::Token(self.metadata.method(method)?),
            ROperand::Field(field) => Operand::Token(self.metadata.field(field)?),
            ROperand::CallSite(signature) => Operand::Token(self.metadata.call_site(signature)?),
        })
    }

    fn definition_token(&self, table: T, index: u32) -> Result<Token> {
        self.metadata.definition_token(table, index)
    }

    fn catch_token(&self, ty: &TypeDesc) -> Result<Token> {
        if let TypeDesc::Def(id) = ty {
            return self.definition_token(T::TypeDef, id.0);
        }
        self.catches
            .iter()
            .find(|(v, _)| v == ty)
            .map(|(_, token)| *token)
            .or_else(|| {
                self.values.iter().find_map(|(_, operand, raw)| {
                    if operand == &ROperand::Type(ty.clone()) {
                        if let Operand::Token(token) = raw {
                            return Some(*token);
                        }
                    }
                    None
                })
            })
            .map_or_else(|| self.metadata.type_token(ty), Ok)
    }
}

fn encode_body(
    body: &ResolvedBody,
    old: Option<&ResolvedBody>,
    operands: &TokenOperands,
    us: &mut Vec<u8>,
) -> Result<Vec<u8>> {
    let locals_token = if old.is_some_and(|old| body.locals == old.locals) {
        // Preserve old standalone signature and all existing token identities.
        old.unwrap().local_var_sig_tok
    } else {
        operands.metadata.locals(&body.locals)?
    };
    let mut raw = MethodBody {
        max_stack: body.max_stack,
        init_locals: body.init_locals,
        local_var_sig_tok: locals_token,
        ..Default::default()
    };
    for instr in &body.instructions {
        raw.instructions.push(Instruction::new(
            instr.offset,
            instr.opcode,
            operands.operand(instr.opcode.operand_type, &instr.operand, us)?,
        ));
    }
    for handler in &body.exception_handlers {
        let kind = match handler.kind {
            ExceptionKind::Catch => cecil_cil::ExceptionHandlerType::Catch,
            ExceptionKind::Filter => cecil_cil::ExceptionHandlerType::Filter,
            ExceptionKind::Finally => cecil_cil::ExceptionHandlerType::Finally,
            ExceptionKind::Fault => cecil_cil::ExceptionHandlerType::Fault,
        };
        let mut raw_handler = cecil_cil::ExceptionHandler::new(kind);
        raw_handler.try_start = handler.try_offset;
        raw_handler.try_length = handler.try_length;
        raw_handler.handler_start = handler.handler_offset;
        raw_handler.handler_length = handler.handler_length;
        if handler.kind == ExceptionKind::Filter {
            raw_handler.filter_start = Some(handler.filter_offset);
        }
        if handler.kind == ExceptionKind::Catch {
            raw_handler.catch_type = operands.catch_token(
                handler
                    .catch_type
                    .as_ref()
                    .ok_or_else(|| Error::invalid_op("catch handler requires type"))?,
            )?;
        }
        raw.exception_handlers.push(raw_handler);
    }
    cecil_cil::encode_method_body(&raw)
}

fn bodies_equal(a: Option<&ResolvedBody>, b: Option<&ResolvedBody>) -> bool {
    let (Some(a), Some(b)) = (a, b) else {
        return a.is_none() && b.is_none();
    };
    a.max_stack == b.max_stack
        && a.init_locals == b.init_locals
        && a.local_var_sig_tok == b.local_var_sig_tok
        && a.locals == b.locals
        && a.exception_handlers == b.exception_handlers
        && a.instructions.len() == b.instructions.len()
        && a.instructions.iter().zip(&b.instructions).all(|(a, b)| {
            a.offset == b.offset
                && a.opcode == b.opcode
                && match (&a.operand, &b.operand) {
                    (ROperand::Float32(a), ROperand::Float32(b)) => a.to_bits() == b.to_bits(),
                    (ROperand::Float64(a), ROperand::Float64(b)) => a.to_bits() == b.to_bits(),
                    (a, b) => a == b,
                }
        })
}

pub(crate) fn write(
    module: &Module,
    assembly: Option<&AssemblyNameDefinition>,
    entry: Option<MethodId>,
    opts: &WriteParameters,
) -> Result<Vec<u8>> {
    let native =
        module.native_image.as_ref().ok_or_else(|| unsupported("original image is unavailable"))?;
    if opts.strong_name_key.is_some()
        || opts.deterministic_mvid
        || opts.effective_symbol_output() != SymbolOutput::None
    {
        return Err(unsupported(
            "signing, deterministic MVID generation and symbol conversion are unsupported; existing native debug data is preserved",
        ));
    }
    let mut normalized = module.clone();
    let mut names = normalize_names(&mut normalized, &native.original)?;
    let mut baseline = native.original.clone();
    for method in &mut baseline.methods {
        method.body = None;
    }
    // Importing new references appends rows; existing scope identities remain
    // immutable because native machine code can retain their old tokens.
    if !module.assembly_refs.starts_with(&native.original.assembly_refs)
        || !module.module_refs.starts_with(&native.original.module_refs)
    {
        return Err(unsupported(
            "existing assembly/module references cannot be removed, reordered or edited",
        ));
    }
    normalized.assembly_refs.truncate(baseline.assembly_refs.len());
    normalized.module_refs.truncate(baseline.module_refs.len());
    normalized.external_value_types = baseline.external_value_types.clone();
    normalized.types.truncate(baseline.types.len());
    normalized.methods.truncate(baseline.methods.len());
    normalized.fields.truncate(baseline.fields.len());
    normalize_constants(&mut normalized, &mut baseline)?;
    if normalized != baseline {
        return Err(unsupported(
            "unsupported metadata, signature, native-method or PE identity edit",
        ));
    }
    let mut normalized_asm = assembly.cloned();
    if let (Some(now), Some(old)) = (&mut normalized_asm, &native.assembly) {
        if now.name != old.name {
            names.push(NameEdit { table: T::Assembly, rid: 1, column: 7, value: now.name.clone() });
            now.name = old.name.clone();
        }
    }
    if normalized_asm != native.assembly {
        return Err(unsupported("changing assembly identity other than its name is unsupported"));
    }
    let references_changed = module.assembly_refs.len() != native.original.assembly_refs.len()
        || module.module_refs.len() != native.original.module_refs.len()
        || module.types.len() != native.original.types.len()
        || module.methods.len() != native.original.methods.len()
        || module.fields.len() != native.original.fields.len();
    let bodies_changed = module
        .methods
        .iter()
        .zip(&native.original.methods)
        .any(|(a, b)| !bodies_equal(a.body.as_ref(), b.body.as_ref()));
    let parameter_names_changed =
        module.methods.iter().zip(&native.original.methods).any(|(a, b)| {
            a.return_parameter.name != b.return_parameter.name
                || a.parameters.iter().zip(&b.parameters).any(|(a, b)| a.name != b.name)
        });
    let original_entry = if native.original.entry_point_token.table_byte() == T::MethodDef as u8 {
        native
            .original
            .entry_point_token
            .rid()
            .checked_sub(1)
            .map(MethodId)
            .filter(|id| id.index() < native.original.methods.len())
    } else {
        None
    };
    // Preserve malformed-but-readable metadata verbatim: skipped Param rows,
    // absent unused heaps and dangling entry tokens need no normalization.
    if names.is_empty()
        && !bodies_changed
        && !references_changed
        && !parameter_names_changed
        && module.guid == native.original.guid
        && entry == original_entry
        && opts.timestamp.is_none()
    {
        return Ok(native.bytes.clone());
    }
    if !module.read_diagnostics.is_empty() {
        return Err(unsupported(
            "recovered malformed input can only be written byte-identically; its incomplete model cannot be edited safely",
        ));
    }
    let image = cecil_pe::Image::parse(&native.bytes)?;
    if bodies_changed && image.cli_header.managed_native_header_rva != 0 {
        return Err(unsupported(
            "editing IL in a precompiled managed-native image requires rebuilding its native method map",
        ));
    }
    let (rva, size) = image.metadata_rva()?;
    let root = image.rva_bytes(rva, size)?;
    let md = MetadataReader::parse(root)?;
    let header = cecil_metadata::parse_root(root)?;
    if parameter_names_changed {
        collect_param_names(module, &native.original, &md, &mut names)?;
    }
    let mut streams: Vec<(String, Vec<u8>)> = header
        .streams
        .iter()
        .map(|s| Ok((s.name.clone(), cecil_metadata::stream_slice(root, s)?.to_vec())))
        .collect::<Result<_>>()?;
    let stream_index = |name: &str| streams.iter().rposition(|(n, _)| n == name);
    let table_idx = streams
        .iter()
        .rposition(|(n, _)| n == "#-" || n == "#~")
        .ok_or_else(|| Error::bad_image("missing table stream"))?;
    let strings_idx =
        stream_index("#Strings").ok_or_else(|| Error::bad_image("missing #Strings"))?;
    let us_idx = stream_index("#US");
    let guid_idx = stream_index("#GUID");
    let blob_idx = stream_index("#Blob");
    let metadata = MetadataEditor::new(&md, &streams[table_idx].1, module)?;
    metadata.append_module_references(&native.original)?;
    metadata.append_helper_definitions(&native.original)?;
    for edit in &names {
        let index = metadata.intern_string(&edit.value)?;
        metadata.set_cell(edit.table, edit.rid, edit.column, index as u64)?;
    }
    let mut us = us_idx.map_or_else(|| vec![0], |i| streams[i].1.clone());
    let mut operands =
        TokenOperands { values: Vec::new(), catches: Vec::new(), metadata: &metadata };
    for (i, old) in native.original.methods.iter().enumerate() {
        if !bodies_changed {
            break;
        }
        let Some(body) = &old.body else {
            continue;
        };
        let method_rva = md.column(T::MethodDef, i as u32 + 1, 0)?;
        let section = image
            .section_at_virtual_address(method_rva)
            .ok_or_else(|| Error::bad_image("unmapped method body"))?;
        let remaining = (section.size_of_raw_data as u64)
            .checked_sub(method_rva - section.virtual_address as u64)
            .ok_or_else(|| Error::bad_image("method body is not file backed"))?
            as usize;
        let raw = cecil_cil::decode_method_body(image.rva_bytes(method_rva, remaining)?)?.0;
        if body.instructions.len() != raw.instructions.len()
            || body.exception_handlers.len() != raw.exception_handlers.len()
        {
            return Err(Error::bad_image("original IL model differs from body bytes"));
        }
        for (resolved, original) in body.instructions.iter().zip(&raw.instructions) {
            if resolved.opcode != original.opcode {
                return Err(Error::bad_image("original IL model differs from body bytes"));
            }
            if matches!(original.operand, Operand::Token(_) | Operand::UserString(_)) {
                operands.values.push((
                    resolved.opcode.operand_type,
                    resolved.operand.clone(),
                    original.operand.clone(),
                ));
            }
        }
        for (resolved, original) in body.exception_handlers.iter().zip(&raw.exception_handlers) {
            if let Some(ty) = &resolved.catch_type {
                operands.catches.push((ty.clone(), original.catch_type));
            }
        }
    }
    let mut bodies = Vec::new();
    for (i, now) in module.methods.iter().enumerate() {
        let old = native.original.methods.get(i);
        if old.is_some_and(|old| bodies_equal(now.body.as_ref(), old.body.as_ref())) {
            continue;
        }
        if module.native_method_rvas.contains_key(&MethodId(i as u32)) {
            return Err(unsupported("native/OPTIL methods cannot acquire IL bodies"));
        }
        let Some(body) = &now.body else {
            return Err(Error::argument("managed IL method cannot lose its required body"));
        };
        if now.attributes.contains(cecil_core::flags::MethodAttributes::ABSTRACT)
            || now.attributes.contains(cecil_core::flags::MethodAttributes::PINVOKE_IMPL)
            || now.impl_attributes.bits() & 3 != 0
        {
            return Err(Error::argument("only managed IL implementations may receive a body"));
        }
        bodies.push((
            i as u32 + 1,
            encode_body(body, old.and_then(|old| old.body.as_ref()), &operands, &mut us)?,
        ));
    }
    if native.original.native_entry_point_rva.is_some() && entry.is_some() {
        return Err(unsupported("a native entry point cannot be replaced with a managed token"));
    }
    if let Some(id) = entry {
        if id.index() >= module.methods.len() {
            return Err(Error::argument("entry point method is out of range"));
        }
    }
    let metadata_changed = references_changed
        || !names.is_empty()
        || module.guid != native.original.guid
        || !bodies.is_empty()
        || us_idx.is_some_and(|i| us != streams[i].1);
    if metadata_changed
        && (image.cli_header.managed_native_header_rva != 0
            || image.cli_header.managed_native_header_size != 0)
    {
        return Err(unsupported(
            "relocating metadata in a precompiled managed-native image requires rebuilding its native metadata references",
        ));
    }
    let changed = metadata_changed || entry != original_entry || opts.timestamp.is_some();
    if !changed {
        return Ok(native.bytes.clone());
    }
    if image.cli_header.flags & 8 != 0
        || !image.data_directories[cecil_pe::DataDirectoryIndex::Certificate as usize].is_zero()
    {
        return Err(unsupported(
            "editing a signed native image requires re-signing, which is unsupported",
        ));
    }
    let mut out = native.bytes.clone();
    if metadata_changed {
        let layout = cecil_pe::ImageWriter::append_section_layout(&image)?;
        let mut payload = ByteWriter::new();
        for (rid, body) in &bodies {
            payload.align(4);
            let body_rva = layout
                .virtual_address
                .checked_add(
                    u32::try_from(payload.len())
                        .map_err(|_| unsupported("appended code exceeds 4 GiB"))?,
                )
                .ok_or_else(|| unsupported("appended body RVA overflows"))?;
            metadata.set_cell(T::MethodDef, *rid, 0, body_rva as u64)?;
            payload.bytes(body);
        }
        if module.guid != native.original.guid {
            let i = guid_idx.ok_or_else(|| Error::bad_image("missing GUID heap"))?;
            let index = md.column(T::Module, 1, 2)? as usize;
            let at = index
                .checked_sub(1)
                .and_then(|v| v.checked_mul(16))
                .ok_or_else(|| Error::bad_image("invalid MVID GUID index"))?;
            streams[i]
                .1
                .get_mut(at..at + 16)
                .ok_or_else(|| Error::bad_image("MVID extends past GUID heap"))?
                .copy_from_slice(&module.guid);
        }
        let guid_len = guid_idx.map_or(0, |i| streams[i].1.len());
        streams[table_idx].1 = metadata.encode_tables(guid_len)?;
        let (strings, blobs) = metadata.heaps();
        streams[strings_idx].1 = strings;
        if let Some(i) = blob_idx {
            streams[i].1 = blobs;
        } else if blobs.len() > 1 {
            streams.push(("#Blob".to_string(), blobs));
        }
        if let Some(i) = us_idx {
            streams[i].1 = us;
        } else if us.len() > 1 {
            streams.push(("#US".to_string(), us));
        }
        payload.align(4);
        let metadata_rva = layout
            .virtual_address
            .checked_add(
                u32::try_from(payload.len())
                    .map_err(|_| unsupported("appended code exceeds 4 GiB"))?,
            )
            .ok_or_else(|| unsupported("appended metadata RVA overflows"))?;
        let refs: Vec<_> = streams.iter().map(|(n, b)| (n.as_str(), b.as_slice())).collect();
        let mut metadata = cecil_metadata::write_root(&header.version, &refs);
        // Preserve original metadata root format, reserved value and flags.
        metadata[4..12].copy_from_slice(&root[4..12]);
        let version_length = u32::from_le_bytes(root[12..16].try_into().unwrap()) as usize;
        let new_version_length = u32::from_le_bytes(metadata[12..16].try_into().unwrap()) as usize;
        if version_length == new_version_length {
            metadata[16..18 + version_length].copy_from_slice(&root[16..18 + version_length]);
        } else {
            // Rebuilding can normalize harmless runtime-version padding;
            // preserve flags independently of the new physical offset.
            metadata[16 + new_version_length..18 + new_version_length]
                .copy_from_slice(&root[16 + version_length..18 + version_length]);
        }
        payload.bytes(&metadata);
        out = cecil_pe::ImageWriter::append_managed_section(&image, payload.as_slice())?;
        let cli = image.rva_offset(image.cli_directory.virtual_address as u64)?;
        out[cli + 8..cli + 12].copy_from_slice(&metadata_rva.to_le_bytes());
        let metadata_size =
            u32::try_from(metadata.len()).map_err(|_| unsupported("metadata exceeds 4 GiB"))?;
        out[cli + 12..cli + 16].copy_from_slice(&metadata_size.to_le_bytes());
    }
    if entry != original_entry && native.original.native_entry_point_rva.is_none() {
        let cli = image.rva_offset(image.cli_directory.virtual_address as u64)?;
        let token = entry.map_or(Token::NIL, |id| Token::new(T::MethodDef, id.0 + 1));
        out[cli + 20..cli + 24].copy_from_slice(&token.0.to_le_bytes());
    }
    if let Some(timestamp) = opts.timestamp {
        let pe = u32::from_le_bytes(out[0x3c..0x40].try_into().unwrap()) as usize;
        out[pe + 8..pe + 12].copy_from_slice(&timestamp.to_le_bytes());
    }
    Ok(out)
}
