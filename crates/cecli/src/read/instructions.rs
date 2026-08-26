//! IL body resolution (`Mono.Cecil.Cil/CodeReader.cs` port, reader unit R3).
//!
//! [`resolve_bodies`] walks every method of a module in arena order (= metadata
//! table row order) and decodes the IL body pointed to by the method row's RVA
//! into a [`ResolvedBody`]: instructions with fully resolved operands
//! ([`ROperand`] trees), local variable slots parsed from the `StandAloneSig`
//! referenced by the fat header, and exception clauses with their catch types
//! resolved through the TypeDefOrRef space.
//!
//! # Design notes / documented deviations
//!
//! * The function signature carries an extra `md: &cecli_metadata::MetadataReader`
//!   parameter compared to the original three-parameter draft. Locals
//!   (`StandAloneSig` blobs), the per-method RVA (the object model does not
//!   retain it after read) and the context bridges all require direct metadata
//!   access; this deviation is wired up by the caller (module reader /
//!   orchestrator).
//! * `ReadOptions.load_bodies == false` cannot be expressed in the frozen
//!   four-parameter signature; [`resolve_bodies_opts`] accepts the flag
//!   explicitly and becomes a no-op when it is `false`. Plain
//!   [`resolve_bodies`] behaves like `load_bodies == true`.
//! * Malformed branch targets (an absolute target that does not land on an
//!   instruction boundary) do NOT fail resolution. Like Mono.Cecil - whose
//!   `GetInstruction` simply yields `null` and defers the problem to writers -
//!   the decoded instruction keeps its computed absolute target and any error
//!   surfaces when the body is re-encoded. Unresolvable metadata tokens inside
//!   instructions likewise degrade to [`ROperand::Token`] instead of failing
//!   the whole-module read. Structural problems (bad body header, truncated
//!   code stream, unreadable local signature, unresolvable catch type) still
//!   return `Err`, matching Mono.Cecil's throwing behavior.
//! * Each method body is decoded at most once: RVAs already processed are
//!   skipped, which guards against overlapping/cyclic reads when several
//!   method rows share one RVA (e.g. explicit overrides).

use std::collections::HashSet;

use cecli_cil::{parse_body_header, parse_sections, read_code};
use cecli_core::flags::{MethodAttributes, MethodImplAttributes};
use cecli_core::{Error, Result, TableIndex, Token};
use cecli_metadata::MetadataReader;
use cecli_pe::Image;

use crate::model::signature::parse_local_var_sig;
use crate::model::types::{
    ExceptionHandlerIL, ExceptionKind, FieldRef, LocalVariable, MethodDefinition, MethodRef,
    ResolvedBody, RInstruction, ROperand,
};
use crate::read::context::{MemberRefRow, ReadContext};
use crate::Module;

/// Resolves the IL bodies of every method with managed IL code.
///
/// See the [module documentation](self) for the exact semantics and the
/// documented deviations from the original draft contract.
pub fn resolve_bodies(
    module: &mut Module,
    ctx: &mut ReadContext,
    md: &MetadataReader<'_>,
    image: &Image,
) -> Result<()> {
    resolve_bodies_opts(module, ctx, md, image, true)
}

/// Same as [`resolve_bodies`] with an explicit `load_bodies` switch mirroring
/// `ReadOptions::load_bodies`; a `false` value makes the call a no-op.
pub fn resolve_bodies_opts(
    module: &mut Module,
    ctx: &mut ReadContext,
    md: &MetadataReader<'_>,
    image: &Image,
    load_bodies: bool,
) -> Result<()> {
    if !load_bodies {
        return Ok(());
    }

    let mut visited_rvas: HashSet<u64> = HashSet::new();
    for index in 0..module.methods.len() {
        // Arena order == MethodDef table row order; the RVA is read straight
        // from the metadata row (column 0), the object model does not keep it.
        let rid = (index + 1) as u32;
        let rva = md.column(TableIndex::MethodDef, rid, 0)? as u64;
        let Some(rva) = il_body_rva(rva, &module.methods[index]) else {
            continue;
        };
        // Guard against overlapping/cyclic reads: each body is decoded once.
        if !visited_rvas.insert(rva) {
            continue;
        }
        let code = image.rva(rva)?;
        let body = decode_resolved_body(&code, ctx, md)?;
        capture_sas_blobs(&body, ctx);
        module.methods[index].body = Some(body);
    }
    // Hand the captured `calli` signature blobs to the object model so the
    // writer can reach them after the read context is gone.
    module.sas_blobs = std::mem::take(&mut ctx.sas_blobs);
    Ok(())
}

/// Returns `Some(rva)` when the method carries a decodable managed IL body:
/// non-zero RVA, not abstract, no P/Invoke, IL implemented (not
/// native/runtime).
fn il_body_rva(rva: u64, method: &MethodDefinition) -> Option<u64> {
    if rva == 0 {
        return None;
    }
    if method.attributes.contains(MethodAttributes::ABSTRACT)
        || method.attributes.contains(MethodAttributes::PINVOKE_IMPL)
        || method.pinvoke.is_some()
    {
        return None;
    }
    let code_type = method.impl_attributes & MethodImplAttributes::CODE_TYPE_MASK;
    if code_type == MethodImplAttributes::NATIVE || code_type == MethodImplAttributes::RUNTIME {
        return None;
    }
    Some(rva)
}

/// Decodes one method body image (header + code + optional exception sections)
/// into a resolved body using the module's token maps and metadata.
fn decode_resolved_body(
    code: &[u8],
    ctx: &ReadContext,
    md: &MetadataReader<'_>,
) -> Result<ResolvedBody> {
    let header = parse_body_header(code)?;
    let header_len = if header.fat { 12usize } else { 1usize };
    // `code` is the whole body image; the IL stream starts past the header
    // (mirrors the `data[code_start..code_end]` slicing in cecli-cil).
    let instructions = read_code(&code[header_len..], header.code_size as usize)?;

    let mut rinstructions = Vec::with_capacity(instructions.len());
    for ins in instructions {
        let operand = match ins.opcode.operand_type {
            cecli_cil::OperandType::InlineTok
            | cecli_cil::OperandType::InlineType
            | cecli_cil::OperandType::InlineMethod
            | cecli_cil::OperandType::InlineField => resolve_token(ctx, md, token_of(&ins.operand)),
            // `calli`: the StandAloneSig token stays raw; its blob bytes are
            // captured by [`capture_sas_blobs`] for write-side remapping.
            cecli_cil::OperandType::InlineSig => ROperand::Token(token_of(&ins.operand)),
            cecli_cil::OperandType::InlineString => resolve_user_string(ctx, md, &ins.operand),
            _ => plain_operand(ins.operand),
        };
        rinstructions.push(RInstruction {
            offset: ins.offset,
            opcode: ins.opcode,
            operand,
        });
    }

    let locals = decode_locals(header.locals_token, ctx, md)?;

    let mut exception_handlers = Vec::new();
    if header.more_sects {
        let sections_offset = align4(header_len + header.code_size as usize);
        let sections = code
            .get(sections_offset..)
            .ok_or_else(|| Error::bad_image("exception section starts past end of body"))?;
        let (handlers, _more) = parse_sections(sections)?;
        exception_handlers.reserve(handlers.len());
        for handler in handlers {
            let kind = match handler.handler_type {
                cecli_cil::ExceptionHandlerType::Catch => ExceptionKind::Catch,
                cecli_cil::ExceptionHandlerType::Filter => ExceptionKind::Filter,
                cecli_cil::ExceptionHandlerType::Finally => ExceptionKind::Finally,
                cecli_cil::ExceptionHandlerType::Fault => ExceptionKind::Fault,
            };
            // filter_offset is only meaningful for Filter clauses; preserved
            // verbatim there, zero otherwise.
            let filter_offset = handler.filter_start.unwrap_or(0);
            let catch_type = match kind {
                ExceptionKind::Catch if handler.catch_type != Token::NIL => {
                    Some(ctx.tdor_to_typedesc(md, tdor_cell(handler.catch_type))?)
                }
                _ => None,
            };
            exception_handlers.push(ExceptionHandlerIL {
                kind,
                try_offset: handler.try_start,
                try_length: handler.try_length,
                filter_offset,
                handler_offset: handler.handler_start,
                handler_length: handler.handler_length,
                catch_type,
            });
        }
    }

    Ok(ResolvedBody {
        max_stack: header.max_stack,
        init_locals: header.init_locals,
        local_var_sig_tok: header.locals_token,
        locals,
        instructions: rinstructions,
        exception_handlers,
    })
}

/// Extracts the raw token out of a decoded cil operand; every variant reaching
/// this helper carries a `Token` payload (guaranteed by the operand-type
/// dispatch in [`decode_resolved_body`]).
fn token_of(operand: &cecli_cil::Operand) -> Token {
    match operand {
        cecli_cil::Operand::Token(t) => *t,
        _ => Token::NIL,
    }
}

/// Maps operand kinds that translate 1:1 between the two models.
///
/// Branch and switch operands already hold absolute IL offsets; var operands
/// hold the raw slot index (arguments and locals share the representation).
fn plain_operand(operand: cecli_cil::Operand) -> ROperand {
    match operand {
        cecli_cil::Operand::None => ROperand::None,
        cecli_cil::Operand::Int8(v) => ROperand::Int8(v),
        cecli_cil::Operand::Int32(v) => ROperand::Int32(v),
        cecli_cil::Operand::Int64(v) => ROperand::Int64(v),
        cecli_cil::Operand::Float32(v) => ROperand::Float32(v),
        cecli_cil::Operand::Float64(v) => ROperand::Float64(v),
        cecli_cil::Operand::Branch(v) => ROperand::Branch(v),
        cecli_cil::Operand::Switch(v) => ROperand::Switch(v),
        cecli_cil::Operand::Var(v) => ROperand::Var(v),
        cecli_cil::Operand::UserString(idx) => ROperand::UserString(idx),
        cecli_cil::Operand::Token(t) => ROperand::Token(t),
        cecli_cil::Operand::Rva(v) => ROperand::Rva(v),
    }
}

/// Decodes an `ldstr` user-string reference into a resolved string through the
/// read context. An undecodable heap offset keeps the raw index
/// ([`ROperand::UserString`]) instead of failing the module read.
fn resolve_user_string(
    ctx: &ReadContext,
    md: &MetadataReader<'_>,
    operand: &cecli_cil::Operand,
) -> ROperand {
    match operand {
        cecli_cil::Operand::UserString(idx) => match ctx.user_string_at(md, *idx) {
            Ok(s) => ROperand::String(s),
            Err(_) => ROperand::UserString(*idx),
        },
        _ => ROperand::None,
    }
}

/// Encodes a TypeDef/TypeRef/TypeSpec token into its TypeDefOrRef coded cell
/// (`(rid << 2) | tag`, matching `cecli_core::coded::TYPE_DEF_OR_REF`).
fn tdor_cell(token: Token) -> u32 {
    let tag = match token.table() {
        TableIndex::TypeDef => 0u32,
        TableIndex::TypeRef => 1,
        TableIndex::TypeSpec => 2,
        _ => 3,
    };
    (token.rid() << 2) | tag
}

/// Resolves a metadata token found in an instruction operand into an
/// [`ROperand`], dispatched by the token's table:
///
/// * TypeDef/TypeRef/TypeSpec -> [`ROperand::Type`] (via
///   [`ReadContext::tdor_to_typedesc`], covering `TypeSpec` rows too)
/// * MethodDef -> [`MethodRef::Def`] over the arena handle map
/// * MemberRef -> the pre-resolved row ([`ReadContext::resolve_member_ref`])
/// * MethodSpec -> generic instantiation ([`ReadContext::method_spec_ref`])
/// * anything else (e.g. `calli` signatures) -> [`ROperand::Token`]
///
/// Per the module-level deferred-resolution policy, tokens that cannot be
/// resolved come back as [`ROperand::Token`] instead of an error.
fn resolve_token(ctx: &ReadContext, md: &MetadataReader<'_>, token: Token) -> ROperand {
    if token == Token::NIL {
        return ROperand::Token(token);
    }
    match token.table() {
        TableIndex::TypeDef | TableIndex::TypeRef | TableIndex::TypeSpec => {
            match ctx.tdor_to_typedesc(md, tdor_cell(token)) {
                Ok(ty) => ROperand::Type(ty),
                Err(_) => ROperand::Token(token),
            }
        }
        TableIndex::MethodDef => match ctx.method_defs.get((token.rid() - 1) as usize) {
            Some(id) => ROperand::Method(MethodRef::Def(*id)),
            None => ROperand::Token(token),
        },
        TableIndex::Field => match ctx.field_defs.get((token.rid() - 1) as usize) {
            Some(id) => ROperand::Field(FieldRef::Def(*id)),
            None => ROperand::Token(token),
        },
        TableIndex::MemberRef => match ctx.resolve_member_ref(md, token.rid()) {
            Ok(MemberRefRow::Method(em)) => ROperand::Method(MethodRef::External(em)),
            Ok(MemberRefRow::Field(ef)) => ROperand::Field(FieldRef::External(ef)),
            Ok(MemberRefRow::Spec(mr)) => ROperand::Method(mr),
            _ => ROperand::Token(token),
        },
        TableIndex::MethodSpec => match ctx.method_spec_ref(md, token.rid()) {
            Ok(mr) => ROperand::Method(mr),
            Err(_) => ROperand::Token(token),
        },
        _ => ROperand::Token(token),
    }
}

/// Parses the `StandAloneSig` local-variable signature referenced by the body
/// header into typed local slots. A `NIL` token means "no locals".
fn decode_locals(
    locals_token: Token,
    ctx: &ReadContext,
    md: &MetadataReader<'_>,
) -> Result<Vec<LocalVariable>> {
    if locals_token == Token::NIL {
        return Ok(Vec::new());
    }
    if locals_token.table() != TableIndex::StandAloneSig {
        return Err(Error::bad_image(format!(
            "local var sig token {locals_token:?} does not reference StandAloneSig"
        )));
    }
    let blob_idx = md.column(TableIndex::StandAloneSig, locals_token.rid(), 0)? as u32;
    let blob = md.heaps().blob.get(blob_idx)?;
    let sig_ctx = ctx.sig_context(md);
    parse_local_var_sig(blob, &sig_ctx)
}

/// Rounds `value` up to the next 4-byte boundary (exception sections start
/// aligned relative to the beginning of the method body).
fn align4(value: usize) -> usize {
    (value + 3) & !3
}

/// Captures the raw `StandAloneSig` blobs referenced by `calli` operands
/// ([`ROperand::Token`] over the `StandAloneSig` table) into
/// [`ReadContext::sas_blobs`], keyed by the original rid. The writer later
/// re-emits these through its own deduplicated `StandAloneSig` rows; rids
/// missing from [`ReadContext::stand_alone_sigs`] are skipped per the
/// module-level deferred-resolution policy.
fn capture_sas_blobs(body: &ResolvedBody, ctx: &mut ReadContext) {
    for ins in &body.instructions {
        if ins.opcode.operand_type != cecli_cil::OperandType::InlineSig {
            continue;
        }
        let ROperand::Token(token) = &ins.operand else {
            continue;
        };
        let rid = token.rid();
        if token.table() != TableIndex::StandAloneSig
            || rid == 0
            || ctx.sas_blobs.contains_key(&rid)
        {
            continue;
        }
        if let Some(blob) = ctx.stand_alone_sigs.get((rid - 1) as usize) {
            ctx.sas_blobs.insert(rid, blob.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use cecli_cil::opcodes;
    use cecli_core::io::ByteWriter;
    use cecli_core::{TableIndex, Token};
    use cecli_metadata::builder::MetadataBuilder;
    use cecli_metadata::MetadataReader;

    use super::*;
    use crate::model::types::{ExternalMethod, ExternalType, TypeDesc};

    /// Builds an in-memory metadata root carrying a `StandAloneSig` locals
    /// signature (int32 + object), one `TypeRef` (`System.Exception`) and the
    /// `Hello` user string. Returns the parsed reader plus the `#US` offset
    /// of `Hello`.
    fn test_metadata() -> (MetadataReader<'static>, u32) {
        let mut builder = MetadataBuilder::new("v4.0.30319");
        let us_hello = builder.insert_user_string("Hello");
        let sig_blob = builder.insert_blob(&[0x07, 0x02, 0x08, 0x1C]);
        builder.add_row(TableIndex::StandAloneSig, &[sig_blob as u64]).expect("sas row");
        let name = builder.insert_string("Exception");
        builder.add_row(TableIndex::TypeRef, &[0, name as u64, 0]).expect("typeref row");
        let bytes: &'static [u8] = Box::leak(builder.finalize().into_boxed_slice());
        (MetadataReader::parse(bytes).expect("parse metadata"), us_hello)
    }

    /// Synthetic read context: one external member reference
    /// (`System.Object.ToString()`) in the member-ref cache.
    fn test_ctx() -> ReadContext {
        let parent = ExternalType {
            namespace: "System".into(),
            name: "Object".into(),
            nesting: Vec::new(),
            scope: crate::model::types::ScopeRef::ThisModule,
        };
        let em = ExternalMethod {
            parent: TypeDesc::External(Box::new(parent)),
            name: "ToString".into(),
            signature: Default::default(),
        };
        ReadContext {
            member_refs: vec![MemberRefRow::Method(em)],
            ..Default::default()
        }
    }
    /// Handcrafted tiny body:
    /// `IL_0000 ldstr`, `IL_0005 switch(2)`, `IL_0012 br.s`,
    /// `IL_0014 callvirt`, `IL_0019 ret` - asserts the full resolved
    /// operand tree with exact offsets preserved.
    #[test]
    fn tiny_body_full_operand_tree() {
        let (md, us_hello) = test_metadata();
        let ctx = test_ctx();

        let mut w = ByteWriter::new();
        w.u8(opcodes::LDSTR.byte2); // IL_0000: ldstr <us>
        w.u32(0x7000_0000 | us_hello);
        w.u8(opcodes::SWITCH.byte2); // IL_0005: switch (count, d1, d2)
        w.i32(2);
        w.i32(0);  // -> IL_0012 (base 18 + 0)
        w.i32(7);  // -> IL_0019 (base 18 + 7)
        w.u8(opcodes::BR_S.byte2); // IL_0012: br.s +5 -> IL_0019
        w.i8(5);
        w.u8(opcodes::CALLVIRT.byte2); // IL_0014: callvirt <memberref>
        w.u32(0x0A00_0001);
        w.u8(opcodes::RET.byte2); // IL_0019: ret
        let mut body_bytes = ByteWriter::new();
        body_bytes.u8(((26u32 << 2) | 0x2) as u8); // tiny header, code size 26
        body_bytes.bytes(&w.into_vec());
        let code: &[u8] = &body_bytes.into_vec();

        let body = decode_resolved_body(code, &ctx, &md).expect("decode");

        assert_eq!(body.max_stack, 8);
        assert!(!body.init_locals);
        assert_eq!(body.local_var_sig_tok, Token::NIL);
        assert!(body.locals.is_empty());
        assert_eq!(body.instructions.len(), 5);
        for (ins, expected_offset) in body.instructions.iter().zip([0i32, 5, 18, 20, 25]) {
            assert_eq!(ins.offset, expected_offset, "offsets must be preserved");
        }

        let em_parent = ExternalType {
            namespace: "System".into(),
            name: "Object".into(),
            nesting: Vec::new(),
            scope: crate::model::types::ScopeRef::ThisModule,
        };
        let expected_em = ExternalMethod {
            parent: TypeDesc::External(Box::new(em_parent)),
            name: "ToString".into(),
            signature: Default::default(),
        };
        assert_eq!(body.instructions[1].operand, ROperand::Switch(vec![18, 25]));
        assert_eq!(body.instructions[2].operand, ROperand::Branch(25));
        assert_eq!(
            body.instructions[3].operand,
            ROperand::Method(MethodRef::External(expected_em))
        );
        assert_eq!(body.instructions[4].operand, ROperand::None);
    }

    /// Fat body with `init_locals`, a locals signature and a small exception
    /// section holding one `catch` and one `finally` clause.
    #[test]
    fn fat_body_locals_and_exception_handlers() {
        let (md, _us) = test_metadata();
        let ctx = test_ctx();

        let mut code = ByteWriter::new();
        // Header: fat | more_sects | init_locals, maxstack 1, 4 bytes code,
        // locals token -> StandAloneSig rid 1.
        code.u16(0x0003 | 0x0008 | 0x0010);
        code.u16(1);
        code.u32(4);
        code.u32(0x1100_0001);
        // IL_0000 ldc.i4.5; IL_0001 stloc.0; IL_0002 ldloc.0; IL_0003 ret
        // (12 + 4 == 16, already 4-aligned: no padding before the section).
        code.bytes(&[0x17, 0x0A, 0x06, 0x2A]);
        // Small EH section: eh_table flag, data size 4 + 2*12, 2 pad bytes.
        code.u8(0x01);
        code.u8(28);
        code.u16(0);
        // Clause A: catch System.Exception over [0,2) handler [2,2).
        code.u16(0); // kind = Catch
        code.u16(0); // try offset
        code.u8(2); // try length
        code.u16(2); // handler offset
        code.u8(2); // handler length
        code.u32(0x0100_0001); // TypeRef rid 1
        // Clause B: finally over [0,2) handler [4,4).
        code.u16(2); // kind = Finally
        code.u16(0);
        code.u8(2);
        code.u16(4);
        code.u8(4);
        code.u32(0);

        let body = decode_resolved_body(code.into_vec().as_slice(), &ctx, &md).expect("decode");

        assert_eq!(body.max_stack, 1);
        assert!(body.init_locals);
        assert_eq!(body.local_var_sig_tok, Token::new(TableIndex::StandAloneSig, 1));
        assert_eq!(body.locals.len(), 2);
        assert_eq!(body.locals[0].index, 0);
        assert_eq!(body.locals[0].ty, TypeDesc::Internal("int32".into()));
        assert!(!body.locals[0].pinned);
        assert_eq!(body.locals[1].ty, TypeDesc::Internal("object".into()));

        assert_eq!(body.exception_handlers.len(), 2);
        let catch = &body.exception_handlers[0];
        assert_eq!(catch.kind, ExceptionKind::Catch);
        assert_eq!(catch.try_offset, 0);
        assert_eq!(catch.try_length, 2);
        assert_eq!(catch.handler_offset, 2);
        assert_eq!(catch.handler_length, 2);
        assert_eq!(catch.filter_offset, 0);
        match &catch.catch_type {
            Some(TypeDesc::External(et)) => assert_eq!(et.name, "Exception"),
            other => panic!("expected resolved catch type, got {other:?}"),
        }
        let fin = &body.exception_handlers[1];
        assert_eq!(fin.kind, ExceptionKind::Finally);
        assert_eq!(fin.catch_type, None);
        assert_eq!(fin.handler_offset, 4);
    }

    /// Documented deferred-error policy: a branch target that does not land
    /// on an instruction boundary still decodes - the absolute target is kept
    /// verbatim and validation is deferred to re-encode time.
    #[test]
    fn malformed_branch_target_is_deferred() {
        let (md, _us) = test_metadata();
        let ctx = test_ctx();

        let mut w = ByteWriter::new();
        w.u8(((2u32 << 2) | 0x2) as u8); // tiny header, code size 2
        w.u8(opcodes::BR_S.byte2); // IL_0000: br.s +100 -> IL_0066
        w.i8(100);

        let body = decode_resolved_body(w.into_vec().as_slice(), &ctx, &md).expect("decode");
        assert_eq!(body.instructions.len(), 1);
        assert_eq!(body.instructions[0].offset, 0);
        assert_eq!(body.instructions[0].operand, ROperand::Branch(102));
    }

    /// Only managed IL bodies are decoded: abstract, P/Invoke, native and
    /// runtime-implemented methods (and zero RVAs) are skipped.
    #[test]
    fn il_body_rva_skip_rules() {
        use crate::model::types::{MethodDefinition, PInvokeInfo};

        let mut m = MethodDefinition::default();
        assert_eq!(il_body_rva(0x2000, &m), Some(0x2000));

        m.attributes |= MethodAttributes::ABSTRACT;
        assert_eq!(il_body_rva(0x2000, &m), None);
        m.attributes -= MethodAttributes::ABSTRACT;

        m.impl_attributes |= MethodImplAttributes::NATIVE;
        assert_eq!(il_body_rva(0x2000, &m), None);
        m.impl_attributes -= MethodImplAttributes::NATIVE;

        m.impl_attributes |= MethodImplAttributes::RUNTIME;
        assert_eq!(il_body_rva(0x2000, &m), None);
        m.impl_attributes -= MethodImplAttributes::RUNTIME;

        assert_eq!(il_body_rva(0x2000, &m), Some(0x2000));

        m.pinvoke = Some(PInvokeInfo {
            attributes: Default::default(),
            entry_point: String::new(),
            module: String::new(),
        });
        assert_eq!(il_body_rva(0x2000, &m), None);

        assert_eq!(il_body_rva(0, &m), None);
    }

}