//! The complete CIL opcode table, ported 1:1 from `Mono.Cecil.Cil/OpCodes.cs`.
//!
//! Constants are named exactly like the C# fields (upper-cased), e.g.
//! [`LDARG_0`], [`LDC_I4_S`], [`BR_S`], [`CONV_U`]. Every entry carries the
//! exact byte encoding: single-byte instructions use prefix `0xFF`,
//! two-byte instructions the `0xFE` escape prefix.

use crate::code::Code;
use crate::opcode::{OpCode, OperandType};

macro_rules! single_byte {
    ($(($name:ident, $code:ident, $m:expr, $b2:expr, $ot:ident)),* $(,)?) => {
        $(
            /// Single-byte CIL opcode.
            pub const $name: OpCode = OpCode::new(Code::$code, $m, 0xFF, $b2, OperandType::$ot);
        )*
    };
}

macro_rules! two_byte {
    ($(($name:ident, $code:ident, $m:expr, $b2:expr, $ot:ident)),* $(,)?) => {
        $(
            /// Two-byte (`0xFE`-prefixed) CIL opcode.
            pub const $name: OpCode = OpCode::new(Code::$code, $m, 0xFE, $b2, OperandType::$ot);
        )*
    };
}

macro_rules! one_byte_entry {
    ($table:ident, $name:ident, 0xFF, $b2:expr) => {
        $table[$b2 as usize] = Some(&$name);
    };
    ($table:ident, $name:ident, 0xFE, $b2:expr) => {};
}

macro_rules! two_byte_entry {
    ($table:ident, $name:ident, 0xFF, $b2:expr) => {};
    ($table:ident, $name:ident, 0xFE, $b2:expr) => {
        $table[$b2 as usize] = Some(&$name);
    };
}

macro_rules! all_opcodes {
    ($(($name:ident, $code:ident, $m:expr, $b1:tt, $b2:expr, $ot:ident)),* $(,)?) => {
        /// Every opcode defined by ECMA-335 partition III, in encoding order
        /// (single-byte instructions by ascending second byte, then the
        /// `0xFE`-prefixed ones). 191 + 28 = 219 entries, matching
        /// `Mono.Cecil.Cil/OpCodes.cs`.
        pub static ALL: &[OpCode] = &[$($name),*];

        /// Single-byte decode table indexed by the instruction byte.
        pub const ONE_BYTE: [Option<&'static OpCode>; 0x100] = {
            let mut table = [None; 0x100];
            $(one_byte_entry!(table, $name, $b1, $b2);)*
            table
        };

        /// Two-byte decode table indexed by the byte following `0xFE`.
        pub const TWO_BYTE: [Option<&'static OpCode>; 0x20] = {
            let mut table = [None; 0x20];
            $(two_byte_entry!(table, $name, $b1, $b2);)*
            table
        };
    };
}

single_byte! {
    (NOP, Nop, "nop", 0x00, InlineNone),
    (BREAK, Break, "break", 0x01, InlineNone),
    (LDARG_0, Ldarg_0, "ldarg.0", 0x02, InlineNone),
    (LDARG_1, Ldarg_1, "ldarg.1", 0x03, InlineNone),
    (LDARG_2, Ldarg_2, "ldarg.2", 0x04, InlineNone),
    (LDARG_3, Ldarg_3, "ldarg.3", 0x05, InlineNone),
    (LDLOC_0, Ldloc_0, "ldloc.0", 0x06, InlineNone),
    (LDLOC_1, Ldloc_1, "ldloc.1", 0x07, InlineNone),
    (LDLOC_2, Ldloc_2, "ldloc.2", 0x08, InlineNone),
    (LDLOC_3, Ldloc_3, "ldloc.3", 0x09, InlineNone),
    (STLOC_0, Stloc_0, "stloc.0", 0x0a, InlineNone),
    (STLOC_1, Stloc_1, "stloc.1", 0x0b, InlineNone),
    (STLOC_2, Stloc_2, "stloc.2", 0x0c, InlineNone),
    (STLOC_3, Stloc_3, "stloc.3", 0x0d, InlineNone),
    (LDARG_S, Ldarg_S, "ldarg.s", 0x0e, ShortInlineArg),
    (LDARGA_S, Ldarga_S, "ldarga.s", 0x0f, ShortInlineArg),
    (STARG_S, Starg_S, "starg.s", 0x10, ShortInlineArg),
    (LDLOC_S, Ldloc_S, "ldloc.s", 0x11, ShortInlineVar),
    (LDLOCA_S, Ldloca_S, "ldloca.s", 0x12, ShortInlineVar),
    (STLOC_S, Stloc_S, "stloc.s", 0x13, ShortInlineVar),
    (LDNULL, Ldnull, "ldnull", 0x14, InlineNone),
    (LDC_I4_M1, Ldc_I4_M1, "ldc.i4.m1", 0x15, InlineNone),
    (LDC_I4_0, Ldc_I4_0, "ldc.i4.0", 0x16, InlineNone),
    (LDC_I4_1, Ldc_I4_1, "ldc.i4.1", 0x17, InlineNone),
    (LDC_I4_2, Ldc_I4_2, "ldc.i4.2", 0x18, InlineNone),
    (LDC_I4_3, Ldc_I4_3, "ldc.i4.3", 0x19, InlineNone),
    (LDC_I4_4, Ldc_I4_4, "ldc.i4.4", 0x1a, InlineNone),
    (LDC_I4_5, Ldc_I4_5, "ldc.i4.5", 0x1b, InlineNone),
    (LDC_I4_6, Ldc_I4_6, "ldc.i4.6", 0x1c, InlineNone),
    (LDC_I4_7, Ldc_I4_7, "ldc.i4.7", 0x1d, InlineNone),
    (LDC_I4_8, Ldc_I4_8, "ldc.i4.8", 0x1e, InlineNone),
    (LDC_I4_S, Ldc_I4_S, "ldc.i4.s", 0x1f, ShortInlineI),
    (LDC_I4, Ldc_I4, "ldc.i4", 0x20, InlineI),
    (LDC_I8, Ldc_I8, "ldc.i8", 0x21, InlineI8),
    (LDC_R4, Ldc_R4, "ldc.r4", 0x22, ShortInlineR),
    (LDC_R8, Ldc_R8, "ldc.r8", 0x23, InlineR),
    (DUP, Dup, "dup", 0x25, InlineNone),
    (POP, Pop, "pop", 0x26, InlineNone),
    (JMP, Jmp, "jmp", 0x27, InlineMethod),
    (CALL, Call, "call", 0x28, InlineMethod),
    (CALLI, Calli, "calli", 0x29, InlineSig),
    (RET, Ret, "ret", 0x2a, InlineNone),
    (BR_S, Br_S, "br.s", 0x2b, ShortInlineBrTarget),
    (BRFALSE_S, Brfalse_S, "brfalse.s", 0x2c, ShortInlineBrTarget),
    (BRTRUE_S, Brtrue_S, "brtrue.s", 0x2d, ShortInlineBrTarget),
    (BEQ_S, Beq_S, "beq.s", 0x2e, ShortInlineBrTarget),
    (BGE_S, Bge_S, "bge.s", 0x2f, ShortInlineBrTarget),
    (BGT_S, Bgt_S, "bgt.s", 0x30, ShortInlineBrTarget),
    (BLE_S, Ble_S, "ble.s", 0x31, ShortInlineBrTarget),
    (BLT_S, Blt_S, "blt.s", 0x32, ShortInlineBrTarget),
    (BNE_UN_S, Bne_Un_S, "bne.un.s", 0x33, ShortInlineBrTarget),
    (BGE_UN_S, Bge_Un_S, "bge.un.s", 0x34, ShortInlineBrTarget),
    (BGT_UN_S, Bgt_Un_S, "bgt.un.s", 0x35, ShortInlineBrTarget),
    (BLE_UN_S, Ble_Un_S, "ble.un.s", 0x36, ShortInlineBrTarget),
    (BLT_UN_S, Blt_Un_S, "blt.un.s", 0x37, ShortInlineBrTarget),
    (BR, Br, "br", 0x38, InlineBrTarget),
    (BRFALSE, Brfalse, "brfalse", 0x39, InlineBrTarget),
    (BRTRUE, Brtrue, "brtrue", 0x3a, InlineBrTarget),
    (BEQ, Beq, "beq", 0x3b, InlineBrTarget),
    (BGE, Bge, "bge", 0x3c, InlineBrTarget),
    (BGT, Bgt, "bgt", 0x3d, InlineBrTarget),
    (BLE, Ble, "ble", 0x3e, InlineBrTarget),
    (BLT, Blt, "blt", 0x3f, InlineBrTarget),
    (BNE_UN, Bne_Un, "bne.un", 0x40, InlineBrTarget),
    (BGE_UN, Bge_Un, "bge.un", 0x41, InlineBrTarget),
    (BGT_UN, Bgt_Un, "bgt.un", 0x42, InlineBrTarget),
    (BLE_UN, Ble_Un, "ble.un", 0x43, InlineBrTarget),
    (BLT_UN, Blt_Un, "blt.un", 0x44, InlineBrTarget),
    (SWITCH, Switch, "switch", 0x45, InlineSwitch),
    (LDIND_I1, Ldind_I1, "ldind.i1", 0x46, InlineNone),
    (LDIND_U1, Ldind_U1, "ldind.u1", 0x47, InlineNone),
    (LDIND_I2, Ldind_I2, "ldind.i2", 0x48, InlineNone),
    (LDIND_U2, Ldind_U2, "ldind.u2", 0x49, InlineNone),
    (LDIND_I4, Ldind_I4, "ldind.i4", 0x4a, InlineNone),
    (LDIND_U4, Ldind_U4, "ldind.u4", 0x4b, InlineNone),
    (LDIND_I8, Ldind_I8, "ldind.i8", 0x4c, InlineNone),
    (LDIND_I, Ldind_I, "ldind.i", 0x4d, InlineNone),
    (LDIND_R4, Ldind_R4, "ldind.r4", 0x4e, InlineNone),
    (LDIND_R8, Ldind_R8, "ldind.r8", 0x4f, InlineNone),
    (LDIND_REF, Ldind_Ref, "ldind.ref", 0x50, InlineNone),
    (STIND_REF, Stind_Ref, "stind.ref", 0x51, InlineNone),
    (STIND_I1, Stind_I1, "stind.i1", 0x52, InlineNone),
    (STIND_I2, Stind_I2, "stind.i2", 0x53, InlineNone),
    (STIND_I4, Stind_I4, "stind.i4", 0x54, InlineNone),
    (STIND_I8, Stind_I8, "stind.i8", 0x55, InlineNone),
    (STIND_R4, Stind_R4, "stind.r4", 0x56, InlineNone),
    (STIND_R8, Stind_R8, "stind.r8", 0x57, InlineNone),
    (ADD, Add, "add", 0x58, InlineNone),
    (SUB, Sub, "sub", 0x59, InlineNone),
    (MUL, Mul, "mul", 0x5a, InlineNone),
    (DIV, Div, "div", 0x5b, InlineNone),
    (DIV_UN, Div_Un, "div.un", 0x5c, InlineNone),
    (REM, Rem, "rem", 0x5d, InlineNone),
    (REM_UN, Rem_Un, "rem.un", 0x5e, InlineNone),
    (AND, And, "and", 0x5f, InlineNone),
    (OR, Or, "or", 0x60, InlineNone),
    (XOR, Xor, "xor", 0x61, InlineNone),
    (SHL, Shl, "shl", 0x62, InlineNone),
    (SHR, Shr, "shr", 0x63, InlineNone),
    (SHR_UN, Shr_Un, "shr.un", 0x64, InlineNone),
    (NEG, Neg, "neg", 0x65, InlineNone),
    (NOT, Not, "not", 0x66, InlineNone),
    (CONV_I1, Conv_I1, "conv.i1", 0x67, InlineNone),
    (CONV_I2, Conv_I2, "conv.i2", 0x68, InlineNone),
    (CONV_I4, Conv_I4, "conv.i4", 0x69, InlineNone),
    (CONV_I8, Conv_I8, "conv.i8", 0x6a, InlineNone),
    (CONV_R4, Conv_R4, "conv.r4", 0x6b, InlineNone),
    (CONV_R8, Conv_R8, "conv.r8", 0x6c, InlineNone),
    (CONV_U4, Conv_U4, "conv.u4", 0x6d, InlineNone),
    (CONV_U8, Conv_U8, "conv.u8", 0x6e, InlineNone),
    (CALLVIRT, Callvirt, "callvirt", 0x6f, InlineMethod),
    (CPOBJ, Cpobj, "cpobj", 0x70, InlineType),
    (LDOBJ, Ldobj, "ldobj", 0x71, InlineType),
    (LDSTR, Ldstr, "ldstr", 0x72, InlineString),
    (NEWOBJ, Newobj, "newobj", 0x73, InlineMethod),
    (CASTCLASS, Castclass, "castclass", 0x74, InlineType),
    (ISINST, Isinst, "isinst", 0x75, InlineType),
    (CONV_R_UN, Conv_R_Un, "conv.r.un", 0x76, InlineNone),
    (UNBOX, Unbox, "unbox", 0x79, InlineType),
    (THROW, Throw, "throw", 0x7a, InlineNone),
    (LDFLD, Ldfld, "ldfld", 0x7b, InlineField),
    (LDFLDA, Ldflda, "ldflda", 0x7c, InlineField),
    (STFLD, Stfld, "stfld", 0x7d, InlineField),
    (LDSFLD, Ldsfld, "ldsfld", 0x7e, InlineField),
    (LDSFLDA, Ldsflda, "ldsflda", 0x7f, InlineField),
    (STSFLD, Stsfld, "stsfld", 0x80, InlineField),
    (STOBJ, Stobj, "stobj", 0x81, InlineType),
    (CONV_OVF_I1_UN, Conv_Ovf_I1_Un, "conv.ovf.i1.un", 0x82, InlineNone),
    (CONV_OVF_I2_UN, Conv_Ovf_I2_Un, "conv.ovf.i2.un", 0x83, InlineNone),
    (CONV_OVF_I4_UN, Conv_Ovf_I4_Un, "conv.ovf.i4.un", 0x84, InlineNone),
    (CONV_OVF_I8_UN, Conv_Ovf_I8_Un, "conv.ovf.i8.un", 0x85, InlineNone),
    (CONV_OVF_U1_UN, Conv_Ovf_U1_Un, "conv.ovf.u1.un", 0x86, InlineNone),
    (CONV_OVF_U2_UN, Conv_Ovf_U2_Un, "conv.ovf.u2.un", 0x87, InlineNone),
    (CONV_OVF_U4_UN, Conv_Ovf_U4_Un, "conv.ovf.u4.un", 0x88, InlineNone),
    (CONV_OVF_U8_UN, Conv_Ovf_U8_Un, "conv.ovf.u8.un", 0x89, InlineNone),
    (CONV_OVF_I_UN, Conv_Ovf_I_Un, "conv.ovf.i.un", 0x8a, InlineNone),
    (CONV_OVF_U_UN, Conv_Ovf_U_Un, "conv.ovf.u.un", 0x8b, InlineNone),
    (BOX, Box, "box", 0x8c, InlineType),
    (NEWARR, Newarr, "newarr", 0x8d, InlineType),
    (LDLEN, Ldlen, "ldlen", 0x8e, InlineNone),
    (LDELEMA, Ldelema, "ldelema", 0x8f, InlineType),
    (LDELEM_I1, Ldelem_I1, "ldelem.i1", 0x90, InlineNone),
    (LDELEM_U1, Ldelem_U1, "ldelem.u1", 0x91, InlineNone),
    (LDELEM_I2, Ldelem_I2, "ldelem.i2", 0x92, InlineNone),
    (LDELEM_U2, Ldelem_U2, "ldelem.u2", 0x93, InlineNone),
    (LDELEM_I4, Ldelem_I4, "ldelem.i4", 0x94, InlineNone),
    (LDELEM_U4, Ldelem_U4, "ldelem.u4", 0x95, InlineNone),
    (LDELEM_I8, Ldelem_I8, "ldelem.i8", 0x96, InlineNone),
    (LDELEM_I, Ldelem_I, "ldelem.i", 0x97, InlineNone),
    (LDELEM_R4, Ldelem_R4, "ldelem.r4", 0x98, InlineNone),
    (LDELEM_R8, Ldelem_R8, "ldelem.r8", 0x99, InlineNone),
    (LDELEM_REF, Ldelem_Ref, "ldelem.ref", 0x9a, InlineNone),
    (STELEM_I, Stelem_I, "stelem.i", 0x9b, InlineNone),
    (STELEM_I1, Stelem_I1, "stelem.i1", 0x9c, InlineNone),
    (STELEM_I2, Stelem_I2, "stelem.i2", 0x9d, InlineNone),
    (STELEM_I4, Stelem_I4, "stelem.i4", 0x9e, InlineNone),
    (STELEM_I8, Stelem_I8, "stelem.i8", 0x9f, InlineNone),
    (STELEM_R4, Stelem_R4, "stelem.r4", 0xa0, InlineNone),
    (STELEM_R8, Stelem_R8, "stelem.r8", 0xa1, InlineNone),
    (STELEM_REF, Stelem_Ref, "stelem.ref", 0xa2, InlineNone),
    (LDELEM_ANY, Ldelem_Any, "ldelem.any", 0xa3, InlineType),
    (STELEM_ANY, Stelem_Any, "stelem.any", 0xa4, InlineType),
    (UNBOX_ANY, Unbox_Any, "unbox.any", 0xa5, InlineType),
    (CONV_OVF_I1, Conv_Ovf_I1, "conv.ovf.i1", 0xb3, InlineNone),
    (CONV_OVF_U1, Conv_Ovf_U1, "conv.ovf.u1", 0xb4, InlineNone),
    (CONV_OVF_I2, Conv_Ovf_I2, "conv.ovf.i2", 0xb5, InlineNone),
    (CONV_OVF_U2, Conv_Ovf_U2, "conv.ovf.u2", 0xb6, InlineNone),
    (CONV_OVF_I4, Conv_Ovf_I4, "conv.ovf.i4", 0xb7, InlineNone),
    (CONV_OVF_U4, Conv_Ovf_U4, "conv.ovf.u4", 0xb8, InlineNone),
    (CONV_OVF_I8, Conv_Ovf_I8, "conv.ovf.i8", 0xb9, InlineNone),
    (CONV_OVF_U8, Conv_Ovf_U8, "conv.ovf.u8", 0xba, InlineNone),
    (REFANYVAL, Refanyval, "refanyval", 0xc2, InlineType),
    (CKFINITE, Ckfinite, "ckfinite", 0xc3, InlineNone),
    (MKREFANY, Mkrefany, "mkrefany", 0xc6, InlineType),
    (LDTOKEN, Ldtoken, "ldtoken", 0xd0, InlineTok),
    (CONV_U2, Conv_U2, "conv.u2", 0xd1, InlineNone),
    (CONV_U1, Conv_U1, "conv.u1", 0xd2, InlineNone),
    (CONV_I, Conv_I, "conv.i", 0xd3, InlineNone),
    (CONV_OVF_I, Conv_Ovf_I, "conv.ovf.i", 0xd4, InlineNone),
    (CONV_OVF_U, Conv_Ovf_U, "conv.ovf.u", 0xd5, InlineNone),
    (ADD_OVF, Add_Ovf, "add.ovf", 0xd6, InlineNone),
    (ADD_OVF_UN, Add_Ovf_Un, "add.ovf.un", 0xd7, InlineNone),
    (MUL_OVF, Mul_Ovf, "mul.ovf", 0xd8, InlineNone),
    (MUL_OVF_UN, Mul_Ovf_Un, "mul.ovf.un", 0xd9, InlineNone),
    (SUB_OVF, Sub_Ovf, "sub.ovf", 0xda, InlineNone),
    (SUB_OVF_UN, Sub_Ovf_Un, "sub.ovf.un", 0xdb, InlineNone),
    (ENDFINALLY, Endfinally, "endfinally", 0xdc, InlineNone),
    (LEAVE, Leave, "leave", 0xdd, InlineBrTarget),
    (LEAVE_S, Leave_S, "leave.s", 0xde, ShortInlineBrTarget),
    (STIND_I, Stind_I, "stind.i", 0xdf, InlineNone),
    (CONV_U, Conv_U, "conv.u", 0xe0, InlineNone),
}

two_byte! {
    (ARGLIST, Arglist, "arglist", 0x00, InlineNone),
    (CEQ, Ceq, "ceq", 0x01, InlineNone),
    (CGT, Cgt, "cgt", 0x02, InlineNone),
    (CGT_UN, Cgt_Un, "cgt.un", 0x03, InlineNone),
    (CLT, Clt, "clt", 0x04, InlineNone),
    (CLT_UN, Clt_Un, "clt.un", 0x05, InlineNone),
    (LDFTN, Ldftn, "ldftn", 0x06, InlineMethod),
    (LDVIRTFTN, Ldvirtftn, "ldvirtftn", 0x07, InlineMethod),
    (LDARG, Ldarg, "ldarg", 0x09, InlineArg),
    (LDARGA, Ldarga, "ldarga", 0x0a, InlineArg),
    (STARG, Starg, "starg", 0x0b, InlineArg),
    (LDLOC, Ldloc, "ldloc", 0x0c, InlineVar),
    (LDLOCA, Ldloca, "ldloca", 0x0d, InlineVar),
    (STLOC, Stloc, "stloc", 0x0e, InlineVar),
    (LOCALLOC, Localloc, "localloc", 0x0f, InlineNone),
    (ENDFILTER, Endfilter, "endfilter", 0x11, InlineNone),
    (UNALIGNED, Unaligned, "unaligned.", 0x12, ShortInlineI),
    (VOLATILE, Volatile, "volatile.", 0x13, InlineNone),
    (TAIL, Tail, "tail.", 0x14, InlineNone),
    (INITOBJ, Initobj, "initobj", 0x15, InlineType),
    (CONSTRAINED, Constrained, "constrained.", 0x16, InlineType),
    (CPBLK, Cpblk, "cpblk", 0x17, InlineNone),
    (INITBLK, Initblk, "initblk", 0x18, InlineNone),
    (NO, No, "no.", 0x19, ShortInlineI),
    (RETHROW, Rethrow, "rethrow", 0x1a, InlineNone),
    (SIZEOF, Sizeof, "sizeof", 0x1c, InlineType),
    (REFANYTYPE, Refanytype, "refanytype", 0x1d, InlineNone),
    (READONLY, Readonly, "readonly.", 0x1e, InlineNone),
}

// Regenerate the per-opcode metadata for the shared tables below.
macro_rules! table_entries {
    ($mac:ident) => {
        $mac! {
            (NOP, Nop, "nop", 0xFF, 0x00, InlineNone),
            (BREAK, Break, "break", 0xFF, 0x01, InlineNone),
            (LDARG_0, Ldarg_0, "ldarg.0", 0xFF, 0x02, InlineNone),
            (LDARG_1, Ldarg_1, "ldarg.1", 0xFF, 0x03, InlineNone),
            (LDARG_2, Ldarg_2, "ldarg.2", 0xFF, 0x04, InlineNone),
            (LDARG_3, Ldarg_3, "ldarg.3", 0xFF, 0x05, InlineNone),
            (LDLOC_0, Ldloc_0, "ldloc.0", 0xFF, 0x06, InlineNone),
            (LDLOC_1, Ldloc_1, "ldloc.1", 0xFF, 0x07, InlineNone),
            (LDLOC_2, Ldloc_2, "ldloc.2", 0xFF, 0x08, InlineNone),
            (LDLOC_3, Ldloc_3, "ldloc.3", 0xFF, 0x09, InlineNone),
            (STLOC_0, Stloc_0, "stloc.0", 0xFF, 0x0a, InlineNone),
            (STLOC_1, Stloc_1, "stloc.1", 0xFF, 0x0b, InlineNone),
            (STLOC_2, Stloc_2, "stloc.2", 0xFF, 0x0c, InlineNone),
            (STLOC_3, Stloc_3, "stloc.3", 0xFF, 0x0d, InlineNone),
            (LDARG_S, Ldarg_S, "ldarg.s", 0xFF, 0x0e, ShortInlineArg),
            (LDARGA_S, Ldarga_S, "ldarga.s", 0xFF, 0x0f, ShortInlineArg),
            (STARG_S, Starg_S, "starg.s", 0xFF, 0x10, ShortInlineArg),
            (LDLOC_S, Ldloc_S, "ldloc.s", 0xFF, 0x11, ShortInlineVar),
            (LDLOCA_S, Ldloca_S, "ldloca.s", 0xFF, 0x12, ShortInlineVar),
            (STLOC_S, Stloc_S, "stloc.s", 0xFF, 0x13, ShortInlineVar),
            (LDNULL, Ldnull, "ldnull", 0xFF, 0x14, InlineNone),
            (LDC_I4_M1, Ldc_I4_M1, "ldc.i4.m1", 0xFF, 0x15, InlineNone),
            (LDC_I4_0, Ldc_I4_0, "ldc.i4.0", 0xFF, 0x16, InlineNone),
            (LDC_I4_1, Ldc_I4_1, "ldc.i4.1", 0xFF, 0x17, InlineNone),
            (LDC_I4_2, Ldc_I4_2, "ldc.i4.2", 0xFF, 0x18, InlineNone),
            (LDC_I4_3, Ldc_I4_3, "ldc.i4.3", 0xFF, 0x19, InlineNone),
            (LDC_I4_4, Ldc_I4_4, "ldc.i4.4", 0xFF, 0x1a, InlineNone),
            (LDC_I4_5, Ldc_I4_5, "ldc.i4.5", 0xFF, 0x1b, InlineNone),
            (LDC_I4_6, Ldc_I4_6, "ldc.i4.6", 0xFF, 0x1c, InlineNone),
            (LDC_I4_7, Ldc_I4_7, "ldc.i4.7", 0xFF, 0x1d, InlineNone),
            (LDC_I4_8, Ldc_I4_8, "ldc.i4.8", 0xFF, 0x1e, InlineNone),
            (LDC_I4_S, Ldc_I4_S, "ldc.i4.s", 0xFF, 0x1f, ShortInlineI),
            (LDC_I4, Ldc_I4, "ldc.i4", 0xFF, 0x20, InlineI),
            (LDC_I8, Ldc_I8, "ldc.i8", 0xFF, 0x21, InlineI8),
            (LDC_R4, Ldc_R4, "ldc.r4", 0xFF, 0x22, ShortInlineR),
            (LDC_R8, Ldc_R8, "ldc.r8", 0xFF, 0x23, InlineR),
            (DUP, Dup, "dup", 0xFF, 0x25, InlineNone),
            (POP, Pop, "pop", 0xFF, 0x26, InlineNone),
            (JMP, Jmp, "jmp", 0xFF, 0x27, InlineMethod),
            (CALL, Call, "call", 0xFF, 0x28, InlineMethod),
            (CALLI, Calli, "calli", 0xFF, 0x29, InlineSig),
            (RET, Ret, "ret", 0xFF, 0x2a, InlineNone),
            (BR_S, Br_S, "br.s", 0xFF, 0x2b, ShortInlineBrTarget),
            (BRFALSE_S, Brfalse_S, "brfalse.s", 0xFF, 0x2c, ShortInlineBrTarget),
            (BRTRUE_S, Brtrue_S, "brtrue.s", 0xFF, 0x2d, ShortInlineBrTarget),
            (BEQ_S, Beq_S, "beq.s", 0xFF, 0x2e, ShortInlineBrTarget),
            (BGE_S, Bge_S, "bge.s", 0xFF, 0x2f, ShortInlineBrTarget),
            (BGT_S, Bgt_S, "bgt.s", 0xFF, 0x30, ShortInlineBrTarget),
            (BLE_S, Ble_S, "ble.s", 0xFF, 0x31, ShortInlineBrTarget),
            (BLT_S, Blt_S, "blt.s", 0xFF, 0x32, ShortInlineBrTarget),
            (BNE_UN_S, Bne_Un_S, "bne.un.s", 0xFF, 0x33, ShortInlineBrTarget),
            (BGE_UN_S, Bge_Un_S, "bge.un.s", 0xFF, 0x34, ShortInlineBrTarget),
            (BGT_UN_S, Bgt_Un_S, "bgt.un.s", 0xFF, 0x35, ShortInlineBrTarget),
            (BLE_UN_S, Ble_Un_S, "ble.un.s", 0xFF, 0x36, ShortInlineBrTarget),
            (BLT_UN_S, Blt_Un_S, "blt.un.s", 0xFF, 0x37, ShortInlineBrTarget),
            (BR, Br, "br", 0xFF, 0x38, InlineBrTarget),
            (BRFALSE, Brfalse, "brfalse", 0xFF, 0x39, InlineBrTarget),
            (BRTRUE, Brtrue, "brtrue", 0xFF, 0x3a, InlineBrTarget),
            (BEQ, Beq, "beq", 0xFF, 0x3b, InlineBrTarget),
            (BGE, Bge, "bge", 0xFF, 0x3c, InlineBrTarget),
            (BGT, Bgt, "bgt", 0xFF, 0x3d, InlineBrTarget),
            (BLE, Ble, "ble", 0xFF, 0x3e, InlineBrTarget),
            (BLT, Blt, "blt", 0xFF, 0x3f, InlineBrTarget),
            (BNE_UN, Bne_Un, "bne.un", 0xFF, 0x40, InlineBrTarget),
            (BGE_UN, Bge_Un, "bge.un", 0xFF, 0x41, InlineBrTarget),
            (BGT_UN, Bgt_Un, "bgt.un", 0xFF, 0x42, InlineBrTarget),
            (BLE_UN, Ble_Un, "ble.un", 0xFF, 0x43, InlineBrTarget),
            (BLT_UN, Blt_Un, "blt.un", 0xFF, 0x44, InlineBrTarget),
            (SWITCH, Switch, "switch", 0xFF, 0x45, InlineSwitch),
            (LDIND_I1, Ldind_I1, "ldind.i1", 0xFF, 0x46, InlineNone),
            (LDIND_U1, Ldind_U1, "ldind.u1", 0xFF, 0x47, InlineNone),
            (LDIND_I2, Ldind_I2, "ldind.i2", 0xFF, 0x48, InlineNone),
            (LDIND_U2, Ldind_U2, "ldind.u2", 0xFF, 0x49, InlineNone),
            (LDIND_I4, Ldind_I4, "ldind.i4", 0xFF, 0x4a, InlineNone),
            (LDIND_U4, Ldind_U4, "ldind.u4", 0xFF, 0x4b, InlineNone),
            (LDIND_I8, Ldind_I8, "ldind.i8", 0xFF, 0x4c, InlineNone),
            (LDIND_I, Ldind_I, "ldind.i", 0xFF, 0x4d, InlineNone),
            (LDIND_R4, Ldind_R4, "ldind.r4", 0xFF, 0x4e, InlineNone),
            (LDIND_R8, Ldind_R8, "ldind.r8", 0xFF, 0x4f, InlineNone),
            (LDIND_REF, Ldind_Ref, "ldind.ref", 0xFF, 0x50, InlineNone),
            (STIND_REF, Stind_Ref, "stind.ref", 0xFF, 0x51, InlineNone),
            (STIND_I1, Stind_I1, "stind.i1", 0xFF, 0x52, InlineNone),
            (STIND_I2, Stind_I2, "stind.i2", 0xFF, 0x53, InlineNone),
            (STIND_I4, Stind_I4, "stind.i4", 0xFF, 0x54, InlineNone),
            (STIND_I8, Stind_I8, "stind.i8", 0xFF, 0x55, InlineNone),
            (STIND_R4, Stind_R4, "stind.r4", 0xFF, 0x56, InlineNone),
            (STIND_R8, Stind_R8, "stind.r8", 0xFF, 0x57, InlineNone),
            (ADD, Add, "add", 0xFF, 0x58, InlineNone),
            (SUB, Sub, "sub", 0xFF, 0x59, InlineNone),
            (MUL, Mul, "mul", 0xFF, 0x5a, InlineNone),
            (DIV, Div, "div", 0xFF, 0x5b, InlineNone),
            (DIV_UN, Div_Un, "div.un", 0xFF, 0x5c, InlineNone),
            (REM, Rem, "rem", 0xFF, 0x5d, InlineNone),
            (REM_UN, Rem_Un, "rem.un", 0xFF, 0x5e, InlineNone),
            (AND, And, "and", 0xFF, 0x5f, InlineNone),
            (OR, Or, "or", 0xFF, 0x60, InlineNone),
            (XOR, Xor, "xor", 0xFF, 0x61, InlineNone),
            (SHL, Shl, "shl", 0xFF, 0x62, InlineNone),
            (SHR, Shr, "shr", 0xFF, 0x63, InlineNone),
            (SHR_UN, Shr_Un, "shr.un", 0xFF, 0x64, InlineNone),
            (NEG, Neg, "neg", 0xFF, 0x65, InlineNone),
            (NOT, Not, "not", 0xFF, 0x66, InlineNone),
            (CONV_I1, Conv_I1, "conv.i1", 0xFF, 0x67, InlineNone),
            (CONV_I2, Conv_I2, "conv.i2", 0xFF, 0x68, InlineNone),
            (CONV_I4, Conv_I4, "conv.i4", 0xFF, 0x69, InlineNone),
            (CONV_I8, Conv_I8, "conv.i8", 0xFF, 0x6a, InlineNone),
            (CONV_R4, Conv_R4, "conv.r4", 0xFF, 0x6b, InlineNone),
            (CONV_R8, Conv_R8, "conv.r8", 0xFF, 0x6c, InlineNone),
            (CONV_U4, Conv_U4, "conv.u4", 0xFF, 0x6d, InlineNone),
            (CONV_U8, Conv_U8, "conv.u8", 0xFF, 0x6e, InlineNone),
            (CALLVIRT, Callvirt, "callvirt", 0xFF, 0x6f, InlineMethod),
            (CPOBJ, Cpobj, "cpobj", 0xFF, 0x70, InlineType),
            (LDOBJ, Ldobj, "ldobj", 0xFF, 0x71, InlineType),
            (LDSTR, Ldstr, "ldstr", 0xFF, 0x72, InlineString),
            (NEWOBJ, Newobj, "newobj", 0xFF, 0x73, InlineMethod),
            (CASTCLASS, Castclass, "castclass", 0xFF, 0x74, InlineType),
            (ISINST, Isinst, "isinst", 0xFF, 0x75, InlineType),
            (CONV_R_UN, Conv_R_Un, "conv.r.un", 0xFF, 0x76, InlineNone),
            (UNBOX, Unbox, "unbox", 0xFF, 0x79, InlineType),
            (THROW, Throw, "throw", 0xFF, 0x7a, InlineNone),
            (LDFLD, Ldfld, "ldfld", 0xFF, 0x7b, InlineField),
            (LDFLDA, Ldflda, "ldflda", 0xFF, 0x7c, InlineField),
            (STFLD, Stfld, "stfld", 0xFF, 0x7d, InlineField),
            (LDSFLD, Ldsfld, "ldsfld", 0xFF, 0x7e, InlineField),
            (LDSFLDA, Ldsflda, "ldsflda", 0xFF, 0x7f, InlineField),
            (STSFLD, Stsfld, "stsfld", 0xFF, 0x80, InlineField),
            (STOBJ, Stobj, "stobj", 0xFF, 0x81, InlineType),
            (CONV_OVF_I1_UN, Conv_Ovf_I1_Un, "conv.ovf.i1.un", 0xFF, 0x82, InlineNone),
            (CONV_OVF_I2_UN, Conv_Ovf_I2_Un, "conv.ovf.i2.un", 0xFF, 0x83, InlineNone),
            (CONV_OVF_I4_UN, Conv_Ovf_I4_Un, "conv.ovf.i4.un", 0xFF, 0x84, InlineNone),
            (CONV_OVF_I8_UN, Conv_Ovf_I8_Un, "conv.ovf.i8.un", 0xFF, 0x85, InlineNone),
            (CONV_OVF_U1_UN, Conv_Ovf_U1_Un, "conv.ovf.u1.un", 0xFF, 0x86, InlineNone),
            (CONV_OVF_U2_UN, Conv_Ovf_U2_Un, "conv.ovf.u2.un", 0xFF, 0x87, InlineNone),
            (CONV_OVF_U4_UN, Conv_Ovf_U4_Un, "conv.ovf.u4.un", 0xFF, 0x88, InlineNone),
            (CONV_OVF_U8_UN, Conv_Ovf_U8_Un, "conv.ovf.u8.un", 0xFF, 0x89, InlineNone),
            (CONV_OVF_I_UN, Conv_Ovf_I_Un, "conv.ovf.i.un", 0xFF, 0x8a, InlineNone),
            (CONV_OVF_U_UN, Conv_Ovf_U_Un, "conv.ovf.u.un", 0xFF, 0x8b, InlineNone),
            (BOX, Box, "box", 0xFF, 0x8c, InlineType),
            (NEWARR, Newarr, "newarr", 0xFF, 0x8d, InlineType),
            (LDLEN, Ldlen, "ldlen", 0xFF, 0x8e, InlineNone),
            (LDELEMA, Ldelema, "ldelema", 0xFF, 0x8f, InlineType),
            (LDELEM_I1, Ldelem_I1, "ldelem.i1", 0xFF, 0x90, InlineNone),
            (LDELEM_U1, Ldelem_U1, "ldelem.u1", 0xFF, 0x91, InlineNone),
            (LDELEM_I2, Ldelem_I2, "ldelem.i2", 0xFF, 0x92, InlineNone),
            (LDELEM_U2, Ldelem_U2, "ldelem.u2", 0xFF, 0x93, InlineNone),
            (LDELEM_I4, Ldelem_I4, "ldelem.i4", 0xFF, 0x94, InlineNone),
            (LDELEM_U4, Ldelem_U4, "ldelem.u4", 0xFF, 0x95, InlineNone),
            (LDELEM_I8, Ldelem_I8, "ldelem.i8", 0xFF, 0x96, InlineNone),
            (LDELEM_I, Ldelem_I, "ldelem.i", 0xFF, 0x97, InlineNone),
            (LDELEM_R4, Ldelem_R4, "ldelem.r4", 0xFF, 0x98, InlineNone),
            (LDELEM_R8, Ldelem_R8, "ldelem.r8", 0xFF, 0x99, InlineNone),
            (LDELEM_REF, Ldelem_Ref, "ldelem.ref", 0xFF, 0x9a, InlineNone),
            (STELEM_I, Stelem_I, "stelem.i", 0xFF, 0x9b, InlineNone),
            (STELEM_I1, Stelem_I1, "stelem.i1", 0xFF, 0x9c, InlineNone),
            (STELEM_I2, Stelem_I2, "stelem.i2", 0xFF, 0x9d, InlineNone),
            (STELEM_I4, Stelem_I4, "stelem.i4", 0xFF, 0x9e, InlineNone),
            (STELEM_I8, Stelem_I8, "stelem.i8", 0xFF, 0x9f, InlineNone),
            (STELEM_R4, Stelem_R4, "stelem.r4", 0xFF, 0xa0, InlineNone),
            (STELEM_R8, Stelem_R8, "stelem.r8", 0xFF, 0xa1, InlineNone),
            (STELEM_REF, Stelem_Ref, "stelem.ref", 0xFF, 0xa2, InlineNone),
            (LDELEM_ANY, Ldelem_Any, "ldelem.any", 0xFF, 0xa3, InlineType),
            (STELEM_ANY, Stelem_Any, "stelem.any", 0xFF, 0xa4, InlineType),
            (UNBOX_ANY, Unbox_Any, "unbox.any", 0xFF, 0xa5, InlineType),
            (CONV_OVF_I1, Conv_Ovf_I1, "conv.ovf.i1", 0xFF, 0xb3, InlineNone),
            (CONV_OVF_U1, Conv_Ovf_U1, "conv.ovf.u1", 0xFF, 0xb4, InlineNone),
            (CONV_OVF_I2, Conv_Ovf_I2, "conv.ovf.i2", 0xFF, 0xb5, InlineNone),
            (CONV_OVF_U2, Conv_Ovf_U2, "conv.ovf.u2", 0xFF, 0xb6, InlineNone),
            (CONV_OVF_I4, Conv_Ovf_I4, "conv.ovf.i4", 0xFF, 0xb7, InlineNone),
            (CONV_OVF_U4, Conv_Ovf_U4, "conv.ovf.u4", 0xFF, 0xb8, InlineNone),
            (CONV_OVF_I8, Conv_Ovf_I8, "conv.ovf.i8", 0xFF, 0xb9, InlineNone),
            (CONV_OVF_U8, Conv_Ovf_U8, "conv.ovf.u8", 0xFF, 0xba, InlineNone),
            (REFANYVAL, Refanyval, "refanyval", 0xFF, 0xc2, InlineType),
            (CKFINITE, Ckfinite, "ckfinite", 0xFF, 0xc3, InlineNone),
            (MKREFANY, Mkrefany, "mkrefany", 0xFF, 0xc6, InlineType),
            (LDTOKEN, Ldtoken, "ldtoken", 0xFF, 0xd0, InlineTok),
            (CONV_U2, Conv_U2, "conv.u2", 0xFF, 0xd1, InlineNone),
            (CONV_U1, Conv_U1, "conv.u1", 0xFF, 0xd2, InlineNone),
            (CONV_I, Conv_I, "conv.i", 0xFF, 0xd3, InlineNone),
            (CONV_OVF_I, Conv_Ovf_I, "conv.ovf.i", 0xFF, 0xd4, InlineNone),
            (CONV_OVF_U, Conv_Ovf_U, "conv.ovf.u", 0xFF, 0xd5, InlineNone),
            (ADD_OVF, Add_Ovf, "add.ovf", 0xFF, 0xd6, InlineNone),
            (ADD_OVF_UN, Add_Ovf_Un, "add.ovf.un", 0xFF, 0xd7, InlineNone),
            (MUL_OVF, Mul_Ovf, "mul.ovf", 0xFF, 0xd8, InlineNone),
            (MUL_OVF_UN, Mul_Ovf_Un, "mul.ovf.un", 0xFF, 0xd9, InlineNone),
            (SUB_OVF, Sub_Ovf, "sub.ovf", 0xFF, 0xda, InlineNone),
            (SUB_OVF_UN, Sub_Ovf_Un, "sub.ovf.un", 0xFF, 0xdb, InlineNone),
            (ENDFINALLY, Endfinally, "endfinally", 0xFF, 0xdc, InlineNone),
            (LEAVE, Leave, "leave", 0xFF, 0xdd, InlineBrTarget),
            (LEAVE_S, Leave_S, "leave.s", 0xFF, 0xde, ShortInlineBrTarget),
            (STIND_I, Stind_I, "stind.i", 0xFF, 0xdf, InlineNone),
            (CONV_U, Conv_U, "conv.u", 0xFF, 0xe0, InlineNone),
            (ARGLIST, Arglist, "arglist", 0xFE, 0x00, InlineNone),
            (CEQ, Ceq, "ceq", 0xFE, 0x01, InlineNone),
            (CGT, Cgt, "cgt", 0xFE, 0x02, InlineNone),
            (CGT_UN, Cgt_Un, "cgt.un", 0xFE, 0x03, InlineNone),
            (CLT, Clt, "clt", 0xFE, 0x04, InlineNone),
            (CLT_UN, Clt_Un, "clt.un", 0xFE, 0x05, InlineNone),
            (LDFTN, Ldftn, "ldftn", 0xFE, 0x06, InlineMethod),
            (LDVIRTFTN, Ldvirtftn, "ldvirtftn", 0xFE, 0x07, InlineMethod),
            (LDARG, Ldarg, "ldarg", 0xFE, 0x09, InlineArg),
            (LDARGA, Ldarga, "ldarga", 0xFE, 0x0a, InlineArg),
            (STARG, Starg, "starg", 0xFE, 0x0b, InlineArg),
            (LDLOC, Ldloc, "ldloc", 0xFE, 0x0c, InlineVar),
            (LDLOCA, Ldloca, "ldloca", 0xFE, 0x0d, InlineVar),
            (STLOC, Stloc, "stloc", 0xFE, 0x0e, InlineVar),
            (LOCALLOC, Localloc, "localloc", 0xFE, 0x0f, InlineNone),
            (ENDFILTER, Endfilter, "endfilter", 0xFE, 0x11, InlineNone),
            (UNALIGNED, Unaligned, "unaligned.", 0xFE, 0x12, ShortInlineI),
            (VOLATILE, Volatile, "volatile.", 0xFE, 0x13, InlineNone),
            (TAIL, Tail, "tail.", 0xFE, 0x14, InlineNone),
            (INITOBJ, Initobj, "initobj", 0xFE, 0x15, InlineType),
            (CONSTRAINED, Constrained, "constrained.", 0xFE, 0x16, InlineType),
            (CPBLK, Cpblk, "cpblk", 0xFE, 0x17, InlineNone),
            (INITBLK, Initblk, "initblk", 0xFE, 0x18, InlineNone),
            (NO, No, "no.", 0xFE, 0x19, ShortInlineI),
            (RETHROW, Rethrow, "rethrow", 0xFE, 0x1a, InlineNone),
            (SIZEOF, Sizeof, "sizeof", 0xFE, 0x1c, InlineType),
            (REFANYTYPE, Refanytype, "refanytype", 0xFE, 0x1d, InlineNone),
            (READONLY, Readonly, "readonly.", 0xFE, 0x1e, InlineNone),
        }
    };
}

table_entries!(all_opcodes);

/// Looks up an opcode by its single-byte encoding. Returns `None` for bytes
/// that do not map to a defined instruction (e.g. `0x24`, `0xA6..=0xB2`).
pub fn one_byte(second: u8) -> Option<&'static OpCode> {
    ONE_BYTE[second as usize]
}

/// Looks up an opcode by the byte following the `0xFE` escape prefix.
pub fn two_byte(second: u8) -> Option<&'static OpCode> {
    TWO_BYTE.get(second as usize).copied().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::Code;
    use crate::opcode::instruction_size;
    use std::collections::HashSet;

    /// `Mono.Cecil.Cil/OpCodes.cs` defines 191 single-byte opcodes
    /// (0x00..=0xE0 minus the undefined slots) and 28 two-byte opcodes
    /// (0xFE 0x00..=0x1E minus 0x08, 0x10, 0x1B): 219 in total.
    #[test]
    fn table_is_complete() {
        assert_eq!(ALL.len(), 219);
        assert!(ALL.len() >= 200);
        assert_eq!(ALL.iter().filter(|op| op.is_single_byte()).count(), 191);
        assert_eq!(ALL.iter().filter(|op| !op.is_single_byte()).count(), 28);
    }

    #[test]
    fn spot_check_encodings() {
        // NOP = 0x00, size 1.
        assert_eq!((NOP.byte1, NOP.byte2, NOP.size), (0xFF, 0x00, 1));
        assert_eq!(NOP.operand_type, OperandType::InlineNone);
        assert_eq!(NOP.code, Code::Nop);
        // LDARG_0 = 0x02.
        assert_eq!((LDARG_0.byte1, LDARG_0.byte2), (0xFF, 0x02));
        // LDC_I4_M1 = 0x15.
        assert_eq!((LDC_I4_M1.byte1, LDC_I4_M1.byte2), (0xFF, 0x15));
        // BOX = 0x8C with an inline type token.
        assert_eq!((BOX.byte1, BOX.byte2), (0xFF, 0x8C));
        assert_eq!(BOX.operand_type, OperandType::InlineType);
        assert_eq!((CONV_U.byte1, CONV_U.byte2), (0xFF, 0xE0));
        assert_eq!(CONV_U.operand_type, OperandType::InlineNone);
    }

    #[test]
    fn encodings_are_unique() {
        let mut seen = HashSet::new();
        for op in ALL {
            assert!(seen.insert(op.encoding()), "duplicate encoding {}", op.name);
        }
    }

    #[test]
    fn codes_are_unique() {
        let mut seen = HashSet::new();
        for op in ALL {
            assert!(seen.insert(op.code), "duplicate code {}", op.name);
        }
    }

    #[test]
    fn lookup_tables_agree_with_all() {
        for op in ALL {
            if op.is_single_byte() {
                assert_eq!(one_byte(op.byte2), Some(op), "single {:#04x}", op.byte2);
            } else {
                assert_eq!(two_byte(op.byte2), Some(op), "two fe {:#04x}", op.byte2);
            }
        }
        assert_eq!(one_byte(0x24), None);
        assert_eq!(one_byte(0xA6), None);
        assert_eq!(two_byte(0x08), None);
        assert_eq!(two_byte(0x10), None);
        assert_eq!(two_byte(0x1B), None);
    }

    /// Acceptance #4: fixed instruction size is 1..=11 for every opcode and
    /// consistent with its operand type.
    #[test]
    fn instruction_sizes_match_operand_types() {
        for op in ALL {
            let expected = match op.operand_type {
                OperandType::InlineNone => op.size as usize,
                OperandType::InlineSwitch => op.size as usize + 4,
                _ => op.size as usize + op.operand_type.size().unwrap(),
            };
            let size = instruction_size(*op);
            assert!((1..=11).contains(&size), "{} size {} outside 1..=11", op.name, size);
            assert_eq!(size, expected, "{}", op.name);
        }
        assert_eq!(instruction_size(NOP), 1);
        assert_eq!(instruction_size(BR_S), 2);
        assert_eq!(instruction_size(LDC_I8), 9);
        assert_eq!(instruction_size(LEAVE), 5);
        assert_eq!(instruction_size(SWITCH), 5); // + count dword; targets extra
    }

    #[test]
    fn names_follow_csharp_fields() {
        assert_eq!(LDC_I4_S.name, "ldc.i4.s");
        assert_eq!(BNE_UN_S.name, "bne.un.s");
        assert_eq!(CONV_OVF_I1_UN.name, "conv.ovf.i1.un");
        assert_eq!(LDARG_0.name, "ldarg.0");
        assert_eq!(READONLY.name, "readonly.");
    }
}
