//! ECMA-335 II §23.2 signature blob codec.
//!
//! Ports the reading logic of `Mono.Cecil/AssemblyReader.cs` (`SignatureReader`)
//! and the writing logic of `Mono.Cecil/AssemblyWriter.cs` (`SignatureWriter`)
//! onto the frozen [`super::types`] data model.
//!
//! Decoding `CLASS` / `VALUETYPE` / `GENERICINST` / `CMOD_*` elements requires a
//! bidirectional bridge to the module's `TypeDefOrRef` tables, abstracted by
//! [`SigContext`]: forward encoding asks for the coded cell ([`SigContext::tdor_cell`])
//! and the class/value-type marker ([`SigContext::is_value_type`]); decoding maps a
//! cell back to a [`TypeDesc`] via [`SigContext::tdor_type`].

use cecli_core::flags::{
    SignatureCallingConvention, CALL_CONVENTION_EXPLICIT_THIS, CALL_CONVENTION_HAS_THIS,
};
use cecli_core::io::{ByteReader, ByteWriter};
use cecli_core::{ElementType, Error, Result};

use super::types::{
    ConstantValue, FieldSignature, LocalVariable, MethodSignature, PropertySignature, TypeDesc,
};

// ---------------------------------------------------------------------------
// Context trait
// ---------------------------------------------------------------------------

/// Bridge between signature blobs and a module's `TypeDefOrRef` coded index space.
///
/// The two required methods serve the *writing* direction; [`SigContext::tdor_type`]
/// serves the *reading* direction and defaults to an error for contexts that cannot
/// resolve cells back into the object model.
pub trait SigContext {
    /// Returns the encoded TypeDefOrRef cell (2 tag bits + row id) for types that are
    /// encoded as a bare table reference: `Def`, `External`, the definition of a
    /// `GenericInstance`, or a `CMod` modifier.
    fn tdor_cell(&self, ty: &TypeDesc) -> Result<u32>;

    /// Returns whether the given definition/reference type must be marked
    /// `VALUETYPE` (as opposed to `CLASS`) when written into a blob.
    fn is_value_type(&self, ty: &TypeDesc) -> Result<bool>;

    /// Maps an encoded TypeDefOrRef cell read from a blob back into a
    /// [`TypeDesc::Def`] or [`TypeDesc::External`]. `value_type` mirrors the
    /// marker byte that preceded the cell.
    ///
    /// The default implementation always fails; contexts backed by real metadata
    /// token maps override it.
    fn tdor_type(&self, value_type: bool, cell: u32) -> Result<TypeDesc> {
        let _ = value_type;
        let _ = cell;
        Err(Error::unsupported("this SigContext cannot decode TypeDefOrRef cells"))
    }
}

impl SigContext for () {
    fn tdor_cell(&self, _ty: &TypeDesc) -> Result<u32> {
        Err(Error::unsupported("unit SigContext cannot encode TypeDefOrRef cells"))
    }

    fn is_value_type(&self, _ty: &TypeDesc) -> Result<bool> {
        Err(Error::unsupported("unit SigContext cannot classify TypeDefOrRef cells"))
    }
}

// ---------------------------------------------------------------------------
// Element type codes
// ---------------------------------------------------------------------------

const ET_VOID: u8 = 0x01;
const ET_VALUE_TYPE: u8 = ElementType::ValueType as u8;
const ET_CLASS: u8 = ElementType::Class as u8;
const ET_GENERIC_INST: u8 = ElementType::GenericInst as u8;
const ET_VAR: u8 = ElementType::Var as u8;
const ET_MVAR: u8 = ElementType::MVar as u8;
const ET_FNPTR: u8 = ElementType::FnPtr as u8;
const ET_CMOD_REQD: u8 = ElementType::CmodReqd as u8;
const ET_CMOD_OPT: u8 = ElementType::CmodOpt as u8;
const ET_SENTINEL: u8 = ElementType::Sentinel as u8;
const ET_INTERNAL: u8 = ElementType::Internal as u8;
const ET_PTR: u8 = ElementType::Ptr as u8;
const ET_BYREF: u8 = ElementType::ByRef as u8;
const ET_FIELD: u8 = 0x06;
const ET_LOCAL_SIG: u8 = 0x07;
const ET_PROPERTY: u8 = 0x08;
const ET_PINNED: u8 = ElementType::Pinned as u8;
const ET_SZ_ARRAY: u8 = ElementType::SzArray as u8;
const ET_ARRAY: u8 = ElementType::Array as u8;
const ET_TYPED_BYREF: u8 = ElementType::TypedByRef as u8;

/// Canonical ILAsm-style names used for [`TypeDesc::Internal`] encodings of
/// element-type primitives.
fn primitive_code(name: &str) -> Option<u8> {
    Some(match name {
        "void" => ET_VOID,
        "bool" => 0x02,
        "char" => 0x03,
        "int8" | "sbyte" => 0x04,
        "uint8" | "byte" => 0x05,
        "int16" | "short" => 0x06,
        "uint16" | "ushort" => 0x07,
        "int32" => 0x08,
        "uint32" => 0x09,
        "int64" | "long" => 0x0A,
        "uint64" | "ulong" => 0x0B,
        "float32" | "single" => 0x0C,
        "float64" | "double" => 0x0D,
        "string" => 0x0E,
        "intptr" => 0x18,
        "uintptr" => 0x19,
        "object" => 0x1C,
        _ => return None,
    })
}

/// Inverse of [`primitive_code`]; aliases normalize to the first canonical name.
fn primitive_name(code: u8) -> Option<&'static str> {
    Some(match code {
        ET_VOID => "void",
        0x02 => "bool",
        0x03 => "char",
        0x04 => "int8",
        0x05 => "uint8",
        0x06 => "int16",
        0x07 => "uint16",
        0x08 => "int32",
        0x09 => "uint32",
        0x0A => "int64",
        0x0B => "uint64",
        0x0C => "float32",
        0x0D => "float64",
        0x0E => "string",
        0x18 => "intptr",
        0x19 => "uintptr",
        0x1C => "object",
        _ => return None,
    })
}

fn bad_element(code: u8) -> Error {
    Error::bad_image(format!("unknown signature element type 0x{code:02X}"))
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// Reads one type element at the reader's current position.
///
/// `ELEMENT_TYPE_VOID` is tolerated anywhere (C++/CLI mixed images; Cecil does
/// the same), so no return-slot flag is needed.
fn read_type_elem(r: &mut ByteReader, ctx: &dyn SigContext) -> Result<TypeDesc> {
    let et = r.u8()?;
    match et {
        // ELEMENT_TYPE_VOID outside return slots appears in C++/CLI mixed
        // images; Cecil tolerates it, so we map it to the canonical internal.
        ET_VOID => Ok(TypeDesc::Internal("void".into())),
        code if primitive_name(code).is_some() => {
            Ok(TypeDesc::Internal(primitive_name(code).unwrap().into()))
        }
        ET_VALUE_TYPE | ET_CLASS => ctx.tdor_type(et == ET_VALUE_TYPE, r.compressed_u32()?),
        ET_PTR => Ok(TypeDesc::Ptr(Box::new(read_type_elem(r, ctx)?))),
        ET_BYREF => Ok(TypeDesc::ByRef(Box::new(read_type_elem(r, ctx)?))),
        ET_PINNED => Ok(TypeDesc::Pinned(Box::new(read_type_elem(r, ctx)?))),
        ET_SZ_ARRAY => Ok(TypeDesc::SzArray(Box::new(read_type_elem(r, ctx)?))),
        ET_ARRAY => read_array_elem(r, ctx),
        ET_GENERIC_INST => {
            let marker = r.u8()?;
            if marker != ET_VALUE_TYPE && marker != ET_CLASS {
                return Err(Error::bad_image(format!(
                    "GENERICINST marker 0x{marker:02X} is neither CLASS nor VALUETYPE"
                )));
            }
            let definition = Box::new(ctx.tdor_type(marker == ET_VALUE_TYPE, r.compressed_u32()?)?);
            let arity = r.compressed_u32()?;
            let mut arguments = Vec::new();
            for _ in 0..arity {
                arguments.push(read_type_elem(r, ctx)?);
            }
            Ok(TypeDesc::GenericInstance { definition, arguments })
        }
        ET_VAR => Ok(TypeDesc::Var(compressed_index(r)?)),
        ET_MVAR => Ok(TypeDesc::MVar(compressed_index(r)?)),
        ET_FNPTR => {
            let sig = get_method_signature(r, ctx)?;
            Ok(TypeDesc::FnPtr(Box::new(sig)))
        }
        ET_CMOD_REQD | ET_CMOD_OPT => {
            let modifier = Box::new(ctx.tdor_type(false, r.compressed_u32()?)?);
            let unmodified = Box::new(read_type_elem(r, ctx)?);
            Ok(TypeDesc::CMod { required: et == ET_CMOD_REQD, modifier, unmodified })
        }
        ET_SENTINEL => Ok(TypeDesc::Sentinel),
        ET_TYPED_BYREF => Ok(TypeDesc::TypedByRef),
        ET_INTERNAL => {
            let len = r.compressed_u32()? as usize;
            let bytes = r.read_bytes(len)?;
            let name = std::str::from_utf8(bytes).map_err(|e| {
                Error::bad_image(format!("INTERNAL type has invalid UTF-8 name: {e}"))
            })?;
            Ok(TypeDesc::Internal(name.to_owned()))
        }
        _ => Err(bad_element(et)),
    }
}

fn compressed_index(r: &mut ByteReader) -> Result<u16> {
    let v = r.compressed_u32()?;
    u16::try_from(v)
        .map_err(|_| Error::bad_image(format!("generic parameter index {v} exceeds u16")))
}

/// Multi-dimensional array element: rank, sizes count + sizes, lower-bound count + bounds.
fn read_array_elem(r: &mut ByteReader, ctx: &dyn SigContext) -> Result<TypeDesc> {
    let element = Box::new(read_type_elem(r, ctx)?);
    let rank = r.compressed_u32()?;
    let num_sizes = r.compressed_u32()?;
    let mut sizes = Vec::new();
    for _ in 0..num_sizes {
        let s = r.compressed_u32()?;
        let s = i32::try_from(s)
            .map_err(|_| Error::bad_image(format!("array size {s} exceeds i32")))?;
        sizes.push(s);
    }
    let num_lo = r.compressed_u32()?;
    let mut lobounds = Vec::new();
    for _ in 0..num_lo {
        lobounds.push(r.compressed_i32()?);
    }
    if rank == 0 || num_sizes > rank || num_lo > rank {
        return Err(Error::bad_image(format!(
            "array rank {rank} incompatible with {num_sizes} sizes and {num_lo} lower bounds"
        )));
    }
    Ok(TypeDesc::Array { element, sizes, lobounds })
}

/// Reads a method signature body starting at its convention byte
/// (port of `SignatureReader.ReadMethodSignature`).
fn get_method_signature(r: &mut ByteReader, ctx: &dyn SigContext) -> Result<MethodSignature> {
    let raw = r.u8()?;
    let has_this = raw & CALL_CONVENTION_HAS_THIS != 0;
    let explicit_this = raw & CALL_CONVENTION_EXPLICIT_THIS != 0;
    let generic_flag = raw & 0x10 != 0;
    let convention = match raw & 0x0F {
        0x0 => SignatureCallingConvention::Default,
        0x1 => SignatureCallingConvention::C,
        0x2 => SignatureCallingConvention::StdCall,
        0x3 => SignatureCallingConvention::ThisCall,
        0x4 => SignatureCallingConvention::FastCall,
        0x5 => SignatureCallingConvention::VarArg,
        0x9 => SignatureCallingConvention::Unmanaged,
        low => {
            return Err(Error::unsupported(format!(
                "calling convention byte 0x{low:X} is not a method calling convention"
            )))
        }
    };
    let generic_count = if generic_flag {
        let n = r.compressed_u32()?;
        u16::try_from(n).map_err(|_| Error::bad_image(format!("generic arity {n} exceeds u16")))?
    } else {
        0
    };

    let param_count = r.compressed_u32()?;
    let return_type = read_type_elem(r, ctx)?;

    let mut parameters = Vec::new();
    let mut vararg: Option<usize> = None;
    for _ in 0..param_count {
        // A SENTINEL prefixes the first vararg parameter; it shares the blob
        // slot with that parameter (Cecil's SentinelType wrapping).
        let pos = r.position();
        if pos < r.len() && r.bytes()[pos] == ET_SENTINEL {
            if convention != SignatureCallingConvention::VarArg {
                return Err(Error::bad_image("SENTINEL outside a vararg parameter list"));
            }
            if vararg.is_some() {
                return Err(Error::bad_image("duplicate SENTINEL in parameter list"));
            }
            r.seek(pos + 1)?;
            vararg = Some(parameters.len());
        }
        parameters.push(read_type_elem(r, ctx)?);
    }

    let vararg_start = vararg.unwrap_or(parameters.len());

    Ok(MethodSignature {
        has_this,
        explicit_this,
        convention,
        generic_count,
        parameters,
        return_type,
        vararg_start,
    })
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Writes one type element (ECMA-335 II §23.2.12) into `w`.
pub fn write_type_element(ty: &TypeDesc, w: &mut ByteWriter, ctx: &dyn SigContext) -> Result<()> {
    match ty {
        TypeDesc::Internal(name) => match primitive_code(name) {
            Some(code) => w.u8(code),
            None => {
                w.u8(ET_INTERNAL);
                write_ser_string(w, name);
            }
        },
        TypeDesc::Def(_) | TypeDesc::External(_) => write_named_ref(ty, w, ctx)?,
        TypeDesc::GenericInstance { definition, arguments } => {
            w.u8(ET_GENERIC_INST);
            w.u8(if ctx.is_value_type(definition)? { ET_VALUE_TYPE } else { ET_CLASS });
            w.compressed_u32(ctx.tdor_cell(definition)?);
            w.compressed_u32(arguments.len() as u32);
            for arg in arguments {
                write_type_element(arg, w, ctx)?;
            }
        }
        TypeDesc::SzArray(e) => {
            w.u8(ElementType::SzArray as u8);
            write_type_element(e, w, ctx)?;
        }
        TypeDesc::Array { element, sizes, lobounds } => {
            // Rank is not stored separately in the model; it is the larger of the
            // two bound-vector lengths (a fully unspecified rank collapses).
            let rank = sizes.len().max(lobounds.len());
            if rank == 0 {
                return Err(Error::argument("array type carries no rank information"));
            }
            w.u8(ElementType::Array as u8);
            write_type_element(element, w, ctx)?;
            w.compressed_u32(rank as u32);
            w.compressed_u32(sizes.len() as u32);
            for &s in sizes {
                let s = u32::try_from(s).map_err(|_| {
                    Error::argument(format!("negative array size {s} cannot be encoded"))
                })?;
                w.compressed_u32(s);
            }
            w.compressed_u32(lobounds.len() as u32);
            for &lb in lobounds {
                w.compressed_i32(lb);
            }
        }
        TypeDesc::Ptr(e) => {
            w.u8(ElementType::Ptr as u8);
            write_type_element(e, w, ctx)?;
        }
        TypeDesc::ByRef(e) => {
            w.u8(ElementType::ByRef as u8);
            write_type_element(e, w, ctx)?;
        }
        TypeDesc::Pinned(e) => {
            w.u8(ElementType::Pinned as u8);
            write_type_element(e, w, ctx)?;
        }
        TypeDesc::Var(i) => {
            w.u8(ET_VAR);
            w.compressed_u32(*i as u32);
        }
        TypeDesc::MVar(i) => {
            w.u8(ET_MVAR);
            w.compressed_u32(*i as u32);
        }
        TypeDesc::FnPtr(sig) => {
            w.u8(ET_FNPTR);
            put_method_signature(w, sig, ctx)?;
        }
        TypeDesc::CMod { required, modifier, unmodified } => {
            w.u8(if *required { ET_CMOD_REQD } else { ET_CMOD_OPT });
            w.compressed_u32(ctx.tdor_cell(modifier)?);
            write_type_element(unmodified, w, ctx)?;
        }
        TypeDesc::Sentinel => w.u8(ET_SENTINEL),
        TypeDesc::TypedByRef => w.u8(ElementType::TypedByRef as u8),
    }
    Ok(())
}

/// Writes the `CLASS|VALUETYPE + cell` pair for a definition/reference type.
fn write_named_ref(ty: &TypeDesc, w: &mut ByteWriter, ctx: &dyn SigContext) -> Result<()> {
    let value_type = ctx.is_value_type(ty)?;
    w.u8(if value_type { ET_VALUE_TYPE } else { ET_CLASS });
    w.compressed_u32(ctx.tdor_cell(ty)?);
    Ok(())
}

/// Compressed-length UTF-8 string (used only by the INTERNAL escape hatch).
fn write_ser_string(w: &mut ByteWriter, s: &str) {
    w.compressed_u32(s.len() as u32);
    w.bytes(s.as_bytes());
}

/// Writes a method signature body starting at the convention byte.
fn put_method_signature(
    w: &mut ByteWriter,
    sig: &MethodSignature,
    ctx: &dyn SigContext,
) -> Result<()> {
    if sig.explicit_this && !sig.has_this {
        return Err(Error::argument("EXPLICIT_THIS requires HAS_THIS in a method signature"));
    }
    if sig.convention != SignatureCallingConvention::VarArg
        && sig.vararg_start != sig.parameters.len()
    {
        return Err(Error::argument("vararg_start is only meaningful for VARARG signatures"));
    }

    let generic = sig.generic_count > 0;
    let mut conv = match sig.convention {
        // Generic is represented by generic_count > 0 plus the 0x10 flag.
        SignatureCallingConvention::Generic => SignatureCallingConvention::Default as u8,
        c => c as u8,
    };
    if sig.has_this {
        conv |= CALL_CONVENTION_HAS_THIS;
    }
    if sig.explicit_this {
        conv |= CALL_CONVENTION_EXPLICIT_THIS;
    }
    if generic {
        conv |= 0x10;
    }

    w.u8(conv);
    if generic {
        w.compressed_u32(sig.generic_count as u32);
    }
    w.compressed_u32(sig.parameters.len() as u32);
    write_type_element(&sig.return_type, w, ctx)?;

    for (i, param) in sig.parameters.iter().enumerate() {
        // The sentinel shares the slot of the first vararg parameter.
        if sig.convention == SignatureCallingConvention::VarArg
            && i == sig.vararg_start
            && i < sig.parameters.len()
        {
            w.u8(ET_SENTINEL);
        }
        write_type_element(param, w, ctx)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parses a full method reference/definition signature (ECMA-335 II §23.2.1/23.2.2).
pub fn parse_method_signature(blob: &[u8], ctx: &dyn SigContext) -> Result<MethodSignature> {
    let mut r = ByteReader::new(blob);
    get_method_signature(&mut r, ctx)
}

/// Parses a field signature: `0x06` followed by the field type.
pub fn parse_field_signature(blob: &[u8], ctx: &dyn SigContext) -> Result<FieldSignature> {
    let mut r = ByteReader::new(blob);
    expect_prolog(&mut r, ET_FIELD, "field")?;
    Ok(FieldSignature(read_type_elem(&mut r, ctx)?))
}

/// Parses a property signature (ECMA-335 II §23.2.5): `0x08 [| HAS_THIS]`,
/// compressed index-parameter count, property type, then the index parameters.
pub fn parse_property_signature(blob: &[u8], ctx: &dyn SigContext) -> Result<PropertySignature> {
    let mut r = ByteReader::new(blob);
    let raw = r.u8()?;
    let has_this = raw & CALL_CONVENTION_HAS_THIS != 0;
    if raw & !(CALL_CONVENTION_HAS_THIS | CALL_CONVENTION_EXPLICIT_THIS) != ET_PROPERTY {
        return Err(Error::bad_image(format!("expected PROPERTY prolog 0x08, found 0x{raw:02X}")));
    }
    let param_count = r.compressed_u32()?;
    let property_type = read_type_elem(&mut r, ctx)?;
    let mut parameters = Vec::new();
    for _ in 0..param_count {
        parameters.push(read_type_elem(&mut r, ctx)?);
    }
    Ok(PropertySignature { has_this, parameters, property_type })
}

/// Parses a stand-alone local variable signature (`0x07` + count + elements).
/// Slot indices are assigned sequentially from 0.
pub fn parse_local_var_sig(blob: &[u8], ctx: &dyn SigContext) -> Result<Vec<LocalVariable>> {
    let mut r = ByteReader::new(blob);
    expect_prolog(&mut r, ET_LOCAL_SIG, "local variable signature")?;
    let count = r.compressed_u32()?;
    let mut vars = Vec::new();
    for index in 0..count {
        let pinned = {
            let pos = r.position();
            if pos < r.len() && r.bytes()[pos] == ElementType::Pinned as u8 {
                r.seek(pos + 1)?;
                true
            } else {
                false
            }
        };
        vars.push(LocalVariable {
            index: u16::try_from(index)
                .map_err(|_| Error::bad_image(format!("local slot {index} exceeds u16")))?,
            ty: read_type_elem(&mut r, ctx)?,
            pinned,
        });
    }
    Ok(vars)
}

/// Parses one type element starting at `pos`; returns the descriptor and the
/// number of bytes consumed. Reused by constant/attribute decoding paths.
///
/// `allow_void` is accepted for call-site compatibility but is advisory only:
/// `ELEMENT_TYPE_VOID` is tolerated in any position, matching Cecil.
pub fn parse_type_element(
    blob: &[u8],
    pos: usize,
    ctx: &dyn SigContext,
    _allow_void: bool,
) -> Result<(TypeDesc, usize)> {
    if pos > blob.len() {
        return Err(Error::bad_image(format!(
            "type element offset {pos} beyond blob length {}",
            blob.len()
        )));
    }
    let mut r = ByteReader::at(blob, pos);
    let ty = read_type_elem(&mut r, ctx)?;
    Ok((ty, r.position() - pos))
}

/// Encodes a method signature (convention byte through trailing parameters).
pub fn write_method_signature(sig: &MethodSignature, ctx: &dyn SigContext) -> Result<Vec<u8>> {
    let mut w = ByteWriter::new();
    put_method_signature(&mut w, sig, ctx)?;
    Ok(w.into_vec())
}

/// Encodes a field signature (`0x06` + field type).
pub fn write_field_signature(s: &FieldSignature, ctx: &dyn SigContext) -> Result<Vec<u8>> {
    let mut w = ByteWriter::new();
    w.u8(ET_FIELD);
    write_type_element(&s.0, &mut w, ctx)?;
    Ok(w.into_vec())
}

/// Encodes a property signature (`0x08 [| HAS_THIS]` + count + type + params).
pub fn write_property_signature(s: &PropertySignature, ctx: &dyn SigContext) -> Result<Vec<u8>> {
    let mut w = ByteWriter::new();
    let mut prolog = ET_PROPERTY;
    if s.has_this {
        prolog |= CALL_CONVENTION_HAS_THIS;
    }
    w.u8(prolog);
    w.compressed_u32(s.parameters.len() as u32);
    write_type_element(&s.property_type, &mut w, ctx)?;
    for p in &s.parameters {
        write_type_element(p, &mut w, ctx)?;
    }
    Ok(w.into_vec())
}

/// Encodes a local variable signature (`0x07` + count + elements, PINNED prefix
/// per pinned slot). Uses the unit context: locals whose types require a
/// TypeDefOrRef cell fail with [`Error::Unsupported`].
pub fn write_local_var_sig(vars: &[LocalVariable]) -> Result<Vec<u8>> {
    let mut w = ByteWriter::new();
    w.u8(ET_LOCAL_SIG);
    w.compressed_u32(vars.len() as u32);
    for v in vars {
        if v.pinned {
            w.u8(ElementType::Pinned as u8);
        }
        write_type_element(&v.ty, &mut w, &())?;
    }
    Ok(w.into_vec())
}

// ---------------------------------------------------------------------------
// Constant blobs
// ---------------------------------------------------------------------------

/// Decodes a `Constant` row payload according to its declared element type.
///
/// String constants are raw UTF-16LE payloads (Mono.Cecil `ReadConstantString`:
/// an odd trailing byte is dropped before decoding); `NullRef` accepts either
/// an empty blob or the historical 4-byte zero blob.
pub fn parse_constant_blob(et: ElementType, blob: &[u8]) -> Result<ConstantValue> {
    let mut r = ByteReader::new(blob);
    Ok(match et {
        ElementType::Boolean => ConstantValue::Boolean(match r.u8()? {
            0 => false,
            1 => true,
            b => return Err(Error::bad_image(format!("boolean constant byte {b:#04x}"))),
        }),
        ElementType::Char => {
            let v = r.u16()?;
            ConstantValue::Char(char::from_u32(v as u32).ok_or_else(|| {
                Error::bad_image(format!("char constant 0x{v:04X} is not a scalar value"))
            })?)
        }
        ElementType::I1 => ConstantValue::I8(r.i8()?),
        ElementType::U1 => ConstantValue::U8(r.u8()?),
        ElementType::I2 => ConstantValue::I16(r.i16()?),
        ElementType::U2 => ConstantValue::U16(r.u16()?),
        ElementType::I4 => ConstantValue::I32(r.i32()?),
        ElementType::U4 => ConstantValue::U32(r.u32()?),
        ElementType::I8 => ConstantValue::I64(r.i64()?),
        ElementType::U8 => ConstantValue::U64(r.u64()?),
        ElementType::R4 => ConstantValue::F32(r.f32()?),
        ElementType::R8 => ConstantValue::F64(r.f64()?),
        ElementType::Class | ElementType::ValueType => {
            if r.is_empty() || blob == [0, 0, 0, 0] {
                ConstantValue::NullRef
            } else {
                return Err(Error::bad_image(
                    "class constant payload must be empty or a zeroed 4-byte field",
                ));
            }
        }
        ElementType::String => {
            let units: Vec<u16> = blob[..blob.len() & !1]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            ConstantValue::String(String::from_utf16_lossy(&units))
        }
        other => {
            return Err(Error::unsupported(format!("{other:?} is not a constant element type")))
        }
    })
}

/// Encodes a constant value; returns the `ElementType` tag byte plus payload.
///
/// String constants emit their UTF-16LE bytes under the `ELEMENT_TYPE_STRING`
/// (0x0E) tag, mirroring `SignatureWriter.WriteConstantString`; `NullRef` emits
/// an empty payload tagged `CLASS`.
pub fn write_constant_blob(v: &ConstantValue) -> Result<(u8, Vec<u8>)> {
    let mut w = ByteWriter::new();
    let et = match v {
        ConstantValue::Boolean(b) => {
            w.u8(*b as u8);
            ElementType::Boolean as u8
        }
        ConstantValue::Char(c) => {
            // .NET char constants are single UTF-16 code units.
            w.u16(*c as u16);
            ElementType::Char as u8
        }
        ConstantValue::I8(x) => {
            w.i8(*x);
            ElementType::I1 as u8
        }
        ConstantValue::U8(x) => {
            w.u8(*x);
            ElementType::U1 as u8
        }
        ConstantValue::I16(x) => {
            w.i16(*x);
            ElementType::I2 as u8
        }
        ConstantValue::U16(x) => {
            w.u16(*x);
            ElementType::U2 as u8
        }
        ConstantValue::I32(x) => {
            w.i32(*x);
            ElementType::I4 as u8
        }
        ConstantValue::U32(x) => {
            w.u32(*x);
            ElementType::U4 as u8
        }
        ConstantValue::I64(x) => {
            w.i64(*x);
            ElementType::I8 as u8
        }
        ConstantValue::U64(x) => {
            w.u64(*x);
            ElementType::U8 as u8
        }
        ConstantValue::F32(f) => {
            w.f32(*f); // bit-preserving: writes f.to_bits()
            ElementType::R4 as u8
        }
        ConstantValue::F64(f) => {
            w.f64(*f);
            ElementType::R8 as u8
        }
        ConstantValue::String(s) => {
            for unit in s.encode_utf16() {
                w.u16(unit);
            }
            ElementType::String as u8
        }
        ConstantValue::NullRef => ElementType::Class as u8,
    };
    Ok((et, w.into_vec()))
}

fn expect_prolog(r: &mut ByteReader, expected: u8, what: &str) -> Result<()> {
    let got = r.u8()?;
    if got != expected {
        return Err(Error::bad_image(format!(
            "expected {what} prolog 0x{expected:02X}, found 0x{got:02X}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{AssemblyNameReference, ExternalType, ScopeRef, TypeId};
    use std::collections::HashMap;

    const NS: &str = "System";

    fn ext(name: &str) -> ExternalType {
        ExternalType {
            namespace: NS.to_owned(),
            name: name.to_owned(),
            nesting: Vec::new(),
            scope: ScopeRef::Assembly(AssemblyNameReference::new("mscorlib")),
        }
    }

    fn external(name: &str) -> TypeDesc {
        TypeDesc::External(Box::new(ext(name)))
    }

    /// Test context: `Def(TypeId(n))` <-> TypeDef rid `n+1` (cell `(n+1)<<2`),
    /// known externals get fixed TypeRef cells (tag 1). `Def(TypeId(2))` is a
    /// value type so GENERICINST/CRef marker paths are exercised both ways.
    struct TestCtx {
        vt_cells: HashMap<u32, bool>,
    }

    impl TestCtx {
        fn new() -> Self {
            let mut vt_cells = HashMap::new();
            vt_cells.insert((2 + 1) << 2, true); // Def(TypeId(2)) is a value type
            vt_cells.insert(7, false); // List`1 typeref
            vt_cells.insert(5, false); // String typeref
            vt_cells.insert(9, false); // IsVolatile-like modifier typeref
            vt_cells.insert(4, false); // Def(TypeId(0)) used as CMod modifier
            TestCtx { vt_cells }
        }

        fn cell_for(ty: &TypeDesc) -> Result<u32> {
            match ty {
                TypeDesc::Def(id) => Ok((id.0 + 1) << 2),
                TypeDesc::External(e) => match e.name.as_str() {
                    "String" => Ok(5),
                    "List`1" => Ok(7),
                    "IsVolatile" => Ok(9),
                    other => Err(Error::argument(format!("no cell mapped for {other}"))),
                },
                TypeDesc::GenericInstance { definition, .. } => Self::cell_for(definition),
                TypeDesc::CMod { modifier, .. } => Self::cell_for(modifier),
                other => Err(Error::argument(format!("no cell mapped for {other:?}"))),
            }
        }
    }

    impl SigContext for TestCtx {
        fn tdor_cell(&self, ty: &TypeDesc) -> Result<u32> {
            Self::cell_for(ty)
        }

        fn is_value_type(&self, ty: &TypeDesc) -> Result<bool> {
            Ok(match ty {
                TypeDesc::Def(id) => id.0 == 2,
                _ => false,
            })
        }

        fn tdor_type(&self, value_type: bool, cell: u32) -> Result<TypeDesc> {
            if self.vt_cells.get(&cell) != Some(&value_type) {
                return Err(Error::bad_image(format!(
                    "cell {cell}#{value_type} contradicts context classification"
                )));
            }
            match cell {
                5 => Ok(external("String")),
                7 => Ok(external("List`1")),
                9 => Ok(external("IsVolatile")),
                c if c & 3 == 0 && c >= 4 => Ok(TypeDesc::Def(TypeId((c >> 2) - 1))),
                _ => Err(Error::bad_image(format!("unmapped cell {cell}"))),
            }
        }
    }

    fn i32t() -> TypeDesc {
        TypeDesc::Internal("int32".into())
    }

    fn voidt() -> TypeDesc {
        TypeDesc::Internal("void".into())
    }

    fn roundtrip_method(sig: MethodSignature) {
        let blob = write_method_signature(&sig, &TestCtx::new()).expect("write");
        let parsed = parse_method_signature(&blob, &TestCtx::new()).expect("parse");
        assert_eq!(parsed, sig, "roundtrip mismatch, blob = {blob:02X?}");
    }

    #[test]
    fn method_default_instance_void_int() {
        roundtrip_method(MethodSignature {
            has_this: true,
            explicit_this: false,
            convention: SignatureCallingConvention::Default,
            generic_count: 0,
            parameters: vec![i32t()],
            return_type: voidt(),
            vararg_start: 1,
        });
    }

    #[test]
    fn method_static_generic_complex_params() {
        let list_of_string = TypeDesc::GenericInstance {
            definition: Box::new(external("List`1")),
            arguments: vec![external("String")],
        };
        let int_ptr_array = TypeDesc::SzArray(Box::new(TypeDesc::Ptr(Box::new(i32t()))));
        roundtrip_method(MethodSignature {
            has_this: false,
            explicit_this: false,
            convention: SignatureCallingConvention::Default,
            generic_count: 1,
            parameters: vec![list_of_string, int_ptr_array],
            return_type: TypeDesc::ByRef(Box::new(TypeDesc::Internal("char".into()))),
            vararg_start: 2,
        });
    }

    #[test]
    fn method_vararg_with_sentinel() {
        roundtrip_method(MethodSignature {
            has_this: true,
            explicit_this: false,
            convention: SignatureCallingConvention::VarArg,
            generic_count: 0,
            parameters: vec![i32t(), external("String")],
            return_type: voidt(),
            vararg_start: 1,
        });
    }

    #[test]
    fn method_native_calling_conventions_roundtrip() {
        // Mixed-mode images carry unmanaged native conventions in the low
        // nibble (ECMA-335 II §23.2.1); each must survive a blob roundtrip.
        for (conv, byte) in [
            (SignatureCallingConvention::C, 0x21u8),
            (SignatureCallingConvention::StdCall, 0x22),
            (SignatureCallingConvention::ThisCall, 0x23),
            (SignatureCallingConvention::FastCall, 0x24),
        ] {
            let sig = MethodSignature {
                has_this: true,
                explicit_this: false,
                convention: conv,
                generic_count: 0,
                parameters: vec![i32t()],
                return_type: voidt(),
                vararg_start: 1,
            };
            roundtrip_method(sig.clone());
            assert_eq!(
                write_method_signature(&sig, &TestCtx::new()).unwrap()[0],
                byte,
                "convention {conv:?} lost its raw encoding"
            );
        }
    }

    #[test]
    fn method_fnptr_parameter() {
        let inner = MethodSignature {
            has_this: true,
            explicit_this: false,
            convention: SignatureCallingConvention::Default,
            generic_count: 0,
            parameters: vec![i32t()],
            return_type: voidt(),
            vararg_start: 1,
        };
        roundtrip_method(MethodSignature {
            has_this: true,
            explicit_this: false,
            convention: SignatureCallingConvention::Default,
            generic_count: 0,
            parameters: vec![TypeDesc::FnPtr(Box::new(inner))],
            return_type: voidt(),
            vararg_start: 1,
        });
    }

    #[test]
    fn field_with_cmod_roundtrip() {
        let sig = FieldSignature(TypeDesc::CMod {
            required: true,
            modifier: Box::new(TypeDesc::Def(TypeId(0))),
            unmodified: Box::new(i32t()),
        });
        let blob = write_field_signature(&sig, &TestCtx::new()).expect("write");
        assert_eq!(blob[0], 0x06);
        assert_eq!(blob[1], ET_CMOD_REQD);
        let parsed = parse_field_signature(&blob, &TestCtx::new()).expect("parse");
        assert_eq!(parsed, sig);

        // Optional modifier path too.
        let opt = FieldSignature(TypeDesc::CMod {
            required: false,
            modifier: Box::new(external("IsVolatile")),
            unmodified: Box::new(TypeDesc::Internal("float32".into())),
        });
        let blob = write_field_signature(&opt, &TestCtx::new()).unwrap();
        assert_eq!(blob[1], ET_CMOD_OPT);
        assert_eq!(parse_field_signature(&blob, &TestCtx::new()).unwrap(), opt);
    }

    #[test]
    fn property_sig_with_has_this_and_index_params() {
        let sig = PropertySignature {
            has_this: true,
            parameters: vec![i32t(), external("String")],
            property_type: external("String"),
        };
        let blob = write_property_signature(&sig, &TestCtx::new()).expect("write");
        assert_eq!(blob[0], 0x08 | CALL_CONVENTION_HAS_THIS);
        let parsed = parse_property_signature(&blob, &TestCtx::new()).expect("parse");
        assert_eq!(parsed, sig);
    }

    #[test]
    fn local_var_sig_pinned_and_byref() {
        let vars = vec![
            LocalVariable { index: 0, ty: TypeDesc::Internal("bool".into()), pinned: true },
            LocalVariable { index: 1, ty: TypeDesc::ByRef(Box::new(i32t())), pinned: false },
        ];
        let blob = write_local_var_sig(&vars).expect("write");
        assert_eq!(blob, vec![0x07, 0x02, 0x45, 0x02, 0x10, 0x08]);
        let parsed = parse_local_var_sig(&blob, &TestCtx::new()).expect("parse");
        assert_eq!(parsed, vars);
    }

    #[test]
    fn parse_type_element_reports_consumed_bytes() {
        let blob = [ElementType::SzArray as u8, ElementType::I4 as u8];
        let (ty, used) = parse_type_element(&blob, 0, &TestCtx::new(), false).expect("parse");
        assert_eq!(ty, TypeDesc::SzArray(Box::new(i32t())));
        assert_eq!(used, 2);

        // Offset start works too.
        let blob = [0xFF, ElementType::MVar as u8, 0x03];
        let (ty, used) = parse_type_element(&blob, 1, &TestCtx::new(), false).expect("parse");
        assert_eq!(ty, TypeDesc::MVar(3));
        assert_eq!(used, 2);
    }

    #[test]
    fn array_with_sizes_and_lobounds_roundtrip() {
        let mut w = ByteWriter::new();
        let ty = TypeDesc::Array {
            element: Box::new(i32t()),
            sizes: vec![10, 20],
            lobounds: vec![-1, 0],
        };
        write_type_element(&ty, &mut w, &TestCtx::new()).unwrap();
        let blob = w.into_vec();
        let (parsed, _) = parse_type_element(&blob, 0, &TestCtx::new(), false).unwrap();
        assert_eq!(parsed, ty);
    }

    #[test]
    fn generic_instance_value_type_marker_roundtrip() {
        // Def(TypeId(2)) is registered as a value type in TestCtx.
        let ty = TypeDesc::GenericInstance {
            definition: Box::new(TypeDesc::Def(TypeId(2))),
            arguments: vec![i32t()],
        };
        let mut w = ByteWriter::new();
        write_type_element(&ty, &mut w, &TestCtx::new()).unwrap();
        let blob = w.into_vec();
        assert_eq!(blob[0], ET_GENERIC_INST);
        assert_eq!(blob[1], ET_VALUE_TYPE, "value-type definition must use VALUETYPE marker");
        let (parsed, _) = parse_type_element(&blob, 0, &TestCtx::new(), false).unwrap();
        assert_eq!(parsed, ty);
    }

    #[test]
    fn constants_roundtrip_all_variants() {
        let cases: Vec<(ConstantValue, ElementType)> = vec![
            (ConstantValue::Boolean(true), ElementType::Boolean),
            (ConstantValue::Boolean(false), ElementType::Boolean),
            (ConstantValue::Char('A'), ElementType::Char),
            (ConstantValue::Char('\u{2764}'), ElementType::Char),
            (ConstantValue::I8(i8::MIN), ElementType::I1),
            (ConstantValue::U8(u8::MAX), ElementType::U1),
            (ConstantValue::I16(i16::MIN), ElementType::I2),
            (ConstantValue::U16(u16::MAX), ElementType::U2),
            (ConstantValue::I32(i32::MIN), ElementType::I4),
            (ConstantValue::U32(u32::MAX), ElementType::U4),
            (ConstantValue::I64(i64::MIN), ElementType::I8),
            (ConstantValue::U64(u64::MAX), ElementType::U8),
            (ConstantValue::F32(f32::NAN), ElementType::R4),
            (ConstantValue::F32(f32::INFINITY), ElementType::R4),
            (ConstantValue::F64(-f64::NAN), ElementType::R8),
            (ConstantValue::NullRef, ElementType::Class),
        ];
        for (value, et) in cases {
            let (tag, payload) = write_constant_blob(&value).expect("write");
            assert_eq!(tag, et as u8, "element tag for {value:?}");
            let back = parse_constant_blob(et, &payload).expect("parse");
            match (&back, &value) {
                (ConstantValue::F32(a), ConstantValue::F32(b)) => {
                    assert_eq!(a.to_bits(), b.to_bits())
                }
                (ConstantValue::F64(a), ConstantValue::F64(b)) => {
                    assert_eq!(a.to_bits(), b.to_bits())
                }
                _ => assert_eq!(back, value),
            }
        }

        // NaN bits survive verbatim.
        let nan_bits = 0x7FC0_1234u32;
        let (_, payload) =
            write_constant_blob(&ConstantValue::F32(f32::from_bits(nan_bits))).unwrap();
        assert_eq!(payload, nan_bits.to_le_bytes());

        // Historical 4-byte zero class blob also decodes as NullRef.
        assert_eq!(
            parse_constant_blob(ElementType::ValueType, &[0, 0, 0, 0]).unwrap(),
            ConstantValue::NullRef
        );
    }

    #[test]
    fn string_constants_roundtrip_utf16le() {
        // ASCII, non-ASCII, emoji (surrogate pair), empty.
        for s in ["hi", "héllo wörld", "日本語テキスト", "emoji: \u{1F600}", ""] {
            let (tag, payload) = write_constant_blob(&ConstantValue::String(s.into())).unwrap();
            assert_eq!(tag, ElementType::String as u8);
            // Raw payload is UTF-16LE.
            let expected: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
            assert_eq!(payload, expected, "utf16le bytes for {s:?}");
            let back = parse_constant_blob(ElementType::String, &payload).unwrap();
            assert_eq!(back, ConstantValue::String(s.into()), "roundtrip {s:?}");
        }

        // Odd-length blob: Cecil's reader drops the trailing byte.
        let (_, mut payload) = write_constant_blob(&ConstantValue::String("abc".into())).unwrap();
        payload.push(0xAA);
        assert_eq!(
            parse_constant_blob(ElementType::String, &payload).unwrap(),
            ConstantValue::String("abc".into())
        );

        // Empty blob decodes to the empty string.
        assert_eq!(
            parse_constant_blob(ElementType::String, &[]).unwrap(),
            ConstantValue::String(String::new())
        );
    }

    #[test]
    fn malformed_blobs_error() {
        // Empty / truncated method signatures.
        assert!(parse_method_signature(&[], &TestCtx::new()).is_err());
        let good = write_method_signature(
            &MethodSignature {
                has_this: true,
                explicit_this: false,
                convention: SignatureCallingConvention::Default,
                generic_count: 0,
                parameters: vec![i32t()],
                return_type: voidt(),
                vararg_start: 1,
            },
            &TestCtx::new(),
        )
        .unwrap();
        assert!(parse_method_signature(&good[..good.len() - 1], &TestCtx::new()).is_err());
        assert!(parse_method_signature(&good[..2], &TestCtx::new()).is_err());

        // Bad prologs.
        assert!(parse_field_signature(&[0x07, 0x08], &TestCtx::new()).is_err());
        assert!(parse_local_var_sig(&[0x06, 0x00], &TestCtx::new()).is_err());
        assert!(parse_property_signature(&[0x06, 0x00, 0x01], &TestCtx::new()).is_err());

        // Unknown element type.
        assert!(parse_method_signature(&[0x20, 0x00, 0x99], &TestCtx::new()).is_err());
        assert!(parse_field_signature(&[0x06, 0x39, 0x00], &TestCtx::new()).is_err());

        // Truncated constant payloads.
        assert!(parse_constant_blob(ElementType::I4, &[1, 2, 3]).is_err());
        assert!(parse_constant_blob(ElementType::Boolean, &[]).is_err());
        assert!(parse_constant_blob(ElementType::Char, &[1]).is_err());

        // Sentinel outside vararg lists: DEFAULT|HAS_THIS, 1 param, void ret, sentinel, i32.
        let bad = [0x20, 0x01, 0x01, 0x41, 0x08];
        assert!(parse_method_signature(&bad, &TestCtx::new()).is_err());
    }

    #[test]
    fn unit_context_errors_on_tdor_requests() {
        let ctx = ();
        assert!(ctx.tdor_cell(&TypeDesc::Def(TypeId(0))).is_err());
        assert!(ctx.is_value_type(&TypeDesc::Def(TypeId(0))).is_err());
        assert!(ctx.tdor_type(true, 4).is_err());
    }

    #[test]
    fn explicit_this_requires_has_this_on_write() {
        let sig = MethodSignature {
            has_this: false,
            explicit_this: true,
            convention: SignatureCallingConvention::Default,
            generic_count: 0,
            parameters: Vec::new(),
            return_type: voidt(),
            vararg_start: 0,
        };
        assert!(write_method_signature(&sig, &TestCtx::new()).is_err());
    }

    #[test]
    fn vararg_start_outside_vararg_convention_rejected() {
        let sig = MethodSignature {
            has_this: true,
            explicit_this: false,
            convention: SignatureCallingConvention::Default,
            generic_count: 0,
            parameters: vec![i32t()],
            return_type: voidt(),
            vararg_start: 0,
        };
        assert!(write_method_signature(&sig, &TestCtx::new()).is_err());
    }
}
