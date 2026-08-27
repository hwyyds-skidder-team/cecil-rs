//! ECMA-335 II §23.3 custom attribute argument blob codec.
//!
//! Two wire forms live side by side in this module:
//!
//! # Real-image form (constructor-signature driven)
//!
//! [`decode_attribute_args_for`] / [`write_attribute_args_for`] port the
//! layout Mono.Cecil reads in `Mono.Cecil/AssemblyReader.cs`
//! (`ReadCustomAttributeConstructorArguments`, `ReadCustomAttributeFixedArgument`,
//! `ReadCustomAttributeFixedArrayArgument`, `ReadCustomAttributeElement`,
//! `ReadCustomAttributeElementValue`, `ReadTypeReference`,
//! `ReadCustomAttributeFieldOrPropType`) and writes in `AssemblyWriter.cs`.
//! This is what every real assembly contains:
//!
//! ```text
//! prolog      : u16 = 0x0001                     (ECMA II 23.3)
//! fixed args  : one UNTAGGED value per constructor parameter, typed
//!               positionally by the ctor signature (an SZARRAY parameter
//!               reads a raw u32 count followed by untagged elements)
//! named_count : u16                              (ECMA II 23.3 NumNamed)
//! named args  : kind(0x53 field | 0x54 property)
//!             + FieldOrPropType tag chain + SerString(name) + value
//! ```
//!
//! There is no argument count and no per-fixed-arg type tag anywhere: the
//! number and types of the fixed arguments come from the attribute
//! constructor's method signature, which lives outside the blob.
//! `System.Type` values and enum references travel as UTF-8 full type names
//! (parsed via [`crate::type_parser::parse_type_name`]) — never as metadata
//! cells. Enum payloads are read at the width of the enum's true underlying
//! primitive when the caller supplies an [`EnumUnderlying`] callback;
//! otherwise they default to `i32` (documented fallback, lossy for enums
//! declared over wider types).
//!
//! # Self-described form (legacy, synthetic)
//!
//! [`decode_attribute_args`] / [`encode_attribute_args`] implement the
//! historical, deliberately self-contained layout below. It exists for
//! synthetic/test round-trips where no constructor signature is available;
//! it is NOT what real images contain. Real writers MUST use
//! [`write_attribute_args_for`].
//!
//! ```text
//! prolog      : u16 = 0x0001
//! fixed_count : u32                              (extension, see below)
//! fixed args  : tagged elements                  (extension, see below)
//! named_count : u16
//! named args  : kind + FieldOrPropType + SerString(name) + value
//! ```
//!
//! Deviations of the synthetic form from the raw ECMA layout:
//!
//! * a `u32` fixed-argument count follows the prolog, and
//! * every fixed argument is prefixed with the same `FieldOrPropType` byte a
//!   named-argument value uses.
//!
//! Further limitations, stated honestly:
//!
//! * Synthetic-form `System.Type` values are carried as compressed
//!   `TypeDefOrRef` cells passed through the caller-supplied resolver/encoder
//!   instead of Mono.Cecil's UTF-8 full type names, because this object model
//!   stores resolved [`TypeDesc`]s rather than parsed names. The real-image
//!   form uses UTF-8 names exactly like Cecil.
//! * Enum payloads in the synthetic form are always `i32`; 64-bit underlying
//!   enum types are rejected by [`encode_attribute_args`].
//! * A null array (`0xFFFFFFFF` count in real blobs) is rejected on decode in
//!   both forms; [`CArgument::Array`] cannot express it.
//! * The field/property distinction of a named argument is not representable
//!   in the `(String, CArgument)` tuple returned by the decoders.
//! * [`encode_attribute_args`] serialises every named entry with the field
//!   tag `0x53`, so the property tag stays unreachable through it.
//! * A null `System.Type` argument is written as a bare `0xFF` byte in the
//!   real-image form, and as `0x50 0xFF` (type slot with null marker) in the
//!   synthetic form so it stays distinguishable from a null object reference.

use cecli_core::io::{ByteReader, ByteWriter};
use cecli_core::{Error, Result};

use super::types::{CustomAttribute, ExternalType, ScopeRef, TypeDesc};

/// Prolog every custom attribute blob starts with (ECMA-335 II §23.3).
const PROLOG: u16 = 0x0001;

/// Attribute-only element-type codes (`Mono.Cecil.Metadata/ElementType.cs`,
/// "special undocumented constants").
const ET_TYPE: u8 = 0x50;
const ET_BOXED: u8 = 0x51;
const ET_ENUM: u8 = 0x55;

/// `ELEMENT_TYPE_SZARRAY`, prefix of array-valued arguments.
const ET_SZARRAY: u8 = 0x1d;

/// Null marker for strings and type references (`0xFF`, Mono.Cecil `ReadUTF8String`).
const NULL_MARKER: u8 = 0xff;

/// Named-argument kind byte: the entry targets a public field.
const NAMED_FIELD: u8 = 0x53;
/// Named-argument kind byte: the entry targets a public property.
const NAMED_PROPERTY: u8 = 0x54;

/// One decoded custom attribute value (constructor, named, or nested).
#[derive(Debug, Clone, PartialEq)]
pub enum CArgument {
    Bool(bool),
    Char(char),
    I8(i8),
    U8(u8),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    F32(f32),
    F64(f64),
    /// `None` is the `0xFF` null-string marker.
    String(Option<String>),
    /// `None` is the null-type marker (`0x50 0xFF` on the wire).
    Type(Option<TypeDesc>),
    /// A value of statically declared type `System.Object`.
    Boxed(Box<CArgument>),
    /// An enum member: the enum type plus its underlying primitive value.
    Enum {
        ty: TypeDesc,
        value: Box<CArgument>,
    },
    /// `SZARRAY` of values.
    Array(Vec<CArgument>),
    /// A typed null reference (bare `0xFF` element type).
    NullObj,
}

/// Resolves a compressed `TypeDefOrRef` coded index (encoded cell) into a
/// [`TypeDesc`]. Used while decoding enum types and `System.Type` values.
pub type TdorResolver<'a> = dyn FnMut(u32) -> Result<TypeDesc> + 'a;

/// Encodes a [`TypeDesc`] into a compressed `TypeDefOrRef` coded index
/// (encoded cell). Used while writing enum types and `System.Type` values.
pub type TdorEncoder<'a> = dyn FnMut(&TypeDesc) -> Result<u32> + 'a;

/// A named custom-attribute argument: `(name, value)`.
pub type NamedArgument = (String, CArgument);

/// Decoded custom-attribute arguments: the fixed (positional) arguments
/// followed by the named ones.
pub type AttributeArguments = (Vec<CArgument>, Vec<NamedArgument>);

/// A named custom-attribute argument retaining its kind byte
/// (`NAMED_FIELD` | `NAMED_PROPERTY`).
pub type NamedArgumentWithKind = (u8, String, CArgument);

/// Decodes a custom attribute blob in the *self-described synthetic form*
/// into its fixed (positional) and named arguments, validating the `0x0001`
/// prolog. Real images use the constructor-signature-driven layout instead:
/// see [`decode_attribute_args_for`].
///
/// `r` resolves `TypeDefOrRef` cells for enum types and `System.Type` values.
pub fn decode_attribute_args(blob: &[u8], r: &mut TdorResolver) -> Result<AttributeArguments> {
    let mut rd = ByteReader::new(blob);
    if rd.remaining() < 2 || rd.u16()? != PROLOG {
        return Err(Error::bad_image("custom attribute blob must start with the 0x0001 prolog"));
    }

    let fixed_count = rd.u32()?;
    let mut fixed = Vec::new();
    for _ in 0..fixed_count {
        fixed.push(read_element(&mut rd, r)?);
    }

    if rd.remaining() < 2 {
        return Err(Error::bad_image(
            "custom attribute blob truncated before named argument count",
        ));
    }
    let named_count = rd.u16()?;
    let mut named = Vec::new();
    for _ in 0..named_count {
        named.push(read_named_argument(&mut rd, r)?);
    }

    if !rd.is_empty() {
        return Err(Error::bad_image(
            "custom attribute blob has trailing bytes after the named arguments",
        ));
    }
    Ok((fixed, named))
}

/// Encodes fixed and named custom attribute arguments into a blob in the
/// *self-described synthetic form* (inverse of [`decode_attribute_args`]).
/// Real writers must use [`write_attribute_args_for`], which mirrors
/// Mono.Cecil's real-image layout.
///
/// Every named entry is written with the field tag (`0x53`); see the module
/// documentation for why the property tag is unreachable through this signature.
pub fn encode_attribute_args(
    fixed: &[CArgument],
    named: &[(String, CArgument)],
    e: &mut TdorEncoder,
) -> Result<Vec<u8>> {
    let mut w = ByteWriter::new();
    w.u16(PROLOG);
    w.u32(fixed.len() as u32);
    for arg in fixed {
        w.u8(discriminant(arg));
        write_typed_value(&mut w, arg, e)?;
    }
    if named.len() > u16::MAX as usize {
        return Err(Error::argument("too many named arguments for a CA blob"));
    }
    w.u16(named.len() as u16);
    for (name, arg) in named {
        write_named_argument(&mut w, NAMED_FIELD, name, arg, e)?;
    }
    Ok(w.into_vec())
}

/// Reads one named argument: kind byte, typed element, UTF-8 name, value.
pub(crate) fn read_named_argument(
    rd: &mut ByteReader,
    r: &mut TdorResolver,
) -> Result<(String, CArgument)> {
    let kind = rd.u8()?;
    if kind != NAMED_FIELD && kind != NAMED_PROPERTY {
        return Err(Error::bad_image(format!("invalid named argument kind 0x{kind:02X}")));
    }
    let tag = read_element_tag(rd)?;
    let name = read_ser_string(rd)?
        .ok_or_else(|| Error::bad_image("null marker where a named argument name was expected"))?;
    let value = read_typed_value(rd, tag, r)?;
    Ok((name, value))
}

/// Writes one named argument: kind byte, typed element, UTF-8 name, value.
pub(crate) fn write_named_argument(
    w: &mut ByteWriter,
    kind: u8,
    name: &str,
    arg: &CArgument,
    e: &mut TdorEncoder,
) -> Result<()> {
    if kind != NAMED_FIELD && kind != NAMED_PROPERTY {
        return Err(Error::argument(format!("invalid named argument kind 0x{kind:02X}")));
    }
    w.u8(kind);
    w.u8(discriminant(arg));
    write_ser_string(w, Some(name))?;
    write_typed_value(w, arg, e)
}

/// Reads a compressed-length UTF-8 string; `0xFF` yields `None` (port of
/// Mono.Cecil `ReadUTF8String`).
pub(crate) fn read_ser_string(rd: &mut ByteReader) -> Result<Option<String>> {
    if rd.remaining() == 0 {
        return Err(Error::bad_image("blob truncated before string"));
    }
    if rd.bytes()[rd.position()] == NULL_MARKER {
        rd.seek(rd.position() + 1)?;
        return Ok(None);
    }
    let len = rd.compressed_u32()? as usize;
    if rd.remaining() < len {
        return Err(Error::bad_image("string length exceeds blob"));
    }
    let s = std::str::from_utf8(rd.read_bytes(len)?)
        .map_err(|_| Error::bad_image("invalid UTF-8 in blob string"))?;
    Ok(Some(s.to_owned()))
}

/// Writes a compressed-length UTF-8 string; `None` writes the `0xFF` marker.
pub(crate) fn write_ser_string(w: &mut ByteWriter, s: Option<&str>) -> Result<()> {
    match s {
        None => w.u8(NULL_MARKER),
        Some(s) => {
            let b = s.as_bytes();
            if b.len() > 0x1fff_ffff {
                return Err(Error::argument("string too long for compressed length"));
            }
            w.compressed_u32(b.len() as u32);
            w.bytes(b);
        }
    }
    Ok(())
}

/// Discriminator byte of a tagged element, including the attribute-specific
/// `Type`/`Boxed`/`Enum` codes. Payloads (cells, strings, primitives) live in
/// the value body that follows, never in the tag itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ElemTag {
    Prim(u8),
    Str,
    Typ,
    Boxed,
    SzArray,
    Enm,
    Null,
}

fn discriminant(arg: &CArgument) -> u8 {
    match arg {
        CArgument::Bool(_) => 0x02,
        CArgument::Char(_) => 0x03,
        CArgument::I8(_) => 0x04,
        CArgument::U8(_) => 0x05,
        CArgument::I16(_) => 0x06,
        CArgument::U16(_) => 0x07,
        CArgument::I32(_) => 0x08,
        CArgument::U32(_) => 0x09,
        CArgument::I64(_) => 0x0a,
        CArgument::U64(_) => 0x0b,
        CArgument::F32(_) => 0x0c,
        CArgument::F64(_) => 0x0d,
        CArgument::String(_) => 0x0e,
        CArgument::Type(_) => ET_TYPE, // null type keeps the slot, null payload
        CArgument::Boxed(_) => ET_BOXED,
        CArgument::Enum { .. } => ET_ENUM,
        CArgument::Array(_) => ET_SZARRAY,
        CArgument::NullObj => NULL_MARKER,
    }
}

fn read_element_tag(rd: &mut ByteReader) -> Result<ElemTag> {
    Ok(match rd.u8()? {
        0x0e => ElemTag::Str,
        code @ 0x02..=0x0d => ElemTag::Prim(code),
        ET_TYPE => ElemTag::Typ,
        ET_ENUM => ElemTag::Enm,
        ET_BOXED => ElemTag::Boxed,
        ET_SZARRAY => ElemTag::SzArray,
        NULL_MARKER => ElemTag::Null,
        other => {
            return Err(Error::bad_image(format!("unknown attribute element type 0x{other:02X}")))
        }
    })
}

/// Reads the value body following a tag. Arrays store their element count as a
/// raw `u32` (ECMA II 23.3) and each element as a fully tagged value.
fn read_typed_value(rd: &mut ByteReader, tag: ElemTag, r: &mut TdorResolver) -> Result<CArgument> {
    Ok(match tag {
        ElemTag::Prim(code) => read_primitive(rd, code)?,
        ElemTag::Str => CArgument::String(read_ser_string(rd)?),
        // Null marker inside the type slot distinguishes Type(None) from NullObj.
        ElemTag::Typ => {
            if rd.remaining() > 0 && rd.bytes()[rd.position()] == NULL_MARKER {
                rd.seek(rd.position() + 1)?;
                CArgument::Type(None)
            } else {
                let cell = rd.compressed_u32()?;
                CArgument::Type(Some(r(cell)?))
            }
        }
        ElemTag::Boxed => CArgument::Boxed(Box::new(read_element(rd, r)?)),
        ElemTag::SzArray => {
            let count = rd.u32()?;
            if count == u32::MAX {
                return Err(Error::bad_image("null arrays are not supported"));
            }
            // Each element occupies at least its tag byte.
            if count as usize > rd.remaining() {
                return Err(Error::bad_image("array count exceeds blob size"));
            }
            let mut items = Vec::new();
            for _ in 0..count {
                items.push(read_element(rd, r)?);
            }
            CArgument::Array(items)
        }
        ElemTag::Enm => {
            let cell = rd.compressed_u32()?;
            let ty = r(cell)?;
            CArgument::Enum { ty, value: Box::new(CArgument::I32(rd.i32()?)) }
        }
        ElemTag::Null => CArgument::NullObj,
    })
}

/// Writes the value body following the discriminant byte.
fn write_typed_value(w: &mut ByteWriter, arg: &CArgument, e: &mut TdorEncoder) -> Result<()> {
    match arg {
        CArgument::Bool(b) => w.u8(u8::from(*b)),
        CArgument::Char(c) => w.u16(*c as u32 as u16),
        CArgument::I8(v) => w.i8(*v),
        CArgument::U8(v) => w.u8(*v),
        CArgument::I16(v) => w.i16(*v),
        CArgument::U16(v) => w.u16(*v),
        CArgument::I32(v) => w.i32(*v),
        CArgument::U32(v) => w.u32(*v),
        CArgument::I64(v) => w.i64(*v),
        CArgument::U64(v) => w.u64(*v),
        CArgument::F32(v) => w.f32(*v),
        CArgument::F64(v) => w.f64(*v),
        CArgument::String(s) => write_ser_string(w, s.as_deref())?,
        CArgument::Type(Some(ty)) => w.compressed_u32(e(ty)?),
        CArgument::Type(None) => w.u8(NULL_MARKER),
        CArgument::Boxed(inner) => {
            w.u8(discriminant(inner));
            write_typed_value(w, inner, e)?;
        }
        CArgument::Enum { ty, value } => {
            w.compressed_u32(e(ty)?);
            w.i32(enum_payload(value)?);
        }
        CArgument::Array(items) => {
            w.u32(items.len() as u32);
            for item in items {
                w.u8(discriminant(item));
                write_typed_value(w, item, e)?;
            }
        }
        CArgument::NullObj => {}
    }
    Ok(())
}

/// Reads a complete tagged element: discriminator byte followed by value.
fn read_element(rd: &mut ByteReader, r: &mut TdorResolver) -> Result<CArgument> {
    let tag = read_element_tag(rd)?;
    read_typed_value(rd, tag, r)
}

/// Primitive value reader keyed by the `ELEMENT_TYPE_*` byte (port of
/// Mono.Cecil `ReadPrimitiveValue`; boolean true is the byte `1`).
fn read_primitive(rd: &mut ByteReader, code: u8) -> Result<CArgument> {
    Ok(match code {
        0x02 => CArgument::Bool(rd.u8()? == 1),
        0x03 => {
            CArgument::Char(char::from_u32(rd.u16()? as u32).unwrap_or(char::REPLACEMENT_CHARACTER))
        }
        0x04 => CArgument::I8(rd.i8()?),
        0x05 => CArgument::U8(rd.u8()?),
        0x06 => CArgument::I16(rd.i16()?),
        0x07 => CArgument::U16(rd.u16()?),
        0x08 => CArgument::I32(rd.i32()?),
        0x09 => CArgument::U32(rd.u32()?),
        0x0a => CArgument::I64(rd.i64()?),
        0x0b => CArgument::U64(rd.u64()?),
        0x0c => CArgument::F32(rd.f32()?),
        0x0d => CArgument::F64(rd.f64()?),
        other => {
            return Err(Error::bad_image(format!("unknown primitive element type 0x{other:02X}")))
        }
    })
}

/// Reduces an enum payload to its `i32` storage form, rejecting anything the
/// documented `i32`-only representation cannot carry.
fn enum_payload(value: &CArgument) -> Result<i32> {
    Ok(match value {
        CArgument::Bool(b) => i32::from(*b),
        CArgument::Char(c) => *c as u32 as i32,
        CArgument::I8(v) => i32::from(*v),
        CArgument::U8(v) => i32::from(*v),
        CArgument::I16(v) => i32::from(*v),
        CArgument::U16(v) => i32::from(*v),
        CArgument::I32(v) => *v,
        CArgument::U32(v) => i32::try_from(*v)
            .map_err(|_| Error::argument("enum value does not fit in the i32 payload"))?,
        CArgument::I64(_) | CArgument::U64(_) => {
            return Err(Error::argument(
                "64-bit enum underlying types are not supported by the attribute codec",
            ))
        }
        other => return Err(Error::argument(format!("invalid enum underlying value {other:?}"))),
    })
}
// ---------------------------------------------------------------------------
// Real-image form: constructor-signature-driven codec.
//
// Faithful port of Mono.Cecil's actual blob layout (`AssemblyReader.cs`:
// `ReadCustomAttributeConstructorArguments`, `ReadCustomAttributeFixedArgument`,
// `ReadCustomAttributeFixedArrayArgument`, `ReadCustomAttributeElement`,
// `ReadCustomAttributeElementValue`, `ReadTypeReference`,
// `ReadCustomAttributeFieldOrPropType`; mirrored by the writers in
// `AssemblyWriter.cs`). After the prolog the fixed argument values follow
// UNTAGGED, typed positionally by the constructor parameter list; only named
// entries carry a `FieldOrPropType` tag chain.

/// Callback deriving the `ELEMENT_TYPE_*` code (`0x02..=0x0d`) of an enum
/// type's true underlying primitive from its [`TypeDesc`] (port of Cecil's
/// `TypeReference.GetEnumUnderlyingType`). When no callback is supplied the
/// underlying type defaults to `ELEMENT_TYPE_I4` (`0x08`) — the overwhelmingly
/// common case; this fallback is lossy for enums declared over other widths.
pub type EnumUnderlying<'a> = dyn Fn(&TypeDesc) -> Result<u8> + 'a;

/// How a declared type maps onto the attribute wire (the *known*-type side
/// of Mono.Cecil `ReadCustomAttributeFieldOrPropType`).
#[derive(Debug, Clone, PartialEq)]
enum Fpt {
    /// Primitive with its `ELEMENT_TYPE_*` code.
    Prim(u8),
    Str,
    Typ,
    /// `System.Object`: the value carries its own tag chain.
    Obj,
    Arr(Box<Fpt>),
    /// Enum or any other class: a raw underlying-primitive value on the wire.
    Enm(TypeDesc),
}

/// Wire classification of well-known fully-qualified type names; `None` for
/// everything else (which lands on the enum/class path).
fn fpt_of_wire_name(name: &str) -> Option<Fpt> {
    Some(match name {
        "System.Boolean" => Fpt::Prim(0x02),
        "System.Char" => Fpt::Prim(0x03),
        "System.SByte" => Fpt::Prim(0x04),
        "System.Byte" => Fpt::Prim(0x05),
        "System.Int16" => Fpt::Prim(0x06),
        "System.UInt16" => Fpt::Prim(0x07),
        "System.Int32" => Fpt::Prim(0x08),
        "System.UInt32" => Fpt::Prim(0x09),
        "System.Int64" => Fpt::Prim(0x0a),
        "System.UInt64" => Fpt::Prim(0x0b),
        "System.Single" => Fpt::Prim(0x0c),
        "System.Double" => Fpt::Prim(0x0d),
        "System.String" => Fpt::Str,
        "System.Type" => Fpt::Typ,
        "System.Object" => Fpt::Obj,
        _ => return None,
    })
}

/// Full name of an external type in Mono.Cecil `FullName` spelling
/// (`Namespace.Outer/Inner`).
fn external_wire_name(ext: &ExternalType) -> String {
    let mut s = String::new();
    if !ext.namespace.is_empty() {
        s.push_str(&ext.namespace);
        s.push('.');
    }
    let mut parts: Vec<&str> = ext.nesting.iter().map(|b| b.name.as_str()).collect();
    parts.push(&ext.name);
    s.push_str(&parts.join("/"));
    s
}

/// Wire name of a [`TypeDesc`] for `System.Type` values and enum references.
/// Only name-carrying forms can be rendered without module context.
fn type_wire_name(ty: &TypeDesc) -> Result<String> {
    match ty {
        TypeDesc::External(ext) => Ok(external_wire_name(ext)),
        TypeDesc::Internal(name) => Ok(name.clone()),
        other => Err(Error::argument(format!(
            "{other:?} cannot be rendered as a UTF-8 wire type name without module context"
        ))),
    }
}

/// Parses a UTF-8 wire type name (port of Cecil `ReadTypeReference`).
/// Parsed references carry no assembly scope ([`ScopeRef::Moduleless`])
/// because the blob does not record one.
fn parse_wire_type(name: &str) -> Result<TypeDesc> {
    crate::type_parser::parse_type_name(name, ScopeRef::Moduleless)
}

/// Classifies a constructor-parameter type (port of Cecil dispatching
/// `ReadCustomAttributeElement` on the parameter's `etype`).
fn fpt_of_param(ty: &TypeDesc) -> Result<Fpt> {
    match ty {
        // SZARRAY parameter: raw u32 count + untagged elements on the wire.
        TypeDesc::SzArray(elem) => Ok(Fpt::Arr(Box::new(fpt_of_param(elem)?))),
        // A generic instantiation can only be an enum here; its generic
        // arguments have no effect (Cecil `ReadCustomAttributeElementValue`).
        TypeDesc::GenericInstance { definition, .. } => fpt_of_param(definition),
        TypeDesc::External(ext) => {
            let name = external_wire_name(ext);
            if name == "System.Void" {
                return Err(Error::argument("void cannot be a custom attribute argument"));
            }
            Ok(fpt_of_wire_name(&name).unwrap_or_else(|| Fpt::Enm(ty.clone())))
        }
        TypeDesc::Internal(name) => {
            if name == "System.Void" || name == "void" {
                return Err(Error::argument("void cannot be a custom attribute argument"));
            }
            Ok(fpt_of_wire_name(name).unwrap_or_else(|| Fpt::Enm(ty.clone())))
        }
        // Def / Ptr / ByRef / CMod / ...: nominal type => enum-style value.
        _ => Ok(Fpt::Enm(ty.clone())),
    }
}

/// Resolves the primitive code an enum payload is stored at.
fn enum_underlying_code(ty: &TypeDesc, eu: Option<&EnumUnderlying>) -> Result<u8> {
    match eu {
        Some(f) => {
            let code = f(ty)?;
            if !(0x02..=0x0d).contains(&code) {
                return Err(Error::argument(format!(
                    "enum underlying element type 0x{code:02X} is not a primitive"
                )));
            }
            Ok(code)
        }
        // Documented i32 fallback.
        None => Ok(0x08),
    }
}

/// Reads a `System.Type` value: UTF-8 full type name with the `0xFF` null
/// marker (port of Cecil `ReadTypeReference`; a null name decodes to
/// [`CArgument::Type::None`]).
fn read_type_value(rd: &mut ByteReader) -> Result<CArgument> {
    match read_ser_string(rd)? {
        None => Ok(CArgument::Type(None)),
        Some(name) => parse_wire_type(&name).map(|ty| CArgument::Type(Some(ty))),
    }
}

/// Reads an enum payload at the width of the enum's underlying primitive
/// (port of `ReadCustomAttributeEnum`): no wire data names the enum here,
/// the type is known from context.
fn read_enum_payload(
    rd: &mut ByteReader,
    ty: &TypeDesc,
    eu: Option<&EnumUnderlying>,
) -> Result<CArgument> {
    let code = enum_underlying_code(ty, eu)?;
    let value = read_primitive(rd, code)?;
    Ok(CArgument::Enum { ty: ty.clone(), value: Box::new(value) })
}

/// Reads `count` + untagged elements of declared element shape `elem`
/// (shared body of `ReadCustomAttributeFixedArrayArgument`).
fn read_array_body(
    rd: &mut ByteReader,
    elem: &Fpt,
    eu: Option<&EnumUnderlying>,
) -> Result<Vec<CArgument>> {
    let count = rd.u32()?;
    if count == u32::MAX {
        return Err(Error::bad_image("null arrays are not supported"));
    }
    // Each element occupies at least one byte.
    if count as usize > rd.remaining() {
        return Err(Error::bad_image("array count exceeds blob size"));
    }
    let mut items = Vec::with_capacity(count as usize);
    for _ in 0..count {
        items.push(read_value_for(rd, elem, eu)?);
    }
    Ok(items)
}

/// Reads one UNTAGGED value of declared shape `fpt` (port of
/// `ReadCustomAttributeElementValue` / the value half of
/// `ReadCustomAttributeFixedArgument`).
fn read_value_for(
    rd: &mut ByteReader,
    fpt: &Fpt,
    eu: Option<&EnumUnderlying>,
) -> Result<CArgument> {
    Ok(match fpt {
        Fpt::Prim(code) => read_primitive(rd, *code)?,
        Fpt::Str => CArgument::String(read_ser_string(rd)?),
        Fpt::Typ => read_type_value(rd)?,
        Fpt::Obj => {
            // The boxed value carries its own tag chain; a bare `0xFF` is a
            // null object reference with no inner tag.
            let tag = rd.u8()?;
            if tag == NULL_MARKER {
                CArgument::NullObj
            } else {
                CArgument::Boxed(Box::new(read_tagged_value(rd, tag, eu)?))
            }
        }
        Fpt::Arr(elem) => CArgument::Array(read_array_body(rd, elem, eu)?),
        Fpt::Enm(enum_ty) => read_enum_payload(rd, enum_ty, eu)?,
    })
}

/// Reads a `FieldOrPropType` tag chain from the wire (port of Cecil
/// `ReadCustomAttributeFieldOrPropType`); `tag` is the already-consumed
/// first byte. Note that `Boxed` consumes only its own byte — the inner tag
/// belongs to the value position, after the named-argument name.
fn read_fpt_tag(rd: &mut ByteReader, tag: u8) -> Result<Fpt> {
    Ok(match tag {
        code @ 0x02..=0x0d => Fpt::Prim(code),
        0x0e => Fpt::Str,
        ET_TYPE => Fpt::Typ,
        ET_BOXED => Fpt::Obj,
        ET_SZARRAY => {
            let elem_tag = rd.u8()?;
            if elem_tag == NULL_MARKER {
                return Err(Error::bad_image(
                    "null marker where an array element type was expected",
                ));
            }
            Fpt::Arr(Box::new(read_fpt_tag(rd, elem_tag)?))
        }
        ET_ENUM => {
            let name = read_ser_string(rd)?.ok_or_else(|| {
                Error::bad_image("null marker where an enum type name was expected")
            })?;
            Fpt::Enm(parse_wire_type(&name)?)
        }
        NULL_MARKER => {
            return Err(Error::bad_image("null marker where a field-or-prop type was expected"))
        }
        other => {
            return Err(Error::bad_image(format!(
                "unknown field-or-prop element type 0x{other:02X}"
            )))
        }
    })
}

/// Reads the value body following a consumed `FieldOrPropType` tag byte
/// (boxed payloads and array-of-object elements; port of the value half of
/// Cecil `ReadCustomAttributeElement(Object)`).
fn read_tagged_value(
    rd: &mut ByteReader,
    tag: u8,
    eu: Option<&EnumUnderlying>,
) -> Result<CArgument> {
    Ok(match tag {
        code @ 0x02..=0x0d => read_primitive(rd, code)?,
        0x0e => CArgument::String(read_ser_string(rd)?),
        ET_TYPE => read_type_value(rd)?,
        NULL_MARKER => CArgument::NullObj,
        ET_BOXED => {
            let inner = rd.u8()?;
            if inner == NULL_MARKER {
                // Null references collapse to [`CArgument::NullObj`]
                // regardless of boxing depth (`0x51 0xFF`).
                CArgument::NullObj
            } else {
                CArgument::Boxed(Box::new(read_tagged_value(rd, inner, eu)?))
            }
        }
        ET_SZARRAY => {
            let elem_tag = rd.u8()?;
            let elem = read_fpt_tag(rd, elem_tag)?;
            CArgument::Array(read_array_body(rd, &elem, eu)?)
        }
        ET_ENUM => {
            let fpt = read_fpt_tag(rd, ET_ENUM)?;
            match &fpt {
                Fpt::Enm(ty) => read_enum_payload(rd, ty, eu)?,
                _ => unreachable!("ET_ENUM tag chain always yields Fpt::Enm"),
            }
        }
        other => {
            return Err(Error::bad_image(format!("unknown tagged element type 0x{other:02X}")))
        }
    })
}

/// Reads one named argument: kind byte, `FieldOrPropType` tag chain, UTF-8
/// name, value — exactly that order (port of
/// `ReadCustomAttributeNamedArgument`). Returns the retained kind byte.
fn read_named_argument_for(
    rd: &mut ByteReader,
    eu: Option<&EnumUnderlying>,
) -> Result<(u8, String, CArgument)> {
    let kind = rd.u8()?;
    if kind != NAMED_FIELD && kind != NAMED_PROPERTY {
        return Err(Error::bad_image(format!("invalid named argument kind 0x{kind:02X}")));
    }
    let tag = rd.u8()?;
    let fpt = read_fpt_tag(rd, tag)?;
    let name = read_ser_string(rd)?
        .ok_or_else(|| Error::bad_image("null marker where a named argument name was expected"))?;
    let value = read_value_for(rd, &fpt, eu)?;
    Ok((kind, name, value))
}

/// Decodes a custom attribute blob in the **real-image form**: fixed
/// arguments are consumed UNTAGGED, positionally against `ctor_params` (the
/// attribute constructor's method-signature parameter types), followed by
/// the self-describing named section.
///
/// Port of Mono.Cecil `ReadCustomAttributeConstructorArguments` +
/// `ReadCustomAttributeNamedArguments`. Enum payloads default to an `i32`
/// underlying width; use [`decode_attribute_args_for_ctx`] with an
/// [`EnumUnderlying`] callback when the enum's true underlying type differs.
pub fn decode_attribute_args_for(
    blob: &[u8],
    ctor_params: &[TypeDesc],
) -> Result<AttributeArguments> {
    decode_attribute_args_for_ctx(blob, ctor_params, None)
}

/// Like [`decode_attribute_args_for`] with an [`EnumUnderlying`] callback
/// deriving each enum parameter's true underlying primitive width.
pub fn decode_attribute_args_for_ctx(
    blob: &[u8],
    ctor_params: &[TypeDesc],
    enum_underlying: Option<&EnumUnderlying>,
) -> Result<AttributeArguments> {
    let mut rd = ByteReader::new(blob);
    if rd.remaining() < 2 || rd.u16()? != PROLOG {
        return Err(Error::bad_image("custom attribute blob must start with the 0x0001 prolog"));
    }

    let mut fixed = Vec::with_capacity(ctor_params.len());
    for ty in ctor_params {
        let fpt = fpt_of_param(ty)?;
        fixed.push(read_value_for(&mut rd, &fpt, enum_underlying)?);
    }

    if rd.remaining() < 2 {
        return Err(Error::bad_image(
            "custom attribute blob truncated before named argument count",
        ));
    }
    let named_count = rd.u16()?;
    let mut named = Vec::new();
    for _ in 0..named_count {
        let (_, name, value) = read_named_argument_for(&mut rd, enum_underlying)?;
        named.push((name, value));
    }

    if !rd.is_empty() {
        return Err(Error::bad_image(
            "custom attribute blob has trailing bytes after the named arguments",
        ));
    }
    Ok((fixed, named))
}

/// Writes a primitive at exactly the width of `code`, requiring `arg`'s
/// variant to agree with the declared element type.
fn write_primitive_as(w: &mut ByteWriter, code: u8, arg: &CArgument) -> Result<()> {
    match (code, arg) {
        (0x02, CArgument::Bool(b)) => w.u8(u8::from(*b)),
        (0x03, CArgument::Char(c)) => w.u16(*c as u32 as u16),
        (0x04, CArgument::I8(v)) => w.i8(*v),
        (0x05, CArgument::U8(v)) => w.u8(*v),
        (0x06, CArgument::I16(v)) => w.i16(*v),
        (0x07, CArgument::U16(v)) => w.u16(*v),
        (0x08, CArgument::I32(v)) => w.i32(*v),
        (0x09, CArgument::U32(v)) => w.u32(*v),
        (0x0a, CArgument::I64(v)) => w.i64(*v),
        (0x0b, CArgument::U64(v)) => w.u64(*v),
        (0x0c, CArgument::F32(v)) => w.f32(*v),
        (0x0d, CArgument::F64(v)) => w.f64(*v),
        _ => {
            return Err(Error::argument(format!(
                "argument {arg:?} does not match primitive element type 0x{code:02X}"
            )))
        }
    }
    Ok(())
}

/// Serialises a `FieldOrPropType` tag chain (mirror of [`read_fpt_tag`];
/// port of Cecil `WriteCustomAttributeFieldOrPropType`).
fn write_fpt_bytes(w: &mut ByteWriter, fpt: &Fpt) -> Result<()> {
    match fpt {
        Fpt::Prim(code) => w.u8(*code),
        Fpt::Str => w.u8(0x0e),
        Fpt::Typ => w.u8(ET_TYPE),
        Fpt::Obj => w.u8(ET_BOXED),
        Fpt::Arr(elem) => {
            w.u8(ET_SZARRAY);
            write_fpt_bytes(w, elem)?;
        }
        Fpt::Enm(ty) => {
            w.u8(ET_ENUM);
            write_ser_string(w, Some(&type_wire_name(ty)?))?;
        }
    }
    Ok(())
}

/// Derives the `FieldOrPropType` shape of a decoded value (inverse view of
/// [`fpt_of_param`], used wherever the wire describes the type itself).
/// Empty arrays carry the `Object` element placeholder — decodable back to
/// an empty array, since zero elements consume nothing.
fn fpt_of_arg(arg: &CArgument) -> Result<Fpt> {
    Ok(match arg {
        CArgument::Bool(_) => Fpt::Prim(0x02),
        CArgument::Char(_) => Fpt::Prim(0x03),
        CArgument::I8(_) => Fpt::Prim(0x04),
        CArgument::U8(_) => Fpt::Prim(0x05),
        CArgument::I16(_) => Fpt::Prim(0x06),
        CArgument::U16(_) => Fpt::Prim(0x07),
        CArgument::I32(_) => Fpt::Prim(0x08),
        CArgument::U32(_) => Fpt::Prim(0x09),
        CArgument::I64(_) => Fpt::Prim(0x0a),
        CArgument::U64(_) => Fpt::Prim(0x0b),
        CArgument::F32(_) => Fpt::Prim(0x0c),
        CArgument::F64(_) => Fpt::Prim(0x0d),
        CArgument::String(_) => Fpt::Str,
        CArgument::Type(_) => Fpt::Typ,
        CArgument::Boxed(_) => Fpt::Obj,
        CArgument::Enum { ty, .. } => Fpt::Enm(ty.clone()),
        CArgument::Array(items) => Fpt::Arr(Box::new(match items.first() {
            Some(first) => fpt_of_arg(first)?,
            None => Fpt::Obj,
        })),
        CArgument::NullObj => {
            return Err(Error::argument("a null reference carries no field-or-prop type"))
        }
    })
}

fn wire_mismatch(arg: &CArgument, fpt: &Fpt) -> Error {
    Error::argument(format!("argument {arg:?} does not match declared wire shape {fpt:?}"))
}

/// Writes one UNTAGGED value of declared shape `fpt` (mirror of
/// [`read_value_for`]; port of `WriteCustomAttributeValue`).
fn write_value_for(
    w: &mut ByteWriter,
    fpt: &Fpt,
    arg: &CArgument,
    eu: Option<&EnumUnderlying>,
) -> Result<()> {
    match fpt {
        Fpt::Prim(code) => write_primitive_as(w, *code, arg),
        Fpt::Str => match arg {
            CArgument::String(s) => write_ser_string(w, s.as_deref()),
            other => Err(wire_mismatch(other, fpt)),
        },
        Fpt::Typ => match arg {
            CArgument::Type(Some(ty)) => write_ser_string(w, Some(&type_wire_name(ty)?)),
            // Null type reference: bare `0xFF` marker.
            CArgument::Type(None) | CArgument::NullObj => {
                w.u8(NULL_MARKER);
                Ok(())
            }
            other => Err(wire_mismatch(other, fpt)),
        },
        Fpt::Obj => match arg {
            CArgument::Boxed(inner) => {
                let inner_fpt = fpt_of_arg(inner)?;
                write_fpt_bytes(w, &inner_fpt)?;
                write_value_for(w, &inner_fpt, inner, eu)
            }
            CArgument::NullObj => {
                w.u8(NULL_MARKER);
                Ok(())
            }
            other => Err(wire_mismatch(other, fpt)),
        },
        Fpt::Arr(elem) => match arg {
            CArgument::Array(items) => {
                w.u32(items.len() as u32);
                for item in items {
                    write_value_for(w, elem, item, eu)?;
                }
                Ok(())
            }
            other => Err(wire_mismatch(other, fpt)),
        },
        Fpt::Enm(enum_ty) => {
            let code = enum_underlying_code(enum_ty, eu)?;
            let payload = match arg {
                CArgument::Enum { value, .. } => value,
                other => other,
            };
            write_primitive_as(w, code, payload)
        }
    }
}

/// Writes one named argument: kind byte, derived `FieldOrPropType` tag
/// chain, UTF-8 name, value (port of
/// `WriteCustomAttributeNamedArgument`).
fn write_named_argument_for(
    w: &mut ByteWriter,
    kind: u8,
    name: &str,
    arg: &CArgument,
    eu: Option<&EnumUnderlying>,
) -> Result<()> {
    if kind != NAMED_FIELD && kind != NAMED_PROPERTY {
        return Err(Error::argument(format!("invalid named argument kind 0x{kind:02X}")));
    }
    w.u8(kind);
    let fpt = fpt_of_arg(arg)?;
    write_fpt_bytes(w, &fpt)?;
    write_ser_string(w, Some(name))?;
    write_value_for(w, &fpt, arg, eu)
}

/// Encodes fixed and named custom attribute arguments into a blob in the
/// **real-image form** (mirror of [`decode_attribute_args_for`]; port of
/// Cecil `WriteCustomAttributeConstructorArguments` +
/// `WriteCustomAttributeNamedArguments`). Fixed args are written UNTAGGED,
/// typed by `ctor_params`; every named entry uses the field tag (`0x53`)
/// because `(String, CArgument)` cannot carry the kind byte.
///
/// Unlike [`encode_attribute_args`] this produces blobs byte-compatible with
/// real images. Enum payloads are written at `i32` width unless an
/// [`EnumUnderlying`] callback is supplied via [`write_attribute_args_for_ctx`].
pub fn write_attribute_args_for(
    fixed: &[CArgument],
    named: &[(String, CArgument)],
    ctor_params: &[TypeDesc],
) -> Result<Vec<u8>> {
    write_attribute_args_for_ctx(fixed, named, ctor_params, None)
}

/// Like [`write_attribute_args_for`] with an [`EnumUnderlying`] callback
/// deriving each enum parameter's true underlying primitive width.
pub fn write_attribute_args_for_ctx(
    fixed: &[CArgument],
    named: &[(String, CArgument)],
    ctor_params: &[TypeDesc],
    enum_underlying: Option<&EnumUnderlying>,
) -> Result<Vec<u8>> {
    if fixed.len() != ctor_params.len() {
        return Err(Error::argument(format!(
            "{} fixed arguments for {} constructor parameters",
            fixed.len(),
            ctor_params.len()
        )));
    }
    if named.len() > u16::MAX as usize {
        return Err(Error::argument("too many named arguments for a CA blob"));
    }
    let mut w = ByteWriter::new();
    w.u16(PROLOG);
    for (arg, ty) in fixed.iter().zip(ctor_params) {
        let fpt = fpt_of_param(ty)?;
        write_value_for(&mut w, &fpt, arg, enum_underlying)?;
    }
    w.u16(named.len() as u16);
    for (name, arg) in named {
        write_named_argument_for(&mut w, NAMED_FIELD, name, arg, enum_underlying)?;
    }
    Ok(w.into_vec())
}

// ---------------------------------------------------------------------------
// Mono.Cecil `CustomAttribute` ergonomic surface.
//
// Mono.Cecil eagerly populates `ConstructorArguments`, `Properties`, and
// `Fields` while reading the attribute; this object model stores the raw blob,
// so the accessors below decode it on demand. [`decode_attribute_args`]
// discards each named argument's field/property kind byte (the
// `(String, CArgument)` tuple cannot carry it), so the split views go through
// the local [`decode_with_kinds`] instead.

/// Fully decodes a custom attribute blob, retaining each named argument's
/// kind byte (`0x53` field | `0x54` property). Validation mirrors
/// [`decode_attribute_args`] exactly; only the kind retention differs.
fn decode_with_kinds(
    blob: &[u8],
    r: &mut TdorResolver,
) -> Result<(Vec<CArgument>, Vec<NamedArgumentWithKind>)> {
    let mut rd = ByteReader::new(blob);
    if rd.remaining() < 2 || rd.u16()? != PROLOG {
        return Err(Error::bad_image("custom attribute blob must start with the 0x0001 prolog"));
    }

    let fixed_count = rd.u32()?;
    let mut fixed = Vec::new();
    for _ in 0..fixed_count {
        fixed.push(read_element(&mut rd, r)?);
    }

    if rd.remaining() < 2 {
        return Err(Error::bad_image(
            "custom attribute blob truncated before named argument count",
        ));
    }
    let named_count = rd.u16()?;
    let mut named = Vec::new();
    for _ in 0..named_count {
        let kind = rd.u8()?;
        if kind != NAMED_FIELD && kind != NAMED_PROPERTY {
            return Err(Error::bad_image(format!("invalid named argument kind 0x{kind:02X}")));
        }
        let tag = read_element_tag(&mut rd)?;
        let name = read_ser_string(&mut rd)?.ok_or_else(|| {
            Error::bad_image("null marker where a named argument name was expected")
        })?;
        let value = read_typed_value(&mut rd, tag, r)?;
        named.push((kind, name, value));
    }

    if !rd.is_empty() {
        return Err(Error::bad_image(
            "custom attribute blob has trailing bytes after the named arguments",
        ));
    }
    Ok((fixed, named))
}

impl CustomAttribute {
    /// Fixed (positional) constructor arguments. Port of
    /// Mono.Cecil `CustomAttribute.ConstructorArguments`.
    pub fn arguments(&self, r: &mut TdorResolver) -> Result<Vec<CArgument>> {
        Ok(decode_with_kinds(&self.blob, r)?.0)
    }

    /// Named arguments targeting public properties (`0x54`). Port of
    /// Mono.Cecil `CustomAttribute.Properties`.
    ///
    /// Note that [`encode_attribute_args`] serialises every named entry with
    /// the field tag (`0x53`), so round-tripped blobs surface all named
    /// arguments under [`Self::fields`] and none here.
    pub fn properties(&self, r: &mut TdorResolver) -> Result<Vec<NamedArgument>> {
        Ok(decode_with_kinds(&self.blob, r)?
            .1
            .into_iter()
            .filter(|(kind, _, _)| *kind == NAMED_PROPERTY)
            .map(|(_, name, value)| (name, value))
            .collect())
    }

    /// Named arguments targeting public fields (`0x53`). Port of
    /// Mono.Cecil `CustomAttribute.Fields`.
    pub fn fields(&self, r: &mut TdorResolver) -> Result<Vec<NamedArgument>> {
        Ok(decode_with_kinds(&self.blob, r)?
            .1
            .into_iter()
            .filter(|(kind, _, _)| *kind == NAMED_FIELD)
            .map(|(_, name, value)| (name, value))
            .collect())
    }

    /// The property named `name`, or `None`. Port of
    /// Mono.Cecil `CustomAttribute.Properties[name]`-style lookup.
    pub fn get_property(&self, name: &str, r: &mut TdorResolver) -> Result<Option<CArgument>> {
        Ok(self.properties(r)?.into_iter().find(|(n, _)| n == name).map(|(_, v)| v))
    }

    /// The field named `name`, or `None`. Port of
    /// Mono.Cecil `CustomAttribute.Fields[name]`-style lookup.
    pub fn get_field(&self, name: &str, r: &mut TdorResolver) -> Result<Option<CArgument>> {
        Ok(self.fields(r)?.into_iter().find(|(n, _)| n == name).map(|(_, v)| v))
    }

    /// True when the attribute carries at least one fixed constructor
    /// argument. Port of Mono.Cecil `CustomAttribute.HasConstructorArguments`.
    pub fn has_constructor_arguments(&self, r: &mut TdorResolver) -> Result<bool> {
        Ok(!self.arguments(r)?.is_empty())
    }

    /// Fixed (positional) constructor arguments decoded with the real-image
    /// (constructor-signature-driven) layout; port of Mono.Cecil
    /// `CustomAttribute.ConstructorArguments` as populated by
    /// `ReadCustomAttributeConstructorArguments`. `sig_ctx` lazily supplies
    /// the constructor method signature's parameter list — the blob itself
    /// carries neither the argument count nor their types.
    pub fn arguments_resolved(
        &self,
        sig_ctx: &dyn Fn() -> Result<Vec<TypeDesc>>,
    ) -> Result<Vec<CArgument>> {
        let params = sig_ctx()?;
        Ok(decode_attribute_args_for(&self.blob, &params)?.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{ExternalType, MethodId, MethodRef, ScopeRef};

    /// External `NS.<name>` used as the enum / `System.Type` stand-in.
    fn ext_ty(name: &str) -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: "NS".to_owned(),
            name: name.to_owned(),
            nesting: Vec::new(),
            scope: ScopeRef::Moduleless,
        }))
    }

    /// Resolver accepting exactly the cells produced by [`enc_cell`].
    fn resolver() -> impl FnMut(u32) -> Result<TypeDesc> {
        move |cell| match cell {
            7 => Ok(ext_ty("EnumTy")),
            9 => Ok(ext_ty("OtherTy")),
            other => Err(Error::bad_image(format!("unresolvable tdor cell {other}"))),
        }
    }

    fn enc_cell() -> impl FnMut(&TypeDesc) -> Result<u32> {
        move |ty| match ty {
            TypeDesc::External(e) if e.name == "EnumTy" => Ok(7),
            TypeDesc::External(e) if e.name == "OtherTy" => Ok(9),
            other => Err(Error::argument(format!("cannot encode {other:?}"))),
        }
    }

    /// Structural equality with NaN-aware float comparison.
    fn args_eq(a: &CArgument, b: &CArgument) -> bool {
        match (a, b) {
            (CArgument::F32(x), CArgument::F32(y)) => x.to_bits() == y.to_bits(),
            (CArgument::F64(x), CArgument::F64(y)) => x.to_bits() == y.to_bits(),
            (CArgument::Boxed(x), CArgument::Boxed(y)) => args_eq(x, y),
            (CArgument::Enum { ty: t1, value: v1 }, CArgument::Enum { ty: t2, value: v2 }) => {
                t1 == t2 && args_eq(v1, v2)
            }
            (CArgument::Array(xs), CArgument::Array(ys)) => {
                xs.len() == ys.len() && xs.iter().zip(ys).all(|(x, y)| args_eq(x, y))
            }
            _ => a == b,
        }
    }

    fn fixture() -> AttributeArguments {
        let fixed = vec![
            CArgument::Bool(true),
            CArgument::Bool(false),
            CArgument::Char('A'),
            CArgument::Char('\u{2603}'),
            CArgument::I8(-5),
            CArgument::U8(200),
            CArgument::I16(-300),
            CArgument::U16(60_000),
            CArgument::I32(-70_000),
            CArgument::U32(4_000_000_000),
            CArgument::I64(i64::MIN),
            CArgument::U64(u64::MAX),
            CArgument::F32(1.5),
            CArgument::F32(f32::NAN),
            CArgument::F32(f32::INFINITY),
            CArgument::F64(-2.25e-9),
            CArgument::F64(f64::NAN),
            CArgument::String(Some("h\u{e9}llo".to_owned())),
            CArgument::String(None),
            CArgument::Type(Some(ext_ty("OtherTy"))),
            CArgument::Type(None),
            CArgument::Boxed(Box::new(CArgument::I32(42))),
            CArgument::Boxed(Box::new(CArgument::String(Some("x".to_owned())))),
            CArgument::Enum { ty: ext_ty("EnumTy"), value: Box::new(CArgument::I32(7)) },
            CArgument::Array(vec![CArgument::I32(1), CArgument::I32(2)]),
            CArgument::Array(vec![]),
            CArgument::Array(vec![
                CArgument::String(Some("a".to_owned())),
                CArgument::String(None),
            ]),
            CArgument::NullObj,
        ];
        let named = vec![
            ("Flags".to_owned(), CArgument::I32(3)),
            ("Name".to_owned(), CArgument::String(Some("abc".to_owned()))),
            ("Xml".to_owned(), CArgument::String(None)),
            ("T".to_owned(), CArgument::Type(Some(ext_ty("OtherTy")))),
            ("TE".to_owned(), CArgument::Type(None)),
            ("Arr".to_owned(), CArgument::Array(vec![CArgument::I32(9)])),
            ("B".to_owned(), CArgument::Boxed(Box::new(CArgument::F64(2.5)))),
            (
                "En".to_owned(),
                CArgument::Enum { ty: ext_ty("EnumTy"), value: Box::new(CArgument::I32(255)) },
            ),
            ("Nul".to_owned(), CArgument::NullObj),
        ];
        (fixed, named)
    }

    #[test]
    fn roundtrip_all_fixed_and_named() {
        let (fixed, named) = fixture();
        let mut enc = enc_cell();
        let blob = encode_attribute_args(&fixed, &named, &mut enc).expect("encode");
        let mut res = resolver();
        let (fixed2, named2) = decode_attribute_args(&blob, &mut res).expect("decode");
        assert_eq!(fixed.len(), fixed2.len());
        assert_eq!(named.len(), named2.len());
        for (a, b) in fixed.iter().zip(&fixed2) {
            assert!(args_eq(a, b), "fixed arg mismatch: {a:?} vs {b:?}");
        }
        for ((n1, a1), (n2, a2)) in named.iter().zip(&named2) {
            assert_eq!(n1, n2);
            assert!(args_eq(a1, a2), "named arg mismatch: {a1:?} vs {a2:?}");
        }
    }

    #[test]
    fn encode_is_deterministic_and_stable_through_decode() {
        let (fixed, named) = fixture();
        let mut enc = enc_cell();
        let blob1 = encode_attribute_args(&fixed, &named, &mut enc).unwrap();
        let blob2 = encode_attribute_args(&fixed, &named, &mut enc).unwrap();
        assert_eq!(blob1, blob2);

        let mut res = resolver();
        let (f2, n2) = decode_attribute_args(&blob1, &mut res).unwrap();
        let blob3 = encode_attribute_args(&f2, &n2, &mut enc).unwrap();
        assert_eq!(blob1, blob3);
    }

    #[test]
    fn prolog_is_validated() {
        let mut res = resolver();
        assert!(decode_attribute_args(&[], &mut res).is_err());
        assert!(decode_attribute_args(&[0x02, 0x00], &mut res).is_err());
        assert!(decode_attribute_args(&[0x01], &mut res).is_err());
        // Correct prolog but truncated fixed-arg section.
        assert!(decode_attribute_args(&[0x01, 0x00, 0x01, 0x00, 0x00, 0x00], &mut res).is_err());
    }

    #[test]
    fn truncations_are_errors() {
        let (fixed, named) = fixture();
        let mut enc = enc_cell();
        let blob = encode_attribute_args(&fixed, &named, &mut enc).unwrap();
        let mut res = resolver();
        // Every proper prefix of a valid blob must fail to decode (the full
        // blob is the only self-consistent length).
        for cut in 0..blob.len() {
            assert!(
                decode_attribute_args(&blob[..cut], &mut res).is_err(),
                "prefix of length {cut} decoded successfully"
            );
        }
        // Trailing junk is rejected too.
        let mut extended = blob.clone();
        extended.push(0xff);
        assert!(decode_attribute_args(&extended, &mut res).is_err());
    }

    #[test]
    fn unknown_type_codes_are_rejected() {
        // prolog + fixed_count=1 + bogus element type 0x99
        let blob = [0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x99];
        let mut res = resolver();
        assert!(decode_attribute_args(&blob, &mut res).is_err());
    }

    #[test]
    fn invalid_named_kind_is_rejected() {
        // prolog + fixed_count=0 + named_count=1 + kind 0xAA
        let blob = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa];
        let mut res = resolver();
        assert!(decode_attribute_args(&blob, &mut res).is_err());
    }

    #[test]
    fn resolver_errors_propagate() {
        // Encoding an unencodable type fails on the encoder side.
        let fixed = vec![CArgument::Type(Some(TypeDesc::Sentinel))];
        let mut enc = enc_cell();
        assert!(encode_attribute_args(&fixed, &[], &mut enc).is_err());

        // A blob referencing an unresolvable cell fails during decode.
        let blob = [
            0x01, 0x00, // prolog
            0x01, 0x00, 0x00, 0x00, // fixed_count = 1
            0x50, 0x63, // Type with cell 0x63 (unresolvable)
            0x00, 0x00, // named_count = 0
        ];
        let mut res = resolver();
        assert!(decode_attribute_args(&blob, &mut res).is_err());
    }

    #[test]
    fn enum_with_wide_underlying_is_rejected_on_encode() {
        let fixed =
            vec![CArgument::Enum { ty: ext_ty("EnumTy"), value: Box::new(CArgument::I64(-1)) }];
        let mut enc = enc_cell();
        assert!(encode_attribute_args(&fixed, &[], &mut enc).is_err());
    }

    fn attr(blob: Vec<u8>) -> CustomAttribute {
        CustomAttribute { constructor: MethodRef::Def(MethodId(0)), blob }
    }

    #[test]
    fn accessor_views_agree_with_encoded_blob() {
        let fixed = vec![
            CArgument::I32(42),
            CArgument::String(Some("s".to_owned())),
            CArgument::Type(Some(ext_ty("OtherTy"))),
        ];
        let named =
            vec![("F".to_owned(), CArgument::Bool(true)), ("P".to_owned(), CArgument::U32(7))];
        let mut enc = enc_cell();
        let blob = encode_attribute_args(&fixed, &named, &mut enc).unwrap();
        let attribute = attr(blob);

        let mut res = resolver();
        assert!(attribute.has_constructor_arguments(&mut res).unwrap());

        let args = attribute.arguments(&mut res).unwrap();
        assert_eq!(args.len(), fixed.len());
        for (a, b) in args.iter().zip(&fixed) {
            assert!(args_eq(a, b), "{a:?} != {b:?}");
        }

        // encode_attribute_args writes every named entry with the field tag,
        // so all of them surface under fields() and none under properties().
        let fields = attribute.fields(&mut res).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].0, "F");
        assert!(args_eq(&fields[0].1, &CArgument::Bool(true)));
        assert_eq!(fields[1].0, "P");
        assert!(args_eq(&fields[1].1, &CArgument::U32(7)));
        assert!(attribute.properties(&mut res).unwrap().is_empty());

        assert!(
            matches!(attribute.get_field("F", &mut res).unwrap(), Some(v) if args_eq(&v, &CArgument::Bool(true)))
        );
        assert!(attribute.get_field("nope", &mut res).unwrap().is_none());
        // Missing property -> Ok(None), even though a same-named field exists.
        assert!(attribute.get_property("F", &mut res).unwrap().is_none());
        assert!(attribute.get_property("nope", &mut res).unwrap().is_none());
    }

    #[test]
    fn property_tagged_named_args_surface_under_properties() {
        // A hand-built blob mixing real property (0x54) and field (0x53)
        // named entries, as found in actual images.
        let mut enc = enc_cell();
        let mut w = ByteWriter::new();
        w.u16(PROLOG);
        w.u32(0); // fixed_count = 0
        w.u16(2); // named_count = 2
        write_named_argument(&mut w, NAMED_PROPERTY, "P", &CArgument::I16(-3), &mut enc).unwrap();
        write_named_argument(&mut w, NAMED_FIELD, "F", &CArgument::Bool(true), &mut enc).unwrap();
        let attribute = attr(w.into_vec());

        let mut res = resolver();
        assert!(!attribute.has_constructor_arguments(&mut res).unwrap());
        assert!(attribute.arguments(&mut res).unwrap().is_empty());

        let props = attribute.properties(&mut res).unwrap();
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].0, "P");
        assert!(args_eq(&props[0].1, &CArgument::I16(-3)));

        let fields = attribute.fields(&mut res).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, "F");
        assert!(args_eq(&fields[0].1, &CArgument::Bool(true)));

        assert!(
            matches!(attribute.get_property("P", &mut res).unwrap(), Some(v) if args_eq(&v, &CArgument::I16(-3)))
        );
        // Kind-aware lookups do not cross the field/property boundary.
        assert!(attribute.get_property("F", &mut res).unwrap().is_none());
        assert!(attribute.get_field("P", &mut res).unwrap().is_none());
    }

    #[test]
    fn accessor_rejects_malformed_blob() {
        let attribute = attr(vec![0xaa, 0xbb]); // no prolog
        let mut res = resolver();
        assert!(attribute.arguments(&mut res).is_err());
        assert!(attribute.properties(&mut res).is_err());
        assert!(attribute.fields(&mut res).is_err());
        assert!(attribute.has_constructor_arguments(&mut res).is_err());
    }
    // -------------------------------------------------------------------
    // Real-image (constructor-signature-driven) form.

    /// `System.<name>` external reference.
    fn sys(name: &str) -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: "System".to_owned(),
            name: name.to_owned(),
            nesting: Vec::new(),
            scope: ScopeRef::Moduleless,
        }))
    }

    #[test]
    fn real_form_int_argument() {
        // [A(42)] with ctor A(int): prolog, UNTAGGED i32, named count 0 —
        // exactly the layout real images carry (no count, no tags).
        let blob = [0x01, 0x00, 42, 0x00, 0x00, 0x00, 0x00, 0x00];
        let params = vec![sys("Int32")];
        let (fixed, named) = decode_attribute_args_for(&blob, &params).unwrap();
        assert_eq!(fixed, vec![CArgument::I32(42)]);
        assert!(named.is_empty());
    }

    #[test]
    fn real_form_string_and_bool_property() {
        // [A("s", Named = true)] with ctor A(string).
        // [A("s", Named = true)] with ctor A(string): prolog, untagged
        // SerString, NumNamed=1, then kind/tag/name/value.
        let mut blob = vec![0x01, 0x00, 0x01, b's'];
        blob.extend_from_slice(&[0x01, 0x00]); // NumNamed = 1
        blob.extend_from_slice(&[0x54, 0x02]); // property kind, bool tag
        blob.push(b"Named".len() as u8); // SerString compressed length
        blob.extend_from_slice(b"Named");
        blob.push(0x01); // true
        let params = vec![sys("String")];
        let (fixed, named) = decode_attribute_args_for(&blob, &params).unwrap();
        assert_eq!(fixed, vec![CArgument::String(Some("s".to_owned()))]);
        assert_eq!(named.len(), 1);
        assert_eq!(named[0].0, "Named");
        assert!(args_eq(&named[0].1, &CArgument::Bool(true)));
    }

    #[test]
    fn real_form_typeof_argument() {
        // [A(typeof(NS.OtherTy))] with ctor A(Type): UTF-8 full type name,
        // not a metadata cell (Cecil ReadTypeReference).
        let mut blob = vec![0x01, 0x00, b"NS.OtherTy".len() as u8];
        blob.extend_from_slice(b"NS.OtherTy");
        blob.extend_from_slice(&[0x00, 0x00]);
        let params = vec![sys("Type")];
        let (fixed, _) = decode_attribute_args_for(&blob, &params).unwrap();
        assert_eq!(fixed, vec![CArgument::Type(Some(ext_ty("OtherTy")))]);
    }

    #[test]
    fn real_form_roundtrip_through_write_for() {
        let enum_ty = ext_ty("EnumTy");
        let params = vec![
            sys("Int32"),
            sys("String"),
            sys("Double"),
            sys("Object"),
            TypeDesc::SzArray(std::sync::Arc::new(sys("UInt16"))),
            enum_ty.clone(),
        ];
        let fixed = vec![
            CArgument::I32(-7),
            CArgument::String(None),
            CArgument::F64(2.5),
            CArgument::Boxed(Box::new(CArgument::U64(9))),
            CArgument::Array(vec![CArgument::U16(1), CArgument::U16(2)]),
            CArgument::Enum { ty: enum_ty.clone(), value: Box::new(CArgument::I64(-3)) },
        ];
        let named = vec![
            ("Flag".to_owned(), CArgument::Bool(true)),
            ("Tys".to_owned(), CArgument::Array(vec![CArgument::I32(5)])),
            (
                "E".to_owned(),
                CArgument::Enum { ty: enum_ty.clone(), value: Box::new(CArgument::I64(77)) },
            ),
            ("NullTy".to_owned(), CArgument::Type(None)),
        ];
        // The enum stands in for one declared over Int64.
        let wide = move |ty: &TypeDesc| {
            if *ty == enum_ty {
                Ok(0x0a)
            } else {
                Err(Error::argument("unknown enum"))
            }
        };
        let blob = write_attribute_args_for_ctx(&fixed, &named, &params, Some(&wide)).unwrap();
        let (fixed2, named2) = decode_attribute_args_for_ctx(&blob, &params, Some(&wide)).unwrap();
        assert_eq!(fixed2.len(), fixed.len());
        for (a, b) in fixed.iter().zip(&fixed2) {
            assert!(args_eq(a, b), "fixed mismatch: {a:?} vs {b:?}");
        }
        assert_eq!(named2.len(), named.len());
        for ((n1, a1), (n2, a2)) in named.iter().zip(&named2) {
            assert_eq!(n1, n2);
            assert!(args_eq(a1, a2), "named mismatch: {a1:?} vs {a2:?}");
        }
    }

    #[test]
    fn real_form_mismatched_params_are_rejected() {
        // typeof-blob decoded against an empty parameter list: the type
        // name bytes land in the named section and cannot parse.
        let mut blob = vec![0x01, 0x00, b"NS.OtherTy".len() as u8];
        blob.extend_from_slice(b"NS.OtherTy");
        blob.extend_from_slice(&[0x00, 0x00]);
        assert!(decode_attribute_args_for(&blob, &[]).is_err());

        // An i32 payload decoded as a string argument: the compressed
        // length prefix runs past the end of the blob.
        let blob = [0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(decode_attribute_args_for(&blob, &[sys("String")]).is_err());

        // void parameters are never valid attribute arguments.
        assert!(decode_attribute_args_for(&[0x01, 0x00, 0x00, 0x00], &[sys("Void")]).is_err());
        assert!(write_attribute_args_for(&[CArgument::I32(1)], &[], &[sys("Void")]).is_err());

        // Fixed/named arity disagreement between args and signature.
        let params = vec![sys("Int32")];
        assert!(write_attribute_args_for(&[], &[], &params).is_err());
        assert!(write_attribute_args_for(&[CArgument::I32(1), CArgument::I32(2)], &[], &params)
            .is_err());
    }

    #[test]
    fn real_form_truncation_is_an_error() {
        let params = vec![sys("Int32"), sys("String")];
        let fixed = vec![CArgument::I32(1), CArgument::String(Some("xy".to_owned()))];
        let blob = write_attribute_args_for(&fixed, &[], &params).unwrap();
        assert!(!blob.is_empty());
        for cut in 0..blob.len() {
            assert!(
                decode_attribute_args_for(&blob[..cut], &params).is_err(),
                "prefix of length {cut} decoded successfully"
            );
        }
        // Empty blob / broken prolog.
        assert!(decode_attribute_args_for(&[], &params).is_err());
        assert!(decode_attribute_args_for(&[0x02, 0x00], &params).is_err());
    }

    #[test]
    fn real_form_enum_underlying_callback_controls_width() {
        let enum_ty = ext_ty("WideEnum");
        let params = vec![enum_ty.clone()];
        // Payload stored as u64 (prolog, 8 raw bytes, named count 0).
        let mut blob = vec![0x01, 0x00];
        blob.extend_from_slice(&9u64.to_le_bytes());
        blob.extend_from_slice(&[0x00, 0x00]);

        // Without the callback the documented i32 fallback mis-sizes the
        // payload and leaves trailing bytes.
        assert!(decode_attribute_args_for(&blob, &params).is_err());

        let wide = |_ty: &TypeDesc| Ok(0x0bu8);
        let (fixed, _) = decode_attribute_args_for_ctx(&blob, &params, Some(&wide)).unwrap();
        assert_eq!(
            fixed,
            vec![CArgument::Enum { ty: ext_ty("WideEnum"), value: Box::new(CArgument::U64(9)) }]
        );
    }

    #[test]
    fn arguments_resolved_uses_ctor_signature_lazily() {
        // Same hand-crafted [A(42)] blob as above.
        let blob = [0x01, 0x00, 42, 0x00, 0x00, 0x00, 0x00, 0x00];
        let attribute = attr(blob.to_vec());
        let params = || Ok(vec![sys("Int32")]);
        let args = attribute.arguments_resolved(&params).unwrap();
        assert_eq!(args, vec![CArgument::I32(42)]);

        // Signature-resolution failures propagate.
        let bad = || Err(Error::argument("constructor signature unavailable"));
        assert!(attribute.arguments_resolved(&bad).is_err());
    }
}
