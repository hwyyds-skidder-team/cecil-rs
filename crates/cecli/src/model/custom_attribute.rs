//! ECMA-335 II §23.3 custom attribute argument blob codec.
//!
//! Port of the blob reading logic in `Mono.Cecil/AssemblyReader.cs`
//! (`ReadCustomAttributeConstructorArguments`, `ReadCustomAttributeNamedArguments`,
//! `ReadCustomAttributeFieldOrPropType`, `ReadPrimitiveValue`) together with the
//! attribute-specific element-type constants from `Mono.Cecil.Metadata/ElementType.cs`
//! (`Type = 0x50`, `Boxed = 0x51`, `Enum = 0x55`).
//!
//! # Encoding layout produced/consumed by this module
//!
//! ```text
//! prolog      : u16 = 0x0001                     (ECMA II 23.3)
//! fixed_count : u32                              (see deviation note below)
//! fixed args  : tagged elements, see below
//! named_count : u16                              (ECMA II 23.3 NumNamed)
//! named args  : kind(0x53 field | 0x54 property)
//!               + FieldOrPropType + SerString(name) + value
//! ```
//!
//! Every argument — fixed or named — is a *tagged element*: one
//! `FieldOrPropType` discriminator byte followed by its value body. Value bodies
//! follow ECMA II 23.3 / Mono.Cecil exactly: little-endian primitives sized by
//! kind, `SerString` (compressed-length UTF-8 with the `0xFF` null marker), a
//! compressed `TypeDefOrRef` cell for the `Type` (`0x50`) and `Enum` (`0x55`)
//! forms followed by an `i32` enum payload, `0x51` boxed recursion, and a raw
//! `u32` count for the `SZARRAY` (`0x1D`) form.
//!
//! # Documented deviations from the raw ECMA layout
//!
//! In a real image the fixed-argument section carries *no* type information:
//! the number of arguments and their types come from the attribute
//! constructor's method signature, which lives outside the blob. This codec is
//! deliberately self-contained ([`decode_attribute_args`] receives no
//! constructor metadata), so two small extensions make the section decodable
//! on its own:
//!
//! * a `u32` fixed-argument count follows the prolog, and
//! * every fixed argument is prefixed with the same `FieldOrPropType` byte a
//!   named-argument value uses.
//!
//! With those exceptions the named-argument section stays byte-compatible with
//! real images. Further limitations, stated honestly:
//!
//! * Enum payloads are always `i32`; 64-bit underlying enum types are rejected
//!   by [`encode_attribute_args`].
//! * A null array (`0xFFFFFFFF` count in real blobs) is rejected on decode; the
//!   [`CArgument::Array`] variant cannot express it.
//! * The field/property distinction of a named argument is not representable
//!   in the `(String, CArgument)` tuple returned by [`decode_attribute_args`];
//!   [`encode_attribute_args`] serialises every named entry with the field tag
//!   `0x53`.
//! * A null `System.Type` argument is written as `0x50 0xFF` (type slot with
//!   null marker) so it stays distinguishable from a null object reference,
//!   which is the bare `0xFF` byte.
//! * `System.Type` values are carried as compressed `TypeDefOrRef` cells passed
//!   through the caller-supplied resolver/encoder instead of Mono.Cecil's
//!   UTF-8 full type names, because this object model stores resolved
//!   [`TypeDesc`]s rather than parsed names.

use cecli_core::io::{ByteReader, ByteWriter};
use cecli_core::{Error, Result};

use super::types::TypeDesc;

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
    Enum { ty: TypeDesc, value: Box<CArgument> },
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

/// Decodes a custom attribute blob into its fixed (positional) and named
/// arguments, validating the `0x0001` prolog.
///
/// `r` resolves `TypeDefOrRef` cells for enum types and `System.Type` values.
pub fn decode_attribute_args(
    blob: &[u8],
    r: &mut TdorResolver,
) -> Result<(Vec<CArgument>, Vec<(String, CArgument)>)> {
    let mut rd = ByteReader::new(blob);
    if rd.remaining() < 2 || rd.u16()? != PROLOG {
        return Err(Error::bad_image(
            "custom attribute blob must start with the 0x0001 prolog",
        ));
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

/// Encodes fixed and named custom attribute arguments into a blob with the
/// `0x0001` prolog. Inverse of [`decode_attribute_args`].
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
        return Err(Error::bad_image(format!(
            "invalid named argument kind 0x{kind:02X}"
        )));
    }
    let tag = read_element_tag(rd)?;
    let name = read_ser_string(rd)?.ok_or_else(|| {
        Error::bad_image("null marker where a named argument name was expected")
    })?;
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
        return Err(Error::argument(format!(
            "invalid named argument kind 0x{kind:02X}"
        )));
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
            return Err(Error::bad_image(format!(
                "unknown attribute element type 0x{other:02X}"
            )))
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
            CArgument::Enum {
                ty,
                value: Box::new(CArgument::I32(rd.i32()?)),
            }
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
        0x03 => CArgument::Char(
            char::from_u32(rd.u16()? as u32).unwrap_or(char::REPLACEMENT_CHARACTER),
        ),
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
            return Err(Error::bad_image(format!(
                "unknown primitive element type 0x{other:02X}"
            )))
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
        other => {
            return Err(Error::argument(format!(
                "invalid enum underlying value {other:?}"
            )))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{ExternalType, ScopeRef};

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
            (
                CArgument::Enum { ty: t1, value: v1 },
                CArgument::Enum { ty: t2, value: v2 },
            ) => t1 == t2 && args_eq(v1, v2),
            (CArgument::Array(xs), CArgument::Array(ys)) => {
                xs.len() == ys.len() && xs.iter().zip(ys).all(|(x, y)| args_eq(x, y))
            }
            _ => a == b,
        }
    }

    fn fixture() -> (Vec<CArgument>, Vec<(String, CArgument)>) {
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
            CArgument::Enum {
                ty: ext_ty("EnumTy"),
                value: Box::new(CArgument::I32(7)),
            },
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
            (
                "Arr".to_owned(),
                CArgument::Array(vec![CArgument::I32(9)]),
            ),
            (
                "B".to_owned(),
                CArgument::Boxed(Box::new(CArgument::F64(2.5))),
            ),
            (
                "En".to_owned(),
                CArgument::Enum {
                    ty: ext_ty("EnumTy"),
                    value: Box::new(CArgument::I32(255)),
                },
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
        assert!(
            decode_attribute_args(&[0x01, 0x00, 0x01, 0x00, 0x00, 0x00], &mut res).is_err()
        );
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
        let fixed = vec![CArgument::Enum {
            ty: ext_ty("EnumTy"),
            value: Box::new(CArgument::I64(-1)),
        }];
        let mut enc = enc_cell();
        assert!(encode_attribute_args(&fixed, &[], &mut enc).is_err());
    }
}
