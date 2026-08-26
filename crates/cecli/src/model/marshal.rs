//! FieldMarshal blob codec (ECMA-335 II §23.4 native type specifications).
//!
//! Port of the reading logic in `Mono.Cecil/AssemblyReader.cs`
//! (`ReadMarshalInfo`, `ReadNativeType`, `ReadVariantType`) over the
//! `NativeType` values from `Mono.Cecil/NativeType.cs`.
//!
//! Layout notes, matching Mono.Cecil's reader:
//!
//! * Simple native types are a single byte.
//! * `FIXEDSYSSTRING` carries an optional compressed element count.
//! * `FIXEDARRAY` carries an optional compressed size followed by an optional
//!   nested native type byte.
//! * `SAFEARRAY` carries an optional compressed OLE `VARENUM` variant followed
//!   by an optional `TypeDefOrRef` cell describing the element type; the cell
//!   is resolved through the caller-supplied [`TdorResolver`] into a
//!   [`TypeDesc`] (this extends Mono.Cecil, which stops after the variant).
//! * `NATIVEARRAY` carries an optional nested native sub-spec followed by
//!   compressed `ParamNum`, `ElemMult` and `NumElem`.
//! * `INTF` carries a raw little-endian `i32` IID parameter index.
//! * `CUSTOMMARSHALER` carries a raw 16-byte GUID followed by two
//!   SerStrings (unmarshaller type name and cookie). This follows the frozen
//!   object model (`NativeTypeSpec::CustomMarshaler`); Mono.Cecil instead
//!   stores the GUID parsed from its UTF-8 string form plus a managed
//!   `TypeReference`.

use cecli_core::io::{ByteReader, ByteWriter};
use cecli_core::{Error, Result, VariantType};

use super::custom_attribute::{read_ser_string, write_ser_string, TdorEncoder, TdorResolver};
use super::types::{MarshalInfo, NativeTypeSpec, TypeDesc};

/// GUID byte width of the custom marshaler form.
const GUID_LEN: usize = 16;

/// Decodes a `FieldMarshal` blob into a [`MarshalInfo`], resolving any
/// `TypeDefOrRef` cell of a `SafeArray` element description through `r`.
pub fn parse_marshal_spec(blob: &[u8], r: &mut TdorResolver) -> Result<MarshalInfo> {
    let mut rd = ByteReader::new(blob);
    let spec = parse_native_type(&mut rd, r)?;
    if !rd.is_empty() {
        return Err(Error::bad_image(
            "marshal spec has trailing bytes after the native type",
        ));
    }
    Ok(MarshalInfo { spec })
}

/// Encodes a [`MarshalInfo`] into a `FieldMarshal` blob. Inverse of
/// [`parse_marshal_spec`].
pub fn write_marshal_spec(info: &MarshalInfo, e: &mut TdorEncoder) -> Result<Vec<u8>> {
    let mut w = ByteWriter::new();
    write_native_type(&mut w, &info.spec, e)?;
    Ok(w.into_vec())
}

fn native_code(spec: &NativeTypeSpec) -> u8 {
    match spec {
        NativeTypeSpec::None => 0x66,
        NativeTypeSpec::Boolean => 0x02,
        NativeTypeSpec::I1 => 0x03,
        NativeTypeSpec::U1 => 0x04,
        NativeTypeSpec::I2 => 0x05,
        NativeTypeSpec::U2 => 0x06,
        NativeTypeSpec::I4 => 0x07,
        NativeTypeSpec::U4 => 0x08,
        NativeTypeSpec::I8 => 0x09,
        NativeTypeSpec::U8 => 0x0a,
        NativeTypeSpec::R4 => 0x0b,
        NativeTypeSpec::R8 => 0x0c,
        NativeTypeSpec::LPStr => 0x14,
        NativeTypeSpec::Int => 0x1f,
        NativeTypeSpec::UInt => 0x20,
        NativeTypeSpec::Func => 0x26,
        // Both array forms share 0x2a; parse distinguishes them by payload.
        NativeTypeSpec::Array => 0x2a,
        NativeTypeSpec::Currency => 0x0f,
        NativeTypeSpec::BStr => 0x13,
        NativeTypeSpec::LPWStr => 0x15,
        NativeTypeSpec::LPTStr => 0x16,
        NativeTypeSpec::ByValStr => 0x22,
        NativeTypeSpec::ANSIBStr => 0x23,
        NativeTypeSpec::TBStr => 0x24,
        NativeTypeSpec::VariantBool => 0x25,
        NativeTypeSpec::ASAny => 0x28,
        NativeTypeSpec::FixedSysString { .. } => 0x17,
        NativeTypeSpec::FixedArray { .. } => 0x1e,
        NativeTypeSpec::SafeArray { .. } => 0x1d,
        NativeTypeSpec::NativeArray { .. } => 0x2a,
        NativeTypeSpec::IUnknown => 0x19,
        NativeTypeSpec::IDispatch => 0x1a,
        NativeTypeSpec::Struct => 0x1b,
        NativeTypeSpec::IntF { .. } => 0x1c,
        NativeTypeSpec::LPStruct => 0x2b,
        NativeTypeSpec::CustomMarshaler { .. } => 0x2c,
        NativeTypeSpec::Error => 0x2d,
    }
}

fn parse_native_type(rd: &mut ByteReader, r: &mut TdorResolver) -> Result<NativeTypeSpec> {
    Ok(match rd.u8()? {
        0x66 => NativeTypeSpec::None,
        0x02 => NativeTypeSpec::Boolean,
        0x03 => NativeTypeSpec::I1,
        0x04 => NativeTypeSpec::U1,
        0x05 => NativeTypeSpec::I2,
        0x06 => NativeTypeSpec::U2,
        0x07 => NativeTypeSpec::I4,
        0x08 => NativeTypeSpec::U4,
        0x09 => NativeTypeSpec::I8,
        0x0a => NativeTypeSpec::U8,
        0x0b => NativeTypeSpec::R4,
        0x0c => NativeTypeSpec::R8,
        0x14 => NativeTypeSpec::LPStr,
        0x1f => NativeTypeSpec::Int,
        0x20 => NativeTypeSpec::UInt,
        0x26 => NativeTypeSpec::Func,
        0x2a => {
            if rd.is_empty() {
                // Bare tag: the parameterless `Array` form. A parameterised
                // `NativeArray` always writes at least its three counts, so
                // the two are unambiguous on the wire.
                NativeTypeSpec::Array
            } else {
                NativeTypeSpec::NativeArray {
                    // Counts come before the optional sub-spec so the
                    // all-default form stays unambiguous on the wire;
                    // absent fields default to zero (Mono.Cecil CanReadMore).
                    param_num: opt_compressed(rd)?,
                    elem_mult: opt_compressed(rd)?,
                    num_elem: opt_compressed(rd)?,
                    element: opt_native(rd, r)?,
                }
            }
        }
        0x0f => NativeTypeSpec::Currency,
        0x13 => NativeTypeSpec::BStr,
        0x15 => NativeTypeSpec::LPWStr,
        0x16 => NativeTypeSpec::LPTStr,
        0x17 => NativeTypeSpec::FixedSysString {
            size_count: opt_compressed(rd)?,
        },
        0x19 => NativeTypeSpec::IUnknown,
        0x1a => NativeTypeSpec::IDispatch,
        0x1b => NativeTypeSpec::Struct,
        0x1c => NativeTypeSpec::IntF {
            iid_param_index: rd.i32()?,
        },
        0x1d => NativeTypeSpec::SafeArray {
            element_variant: match opt_compressed(rd)? {
                0 => None,
                v => Some(
                    VariantType::from_u32(v)
                        .ok_or_else(|| Error::bad_image(format!("unknown VARIANT type {v:#x}")))?,
                ),
            },
            element_desc: opt_tdor(rd, r)?,
        },
        0x1e => NativeTypeSpec::FixedArray {
            size: opt_compressed(rd)?,
            element: opt_native(rd, r)?,
        },
        0x22 => NativeTypeSpec::ByValStr,
        0x23 => NativeTypeSpec::ANSIBStr,
        0x24 => NativeTypeSpec::TBStr,
        0x25 => NativeTypeSpec::VariantBool,
        0x28 => NativeTypeSpec::ASAny,
        0x2b => NativeTypeSpec::LPStruct,
        0x2c => NativeTypeSpec::CustomMarshaler {
            guid: rd.read_bytes(GUID_LEN)?.try_into().expect("16 bytes"),
            unmarshaller_ty: read_ser_string(rd)?.unwrap_or_default(),
            cookie: read_ser_string(rd)?.unwrap_or_default(),
        },
        0x2d => NativeTypeSpec::Error,
        other => {
            return Err(Error::bad_image(format!(
                "unknown native type 0x{other:02X}"
            )))
        }
    })
}

fn write_native_type(w: &mut ByteWriter, spec: &NativeTypeSpec, e: &mut TdorEncoder) -> Result<()> {
    w.u8(native_code(spec));
    match spec {
        NativeTypeSpec::FixedSysString { size_count } => w.compressed_u32(*size_count),
        NativeTypeSpec::FixedArray { size, element } => {
            w.compressed_u32(*size);
            if let Some(elem) = element {
                write_native_type(w, elem, e)?;
            }
        }
        NativeTypeSpec::SafeArray {
            element_variant,
            element_desc,
        } => {
            w.compressed_u32(element_variant.map_or(0, |v| v as u32));
            if let Some(desc) = element_desc {
                w.compressed_u32(e(desc)?);
            }
        }
        NativeTypeSpec::NativeArray {
            element,
            param_num,
            elem_mult,
            num_elem,
        } => {
            w.compressed_u32(*param_num);
            w.compressed_u32(*elem_mult);
            w.compressed_u32(*num_elem);
            if let Some(elem) = element {
                write_native_type(w, elem, e)?;
            }
        }
        NativeTypeSpec::IntF { iid_param_index } => w.i32(*iid_param_index),
        NativeTypeSpec::CustomMarshaler {
            guid,
            unmarshaller_ty,
            cookie,
        } => {
            w.bytes(&guid[..]);
            write_ser_string(w, Some(unmarshaller_ty))?;
            write_ser_string(w, Some(cookie))?;
        }
        _ => {}
    }
    Ok(())
}

/// Reads a compressed value if any bytes remain; otherwise returns 0
/// (Mono.Cecil treats every trailing field of a marshal spec as optional).
fn opt_compressed(rd: &mut ByteReader) -> Result<u32> {
    if rd.is_empty() {
        Ok(0)
    } else {
        rd.compressed_u32()
    }
}

/// Reads a nested native type if any bytes remain.
fn opt_native(rd: &mut ByteReader, r: &mut TdorResolver) -> Result<Option<Box<NativeTypeSpec>>> {
    if rd.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Box::new(parse_native_type(rd, r)?)))
    }
}

/// Reads a `TypeDefOrRef` cell and resolves it if any bytes remain.
fn opt_tdor(rd: &mut ByteReader, r: &mut TdorResolver) -> Result<Option<Box<TypeDesc>>> {
    if rd.is_empty() {
        Ok(None)
    } else {
        let cell = rd.compressed_u32()?;
        Ok(Some(Box::new(r(cell)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{ExternalType, ScopeRef};

    fn ext_ty(name: &str) -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: "NS".to_owned(),
            name: name.to_owned(),
            nesting: Vec::new(),
            scope: ScopeRef::Moduleless,
        }))
    }

    /// Resolver/encoder pair agreeing on cell 7 <-> external `ElemTy`.
    fn resolver() -> impl FnMut(u32) -> Result<TypeDesc> {
        move |cell| match cell {
            7 => Ok(ext_ty("ElemTy")),
            other => Err(Error::bad_image(format!("unresolvable tdor cell {other}"))),
        }
    }

    fn enc_cell() -> impl FnMut(&TypeDesc) -> Result<u32> {
        move |ty| match ty {
            TypeDesc::External(e) if e.name == "ElemTy" => Ok(7),
            other => Err(Error::argument(format!("cannot encode {other:?}"))),
        }
    }

    /// One sample of every `NativeTypeSpec` variant, including nesting.
    fn all_variants() -> Vec<NativeTypeSpec> {
        vec![
            NativeTypeSpec::None,
            NativeTypeSpec::Boolean,
            NativeTypeSpec::I1,
            NativeTypeSpec::U1,
            NativeTypeSpec::I2,
            NativeTypeSpec::U2,
            NativeTypeSpec::I4,
            NativeTypeSpec::U4,
            NativeTypeSpec::I8,
            NativeTypeSpec::U8,
            NativeTypeSpec::R4,
            NativeTypeSpec::R8,
            NativeTypeSpec::LPStr,
            NativeTypeSpec::Int,
            NativeTypeSpec::UInt,
            NativeTypeSpec::Func,
            NativeTypeSpec::Array,
            NativeTypeSpec::Currency,
            NativeTypeSpec::BStr,
            NativeTypeSpec::LPWStr,
            NativeTypeSpec::LPTStr,
            NativeTypeSpec::ByValStr,
            NativeTypeSpec::ANSIBStr,
            NativeTypeSpec::TBStr,
            NativeTypeSpec::VariantBool,
            NativeTypeSpec::ASAny,
            NativeTypeSpec::IUnknown,
            NativeTypeSpec::IDispatch,
            NativeTypeSpec::Struct,
            NativeTypeSpec::LPStruct,
            NativeTypeSpec::Error,
            NativeTypeSpec::FixedSysString { size_count: 42 },
            NativeTypeSpec::FixedSysString { size_count: 0 },
            NativeTypeSpec::FixedArray {
                size: 8,
                element: Some(Box::new(NativeTypeSpec::U1)),
            },
            NativeTypeSpec::FixedArray {
                size: 3,
                element: None,
            },
            NativeTypeSpec::SafeArray {
                element_variant: Some(VariantType::I4),
                element_desc: Some(Box::new(ext_ty("ElemTy"))),
            },
            NativeTypeSpec::SafeArray {
                element_variant: Some(VariantType::BStr),
                element_desc: None,
            },
            NativeTypeSpec::SafeArray {
                element_variant: None,
                element_desc: None,
            },
            // Nested FixedArray-in-Array.
            NativeTypeSpec::NativeArray {
                element: Some(Box::new(NativeTypeSpec::FixedArray {
                    size: 4,
                    element: Some(Box::new(NativeTypeSpec::I2)),
                })),
                param_num: 1,
                elem_mult: 2,
                num_elem: 3,
            },
            NativeTypeSpec::NativeArray {
                element: None,
                param_num: 0,
                elem_mult: 0,
                num_elem: 0,
            },
            NativeTypeSpec::IntF {
                iid_param_index: -1,
            },
            NativeTypeSpec::CustomMarshaler {
                guid: [
                    0x2f, 0x1d, 0x5a, 0x9b, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                    0xaa, 0xbb, 0xcc,
                ],
                unmarshaller_ty: "Acme.Marshaller, Acme".to_owned(),
                cookie: "cookie-value".to_owned(),
            },
        ]
    }

    #[test]
    fn every_variant_roundtrips() {
        let mut res = resolver();
        let mut enc = enc_cell();
        for spec in all_variants() {
            let info = MarshalInfo { spec };
            let blob = write_marshal_spec(&info, &mut enc)
                .unwrap_or_else(|err| panic!("write {info:?}: {err:?}"));
            let back = parse_marshal_spec(&blob, &mut res)
                .unwrap_or_else(|err| panic!("parse {info:?}: {err:?}"));
            assert_eq!(back, info, "roundtrip mismatch for {:?}", info.spec);
        }
    }

    #[test]
    fn simple_specs_are_single_byte() {
        assert_eq!(
            write_marshal_spec(
                &MarshalInfo {
                    spec: NativeTypeSpec::LPWStr,
                },
                &mut enc_cell()
            )
            .unwrap(),
            vec![0x15]
        );
    }

    #[test]
    fn truncations_are_errors() {
        let mut res = resolver();
        // INTF missing part of its raw i32.
        assert!(parse_marshal_spec(&[0x1c, 0xff, 0x00], &mut res).is_err());
        // SAFEARRAY variant cut mid compressed integer.
        assert!(parse_marshal_spec(&[0x1d, 0x80], &mut res).is_err());
        // FIXEDARRAY size cut mid compressed integer.
        assert!(parse_marshal_spec(&[0x1e, 0x80], &mut res).is_err());
        // NATIVEARRAY count cut mid compressed integer.
        assert!(parse_marshal_spec(&[0x2a, 0x08, 0x80], &mut res).is_err());
        // CUSTOMMARSHALER missing parts of guid / strings.
        assert!(parse_marshal_spec(&[0x2c, 0x01, 0x02], &mut res).is_err());
        let full = MarshalInfo {
            spec: NativeTypeSpec::CustomMarshaler {
                guid: [0u8; 16],
                unmarshaller_ty: "T".to_owned(),
                cookie: "C".to_owned(),
            },
        };
        let blob =
            write_marshal_spec(&full, &mut enc_cell()).expect("write custom marshaler");
        for cut in 17..blob.len() {
            assert!(
                parse_marshal_spec(&blob[..cut], &mut res).is_err(),
                "prefix of length {cut} decoded successfully"
            );
        }
        // Unknown native type byte.
        assert!(parse_marshal_spec(&[0x00], &mut res).is_err());
        // Trailing garbage.
        assert!(parse_marshal_spec(&[0x15, 0x66], &mut res).is_err());
    }

    #[test]
    fn safearray_resolver_errors_propagate() {
        let mut failing: Box<TdorResolver> =
            Box::new(|_| Err(Error::bad_image("no resolver here")));
        assert!(parse_marshal_spec(&[0x1d, 0x08, 0x07], &mut failing).is_err());
    }

    #[test]
    fn unknown_variant_encoding_fails() {
        // An element_desc whose encoder rejects the type surfaces as Err.
        let info = MarshalInfo {
            spec: NativeTypeSpec::SafeArray {
                element_variant: Some(VariantType::I4),
                element_desc: Some(Box::new(TypeDesc::Sentinel)),
            },
        };
        assert!(write_marshal_spec(&info, &mut enc_cell()).is_err());
    }
}
