//! FieldMarshal blob codec (ECMA-335 II §23.4 native type specifications).
//!
//! Byte-exact port of Mono.Cecil's `ReadMarshalInfo` / `WriteMarshalInfo`
//! (`Mono.Cecil/AssemblyReader.cs:3736` / `AssemblyWriter.cs:3261`) over the
//! `NativeType` values from `Mono.Cecil/NativeType.cs`.
//!
//! Wire layouts, matching Mono.Cecil exactly:
//!
//! * Simple native types are a single tag byte.
//! * `FIXEDSYSSTRING` (0x17): optional compressed size (absent ⇒ 0).
//! * `FIXEDARRAY` (0x1e): optional compressed size, then an optional nested
//!   native type spec.
//! * `SAFEARRAY` (0x1d): one **raw** OLE `VARENUM` byte (omitted entirely
//!   when the variant is absent), optionally followed by a `TypeDefOrRef`
//!   cell describing the element type. The cell is a cecli extension — the
//!   frozen object model carries it; Mono.Cecil stops after the variant
//!   byte. Wire bytes decode OLE-first: `0x09` reads as `Dispatch`, not the
//!   colliding plain `U4` code (matches Cecil's `marshal.dll` fixture,
//!   whose `SAFEARRAY` byte 0x09 asserts `VariantType.Dispatch`).
//! * `NATIVEARRAY` (0x2a): an optional nested element spec comes FIRST (no
//!   payload at all is the bare parameterless `Array` form), then up to
//!   three compressed counts in Cecil's positional order: ParamNum,
//!   NumElem, ElemMult. Trailing zero counts are omitted on write and
//!   default to 0 on read.
//! * `INTF` (0x1c): optional compressed IID parameter index. Mono.Cecil
//!   ignores this payload entirely; ILAsm/dnlib emit a compressed value,
//!   so we read it when present and write it when non-zero.
//! * `CUSTOMMARSHALER` (0x2c): four SerStrings in Cecil's wire order —
//!   GUID text (canonical hyphenated form; empty ⇔ `Guid.Empty`), unmanaged
//!   (native) type name, managed custom-marshaller type name, cookie.
//!   All three names are carried on `NativeTypeSpec::CustomMarshaler`
//!   (`unmarshaller_ty` / `managed_ty` / `cookie`) and round-trip intact.

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
        // Both array forms share 0x2a; the payload distinguishes them: no
        // bytes at all is the parameterless `Array`, anything else starts
        // with the nested element spec (Mono.Cecil ReadMarshalInfo order).
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
        NativeTypeSpec::Max => 0x50,
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
                // `NativeArray` always starts with its element spec, so the
                // two are unambiguous on the wire (Mono.Cecil reads the
                // element type whenever any byte remains).
                NativeTypeSpec::Array
            } else {
                // Cecil order: element_type, SizeParameterIndex, Size,
                // SizeParameterMultiplier — i.e. element, ParamNum,
                // NumElem, ElemMult. Each trailing count is optional.
                let element = opt_native(rd, r)?;
                let param_num = opt_compressed(rd)?;
                let num_elem = opt_compressed(rd)?;
                let elem_mult = opt_compressed(rd)?;
                NativeTypeSpec::NativeArray {
                    element,
                    param_num,
                    elem_mult,
                    num_elem,
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
            // Optional compressed index; Mono.Cecil reads it as signed.
            iid_param_index: if rd.is_empty() {
                0
            } else {
                rd.compressed_i32()?
            },
        },
        0x1d => NativeTypeSpec::SafeArray {
            // Raw VARENUM byte (Mono.Cecil ReadVariantType), omitted when
            // absent. 0x00 is the absent marker.
            element_variant: if rd.is_empty() || rd.bytes()[rd.position()] == 0x00 {
                if !rd.is_empty() {
                    rd.seek(rd.position() + 1)?;
                }
                None
            } else {
                let raw = rd.u8()?;
                Some(variant_from_wire(raw)?)
            },
            // cecli extension: optional TypeDefOrRef cell describing the
            // element type (mirrors COM VT_USERDEFINED descriptors).
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
        0x2c => {
            // Cecil order: GUID string, unmanaged type name, managed
            // marshaller type name, cookie — all SerStrings.
            let guid_text = read_ser_string(rd)?.unwrap_or_default();
            let guid = if guid_text.is_empty() {
                [0u8; GUID_LEN]
            } else {
                guid_from_string(&guid_text)?
            };
            let unmarshaller_ty = read_ser_string(rd)?.unwrap_or_default();
            let managed_ty = read_ser_string(rd)?.unwrap_or_default();
            let cookie = read_ser_string(rd)?.unwrap_or_default();
            NativeTypeSpec::CustomMarshaler {
                guid,
                unmarshaller_ty,
                managed_ty,
                cookie,
            }
        }
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
        NativeTypeSpec::FixedSysString { size_count } => {
            if *size_count != 0 {
                w.compressed_u32(*size_count);
            }
        }
        NativeTypeSpec::FixedArray { size, element } => {
            if *size != 0 {
                w.compressed_u32(*size);
            }
            if let Some(elem) = element {
                write_native_type(w, elem, e)?;
            }
        }
        NativeTypeSpec::SafeArray {
            element_variant,
            element_desc,
        } => {
            if element_variant.is_some() || element_desc.is_some() {
                w.u8(match element_variant {
                    Some(v) => variant_to_wire(*v)?,
                    // Anchor byte keeping the optional cell positioned.
                    None => 0x00,
                });
            }
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
            // ECMA-335 II 25.4.4 / Cecil ArrayMarshalInfo: a parameterised
            // ARRAY always carries its element type on the wire.
            let elem = element.as_deref().ok_or_else(|| {
                Error::argument("NATIVE_TYPE_ARRAY requires an element type")
            })?;
            write_native_type(w, elem, e)?;
            // Wire order is ParamNum, NumElem, ElemMult; trim trailing
            // zeros (they default to 0 on read).
            let counts = [*param_num, *num_elem, *elem_mult];
            let written = counts.iter().rposition(|&c| c != 0).map_or(0, |i| i + 1);
            for &c in &counts[..written] {
                w.compressed_u32(c);
            }
        }
        NativeTypeSpec::IntF { iid_param_index } => {
            if *iid_param_index != 0 {
                w.compressed_i32(*iid_param_index);
            }
        }
        NativeTypeSpec::CustomMarshaler {
            guid,
            unmarshaller_ty,
            managed_ty,
            cookie,
        } => {
            if *guid == [0u8; GUID_LEN] {
                // Matches Cecil: Guid.Empty serialises as "".
                write_ser_string(w, Some(""))?;
            } else {
                write_ser_string(w, Some(&guid_to_string(guid)))?;
            }
            write_ser_string(w, Some(unmarshaller_ty.as_str()))?;
            write_ser_string(w, Some(managed_ty.as_str()))?;
            write_ser_string(w, Some(cookie.as_str()))?;
        }
        NativeTypeSpec::Max => {}
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

/// Decodes a wire VARENUM byte into a [`VariantType`]. The OLE families
/// (VT_CY…VT_CLSID, stored shifted in the enum) win over the colliding
/// low codes, so `0x09` is `Dispatch` — matching Cecil's VariantType.
fn variant_from_wire(raw: u8) -> Result<VariantType> {
    VariantType::from_u32(u32::from(raw) << 8)
        .or_else(|| VariantType::from_u32(u32::from(raw)))
        .ok_or_else(|| Error::bad_image(format!("unknown VARIANT type {raw:#x}")))
}

/// Encodes a [`VariantType`] as its wire VARENUM byte (inverse of
/// [`variant_from_wire`] for every unambiguous member).
///
/// Note: the eight plain codes 0x06–0x0D (`I2`…`R8`) collide on the wire
/// with the OLE families `Currency`…`R8`; they are emitted as their plain
/// code, which reads back under its OLE name.
fn variant_to_wire(v: VariantType) -> Result<u8> {
    let raw = v as u32;
    if raw > 0xff {
        let vt = u8::try_from(raw >> 8)
            .map_err(|_| Error::argument(format!("VARIANT type {v:?} out of wire range")))?;
        Ok(vt)
    } else {
        u8::try_from(raw).map_err(|_| Error::argument(format!("VARIANT type {v:?} out of range")))
    }
}

/// Formats a GUID in .NET's canonical lowercase hyphenated form (mixed
/// endian: the first three groups read their bytes little-endian).
fn guid_to_string(guid: &[u8; GUID_LEN]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
         {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid[3], guid[2], guid[1], guid[0], guid[5], guid[4], guid[7], guid[6], guid[8], guid[9],
        guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
    )
}

/// Parses a GUID from its textual form (`N`, `D`, or braced `B` format),
/// reversing [`guid_to_string`]'s endianness.
fn guid_from_string(text: &str) -> Result<[u8; GUID_LEN]> {
    let mut hex = String::with_capacity(32);
    for ch in text.chars() {
        match ch {
            '{' | '}' | '-' | '(' | ')' => {}
            '0'..='9' | 'a'..='f' | 'A'..='F' => hex.push(ch),
            _ => {
                return Err(Error::bad_image(format!(
                    "invalid character {ch:?} in custom marshaler GUID"
                )))
            }
        }
    }
    let nibble = |b: u8| -> Result<u8> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(Error::bad_image("invalid GUID digit")),
        }
    };
    if hex.len() != 32 {
        return Err(Error::bad_image(format!(
            "custom marshaler GUID needs 32 hex digits, got {}",
            hex.len()
        )));
    }
    let bytes = hex.as_bytes();
    let word = |start: usize, width: usize| -> Result<u64> {
        let mut v = 0u64;
        for i in 0..width {
            v = (v << 4) | u64::from(nibble(bytes[start + i])?);
        }
        Ok(v)
    };
    let mut guid = [0u8; GUID_LEN];
    guid[0..4].copy_from_slice(&(word(0, 8)? as u32).to_le_bytes());
    guid[4..6].copy_from_slice(&(word(8, 4)? as u16).to_le_bytes());
    guid[6..8].copy_from_slice(&(word(12, 4)? as u16).to_le_bytes());
    for i in 0..8 {
        guid[8 + i] = nibble(bytes[16 + i * 2])? << 4 | nibble(bytes[17 + i * 2])?;
    }
    Ok(guid)
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

    fn parse_ok(blob: &[u8]) -> MarshalInfo {
        let mut res = resolver();
        parse_marshal_spec(blob, &mut res).unwrap_or_else(|err| panic!("parse {blob:?}: {err:?}"))
    }

    fn write_ok(spec: NativeTypeSpec) -> Vec<u8> {
        let mut enc = enc_cell();
        write_marshal_spec(&MarshalInfo { spec }, &mut enc)
            .unwrap_or_else(|err| panic!("write failed: {err:?}"))
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
            // Zero collapses onto the bare tag; still equal after a round
            // trip because absent == 0.
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
                element_variant: Some(VariantType::Dispatch),
                element_desc: Some(Box::new(ext_ty("ElemTy"))),
            },
            NativeTypeSpec::SafeArray {
                element_variant: Some(VariantType::UserDefined),
                element_desc: None,
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
                num_elem: 3,
                elem_mult: 2,
            },
            // Leading zero counts stay on the wire positionally; a nonzero
            // multiplier prevents the trailing-zero collapse onto bare
            // `Array`.
            NativeTypeSpec::NativeArray {
                element: Some(Box::new(NativeTypeSpec::I8)),
                param_num: 0,
                elem_mult: 2,
                num_elem: 0,
            },
            NativeTypeSpec::IntF { iid_param_index: 2 },
            NativeTypeSpec::IntF {
                iid_param_index: -1,
            },
            NativeTypeSpec::CustomMarshaler {
                guid: [
                    0x2f, 0x1d, 0x5a, 0x9b, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                    0xaa, 0xbb, 0xcc,
                ],
                unmarshaller_ty: "Acme.Unmarshaller".to_owned(),
                managed_ty: String::new(),
                cookie: "cookie-value".to_owned(),
            },
            NativeTypeSpec::CustomMarshaler {
                guid: [0u8; 16],
                unmarshaller_ty: String::new(),
                managed_ty: String::new(),
                cookie: String::new(),
            },
        ]
    }

    #[test]
    fn every_variant_roundtrips() {
        let mut res = resolver();
        let mut enc = enc_cell();
        for spec in all_variants() {
            let info = MarshalInfo {
                spec: spec.clone(),
            };
            let blob = write_marshal_spec(&info, &mut enc)
                .unwrap_or_else(|err| panic!("write {info:?}: {err:?}"));
            let back = parse_marshal_spec(&blob, &mut res)
                .unwrap_or_else(|err| panic!("parse {info:?}: {err:?}"));
            assert_eq!(back, info, "roundtrip mismatch for {:?}", info.spec);

            // Re-encoding the decoded value must be byte-stable.
            let again = write_marshal_spec(&back, &mut enc).expect("rewrite");
            assert_eq!(again, blob, "re-encode mismatch for {:?}", info.spec);
        }

        // ECMA-335 II 25.4.4: a parameterised ARRAY must carry its element
        // type, so encoding `element: None` is a hard Error::argument —
        // while the bare kind-only `Array` form still writes as just 0x2a.
        let headless = MarshalInfo {
            spec: NativeTypeSpec::NativeArray {
                element: None,
                param_num: 1,
                elem_mult: 2,
                num_elem: 3,
            },
        };
        match write_marshal_spec(&headless, &mut enc) {
            Err(Error::Argument(_)) => {}
            other => panic!("element-less NATIVE_ARRAY must be Error::argument, got {other:?}"),
        }
        let bare_array = MarshalInfo {
            spec: NativeTypeSpec::Array,
        };
        assert_eq!(
            write_marshal_spec(&bare_array, &mut enc).expect("write bare Array"),
            vec![0x2a]
        );

        // iid_param_index -1 uses the single-byte signed form (0x7F) under
        // the Cecil-exact compressed-int codec, and round-trips negative.
        let neg = write_marshal_spec(
            &MarshalInfo {
                spec: NativeTypeSpec::IntF {
                    iid_param_index: -1,
                },
            },
            &mut enc,
        )
        .expect("write IntF(-1)");
        assert_eq!(neg, vec![0x1c, 0x7f]);
        assert_eq!(
            parse_ok(&neg).spec,
            NativeTypeSpec::IntF {
                iid_param_index: -1
            }
        );
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
        assert_eq!(parse_ok(&[0x07]).spec, NativeTypeSpec::I4);
        // Bare 0x2a is the parameterless Array form.
        assert_eq!(parse_ok(&[0x2a]).spec, NativeTypeSpec::Array);
    }

    /// Blobs lifted verbatim from the Mono.Cecil `marshal.dll` fixture
    /// (cecill/Test/Resources/assemblies/marshal.dll); expectations follow
    /// the NUnit ParameterTests/FieldTests assertions.
    #[test]
    fn fixture_blobs_decode_like_cecil() {
        // Field a: FIXEDSYSSTRING(42) -> `17 2a`.
        assert_eq!(
            parse_ok(&[0x17, 0x2a]).spec,
            NativeTypeSpec::FixedSysString { size_count: 42 }
        );
        // Field b: FIXEDARRAY(12, Boolean) -> `1e 0c 02`.
        assert_eq!(
            parse_ok(&[0x1e, 0x0c, 0x02]).spec,
            NativeTypeSpec::FixedArray {
                size: 12,
                element: Some(Box::new(NativeTypeSpec::Boolean)),
            }
        );
        // Param: plain I4 -> `07`.
        assert_eq!(parse_ok(&[0x07]).spec, NativeTypeSpec::I4);
        // Method return: SAFEARRAY(VT_DISPATCH) -> `1d 09`; the raw byte
        // 0x09 must read as Dispatch, not the colliding plain U4 code.
        assert_eq!(
            parse_ok(&[0x1d, 0x09]).spec,
            NativeTypeSpec::SafeArray {
                element_variant: Some(VariantType::Dispatch),
                element_desc: None,
            }
        );
        // Param: NATIVE_ARRAY(I8, ParamNum=2, NumElem=66, ElemMult=1)
        // -> `2a 09 02 42 01` (element spec first, Cecil order).
        assert_eq!(
            parse_ok(&[0x2a, 0x09, 0x02, 0x42, 0x01]).spec,
            NativeTypeSpec::NativeArray {
                element: Some(Box::new(NativeTypeSpec::I8)),
                param_num: 2,
                elem_mult: 1,
                num_elem: 66,
            }
        );
    }

    /// Hand-built marshal.dll-style custom-marshaler record: tag 0x2c
    /// followed by four SerStrings (guid="", unmanaged="", managed="Boc",
    /// cookie="nomnom") — byte-for-byte the fixture's FieldMarshal blob.
    #[test]
    fn custom_marshaler_record_parses_without_desync() {
        let mut res = resolver();
        let blob: &[u8] = &[0x2c, 0x00, 0x00, 0x03, b'B', b'o', b'c', 0x06, b'n', b'o', b'm',
                            b'n', b'o', b'm'];
        let info = parse_marshal_spec(blob, &mut res).expect("fixture custom marshaler");
        assert_eq!(
            info.spec,
            NativeTypeSpec::CustomMarshaler {
                guid: [0u8; 16],
                unmarshaller_ty: String::new(),
                managed_ty: "Boc".to_owned(),
                cookie: "nomnom".to_owned(),
            }
        );

        // Our own canonical encoding with a real GUID and both names set.
        let spec = NativeTypeSpec::CustomMarshaler {
            guid: guid_from_string("9B5A1D2F-2211-4433-5566-778899AABBCC").unwrap(),
            unmarshaller_ty: "Acme.NativeType".to_owned(),
            managed_ty: String::new(),
            cookie: "\u{1e}cookie".to_owned(),
        };
        let blob = write_ok(spec.clone());
        assert_eq!(blob[0], 0x2c);
        assert_eq!(parse_marshal_spec(&blob, &mut res).unwrap().spec, spec);
        assert_eq!(
            guid_to_string(&guid_from_string("9b5a1d2f-2211-4433-5566-778899aabbcc").unwrap()),
            "9b5a1d2f-2211-4433-5566-778899aabbcc"
        );
    }

    /// Every prefix of a canonical blob either fails cleanly or decodes to
    /// a strictly shorter (default-filled) spec — never panics, never
    /// over-reads. Forms whose payloads are all mandatory (custom
    /// marshaler, simple tags) must Err on every proper prefix.
    #[test]
    fn truncation_is_safe_and_strict_where_payloads_are_mandatory() {
        let mut res = resolver();

        // Simple tag: empty prefix cannot even read the tag byte.
        assert!(parse_marshal_spec(&[], &mut res).is_err());

        // Custom marshaler with a full GUID string: every proper prefix is
        // rejected (strings are length-checked against the sub-blob).
        let cm = NativeTypeSpec::CustomMarshaler {
            guid: guid_from_string("00000000-0000-0000-0000-000000000001").unwrap(),
            unmarshaller_ty: "T".to_owned(),
            managed_ty: String::new(),
            cookie: "C".to_owned(),
        };
        let blob = write_ok(cm);
        for cut in 0..blob.len() {
            assert!(
                parse_marshal_spec(&blob[..cut], &mut res).is_err(),
                "custom-marshaler prefix of length {cut} decoded successfully"
            );
        }

        // GUID strings shorter than 32 hex digits are clean Errs — the
        // length check fires before any indexing, never a panic.
        assert!(guid_from_string("").is_err());
        assert!(guid_from_string("9B5A").is_err());
        assert!(guid_from_string("9b5a1d2f-2211-4433-5566").is_err());

        // Mid-compressed-integer cuts are hard errors everywhere.
        for tagged in [&[0x1eu8, 0x80][..], &[0x2a, 0x09, 0x80][..], &[0x2a, 0x09, 0x02, 0x80][..]] {
            assert!(
                parse_marshal_spec(tagged, &mut res).is_err(),
                "mid-compressed cut {tagged:?} decoded"
            );
        }
        // SAFEARRAY with an unknown VARENUM byte is rejected.
        assert!(parse_marshal_spec(&[0x1d, 0x80], &mut res).is_err());
        // INTF with a cut compressed index is rejected.
        assert!(parse_marshal_spec(&[0x1c, 0x80], &mut res).is_err());

        // Unknown top-level tag / trailing garbage remain errors.
        assert!(parse_marshal_spec(&[0x00], &mut res).is_err());
        assert!(parse_marshal_spec(&[0x15, 0x66], &mut res).is_err());
    }

    /// Prefixes before optional trailing payloads legitimately decode to a
    /// default-filled spec (this IS Mono.Cecil's CanReadMore behaviour);
    /// assert they differ from the full value instead of requiring Err.
    #[test]
    fn truncated_optional_tails_yield_shorter_specs() {
        let cases: [(Vec<u8>, NativeTypeSpec); 3] = [
            (
                vec![0x17],
                NativeTypeSpec::FixedSysString { size_count: 0 },
            ),
            (
                vec![0x1e, 0x0c],
                NativeTypeSpec::FixedArray {
                    size: 12,
                    element: None,
                },
            ),
            (
                vec![0x2a, 0x09, 0x02, 0x42],
                NativeTypeSpec::NativeArray {
                    element: Some(Box::new(NativeTypeSpec::I8)),
                    param_num: 2,
                    elem_mult: 0,
                    num_elem: 66,
                },
            ),
        ];
        for (prefix, expected) in cases {
            assert_eq!(parse_ok(&prefix).spec, expected);
        }
    }

    #[test]
    fn safearray_resolver_errors_propagate() {
        let mut failing: Box<TdorResolver> =
            Box::new(|_| Err(Error::bad_image("no resolver here")));
        // Raw variant byte 0x09 (Dispatch), then an unresolvable cell.
        assert!(parse_marshal_spec(&[0x1d, 0x09, 0x07], &mut failing).is_err());
    }

    #[test]
    fn unknown_variant_encoding_fails() {
        // An element_desc whose encoder rejects the type surfaces as Err.
        let info = MarshalInfo {
            spec: NativeTypeSpec::SafeArray {
                element_variant: Some(VariantType::BStr),
                element_desc: Some(Box::new(TypeDesc::Sentinel)),
            },
        };
        assert!(write_marshal_spec(&info, &mut enc_cell()).is_err());
    }
}
