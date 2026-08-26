//! Security declaration (`DeclSecurity` blob) decoding and encoding.
//!
//! Port of the permission-set semantics exposed by
//! `rocks/Mono.Cecil.Rocks/SecurityDeclarationRocks.cs`: that code hands the
//! raw blob to the BCL's `PermissionSetAttribute`, which understands two wire
//! forms. Both are implemented here directly (the reference decoder used to pin
//! down the binary layout is dnlib's `DeclSecurityReader`, which mirrors the
//! .NET Framework behaviour):
//!
//! * **Legacy XML form** (.NET Framework 1.x): the whole blob is UTF-16LE
//!   encoded XML text, e.g. `<PermissionSet class="..." version="1">…`.
//! * **Binary attribute-set form** (.NET Framework 2.0+, first byte `.`):
//!   `'.' + compressed_u32(attrCount)` followed per attribute by
//!   `SerString(typeName) + compressed_u32(declaredLength) +
//!   compressed_u32(namedArgCount) + custom-attribute named arguments`
//!   (kind byte, `FieldOrPropType`, SerString name, typed value — identical
//!   encoding to the custom attribute blob).
//!
//! [`decode_security_xml`] normalises either form into the XML text of the
//! permission set; [`encode_security_xml`] parses canonical XML back into the
//! binary attribute-set form.

use cecli_core::io::{ByteReader, ByteWriter};
use cecli_core::{Error, Result};

use super::custom_attribute::{
    read_named_argument, read_ser_string, write_named_argument, write_ser_string, CArgument,
};
use super::types::TypeDesc;

/// First byte selecting the binary attribute-set form.
const BINARY_MARKER: u8 = b'.';

/// Named-argument tag written for permission properties (a `PermissionSet`
/// attribute exposes its settings as properties).
const PROPERTY_TAG: u8 = 0x54;

/// Canonical header line emitted when rebuilding XML from the binary form.
const PERMISSION_SET_HEADER: &str =
    "<PermissionSet class=\"System.Security.PermissionSet\" version=\"1\">\r\n";
/// Canonical closing line.
const PERMISSION_SET_FOOTER: &str = "</PermissionSet>\r\n";

/// Fallback resolver for typed values inside binary permission sets: this API
/// has no metadata context, so `TypeDefOrRef` cells surface as synthetic
/// internal type descriptors instead of failing the whole decode.
fn fallback_resolver() -> impl FnMut(u32) -> Result<TypeDesc> {
    move |cell| Ok(TypeDesc::Internal(format!("<tdor:{cell:#x}>")))
}

/// Encoder stub mirroring [`fallback_resolver`]; only reachable for typed
/// values the XML writer cannot express anyway.
fn fallback_encoder() -> impl FnMut(&TypeDesc) -> Result<u32> {
    |_ty| Err(Error::unsupported("cannot encode typed security property"))
}

/// Decodes a `DeclSecurity` permission-set blob into its XML text.
///
/// Legacy UTF-16 blobs are returned verbatim (minus NUL padding); binary
/// attribute-set blobs are rebuilt into canonical `<PermissionSet>` XML where
/// each decoded attribute becomes one `<IPermission class="…" …/>` element with
/// its named arguments rendered as attributes.
pub fn decode_security_xml(blob: &[u8]) -> Result<String> {
    if blob.is_empty() {
        return Err(Error::bad_image("empty security declaration blob"));
    }
    if blob[0] == BINARY_MARKER {
        decode_binary_permission_set(&blob[1..])
    } else {
        decode_legacy_xml(blob)
    }
}

/// Encodes canonical permission-set XML into the binary attribute-set blob
/// form (first byte `.`). Inverse of [`decode_security_xml`] for canonical
/// input: property values are stored as string arguments and the fixed
/// `version="1"` attribute is implied.
pub fn encode_security_xml(xml: &str) -> Result<Vec<u8>> {
    let permissions = parse_ipermissions(xml)?;
    if permissions.is_empty() {
        return Err(Error::argument("no <IPermission> elements found in permission-set XML"));
    }

    let mut w = ByteWriter::new();
    w.u8(BINARY_MARKER);
    if permissions.len() > 0x1fff_ffff {
        return Err(Error::argument("too many permissions"));
    }
    w.compressed_u32(permissions.len() as u32);
    let mut enc = fallback_encoder();
    for (class, props) in &permissions {
        let mut args = ByteWriter::new();
        if props.len() > 0x1fff_ffff {
            return Err(Error::argument("too many permission properties"));
        }
        for (name, value) in props {
            write_named_argument(&mut args, PROPERTY_TAG, name, value, &mut enc)?;
        }
        write_ser_string(&mut w, Some(class))?;
        // Declared payload length covers everything that follows it.
        let declared_len = compressed_len(props.len() as u32) + args.len();
        w.compressed_u32(declared_len as u32);
        w.compressed_u32(props.len() as u32);
        w.bytes(args.as_slice());
    }
    Ok(w.into_vec())
}

/// Byte length of `v` in compressed-unsigned encoding.
fn compressed_len(v: u32) -> usize {
    if v < 0x80 {
        1
    } else if v < 0x4000 {
        2
    } else {
        4
    }
}

// ---------------------------------------------------------------------------
// Legacy UTF-16 XML form
// ---------------------------------------------------------------------------

fn decode_legacy_xml(blob: &[u8]) -> Result<String> {
    if !blob.len().is_multiple_of(2) {
        return Err(Error::bad_image(
            "legacy security blob must be a whole number of UTF-16 code units",
        ));
    }
    let units: Vec<u16> = blob.chunks_exact(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
    let mut xml = String::from_utf16(&units)
        .map_err(|_| Error::bad_image("invalid UTF-16 in legacy security blob"))?;
    while xml.ends_with('\0') {
        xml.pop();
    }
    Ok(xml)
}

// ---------------------------------------------------------------------------
// Binary attribute-set form
// ---------------------------------------------------------------------------

fn decode_binary_permission_set(data: &[u8]) -> Result<String> {
    let mut rd = ByteReader::new(data);
    let count = rd.compressed_u32()?;
    let mut r = fallback_resolver();
    let mut xml = String::from(PERMISSION_SET_HEADER);
    for _ in 0..count {
        let class = read_ser_string(&mut rd)?.ok_or_else(|| {
            Error::bad_image("null marker where a permission class name was expected")
        })?;
        // Declared payload length: informational, arguments follow inline.
        let _declared_len = rd.compressed_u32()?;
        let prop_count = rd.compressed_u32()?;
        let mut props = String::new();
        for _ in 0..prop_count {
            let (name, value) = read_named_argument(&mut rd, &mut r)?;
            props.push_str(&format!(
                " {}=\"{}\"",
                escape_xml(&name),
                escape_xml(&render_value(&value)?)
            ));
        }
        xml.push_str(&format!(
            "<IPermission class=\"{}\" version=\"1\"{}/>\r\n",
            escape_xml(&class),
            props
        ));
    }
    xml.push_str(PERMISSION_SET_FOOTER);
    if !rd.is_empty() {
        return Err(Error::bad_image("binary permission set has trailing bytes"));
    }
    Ok(xml)
}

/// Renders an argument value as an XML attribute value (best effort).
fn render_value(value: &CArgument) -> Result<String> {
    Ok(match value {
        CArgument::String(Some(s)) => s.clone(),
        CArgument::String(None) => String::new(),
        CArgument::Bool(b) => b.to_string(),
        CArgument::Char(c) => c.to_string(),
        CArgument::I8(v) => v.to_string(),
        CArgument::U8(v) => v.to_string(),
        CArgument::I16(v) => v.to_string(),
        CArgument::U16(v) => v.to_string(),
        CArgument::I32(v) => v.to_string(),
        CArgument::U32(v) => v.to_string(),
        CArgument::I64(v) => v.to_string(),
        CArgument::U64(v) => v.to_string(),
        CArgument::F32(v) => v.to_string(),
        CArgument::F64(v) => v.to_string(),
        CArgument::Enum { value, .. } => match value.as_ref() {
            CArgument::I32(v) => v.to_string(),
            other => {
                return Err(Error::unsupported(format!(
                    "enum permission property value {other:?} has no XML attribute form"
                )))
            }
        },
        CArgument::NullObj => String::new(),
        CArgument::Type(_) | CArgument::Boxed(_) | CArgument::Array(_) => {
            return Err(Error::unsupported(format!(
                "permission property value {value:?} has no XML attribute form"
            )))
        }
    })
}

fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn unescape_xml(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&") // last: keeps "&amp;amp;" correct
}

// ---------------------------------------------------------------------------
// Minimal XML scanning for encode
// ---------------------------------------------------------------------------

/// Extracts `(class, properties)` from each `<IPermission …/>` element of the
/// permission-set XML, in document order. `version` is implied and dropped;
/// every other attribute becomes a string-valued property argument.
fn parse_ipermissions(xml: &str) -> Result<Vec<(String, Vec<(String, CArgument)>)>> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(off) = xml[i..].find("<IPermission") {
        let start = i + off + "<IPermission".len();
        // Element body runs to the next '>' (XML attributes may not contain one).
        let end_rel = xml[start..].find('>').ok_or_else(|| {
            Error::argument("unterminated <IPermission> element in permission-set XML")
        })?;
        let body = &xml[start..start + end_rel];
        i = start + end_rel;

        let mut class: Option<String> = None;
        let mut props = Vec::new();
        let bb = body.as_bytes();
        let mut j = 0;
        while j < bb.len() {
            if bb[j].is_ascii_whitespace() || bb[j] == b'/' {
                j += 1;
                continue;
            }
            // Attribute name runs up to '='.
            let name_start = j;
            while j < bb.len() && bb[j] != b'=' && !bb[j].is_ascii_whitespace() {
                j += 1;
            }
            let name = &body[name_start..j];
            while j < bb.len() && bb[j].is_ascii_whitespace() {
                j += 1;
            }
            if j >= bb.len() || bb[j] != b'=' {
                return Err(Error::argument(format!(
                    "malformed attribute '{name}' in <IPermission>"
                )));
            }
            j += 1;
            while j < bb.len() && bb[j].is_ascii_whitespace() {
                j += 1;
            }
            if j >= bb.len() || (bb[j] != b'"' && bb[j] != b'\'') {
                return Err(Error::argument(format!(
                    "attribute '{name}' is missing a quoted value"
                )));
            }
            let quote = bb[j];
            j += 1;
            let val_start = j;
            while j < bb.len() && bb[j] != quote {
                j += 1;
            }
            if j >= bb.len() {
                return Err(Error::argument("unterminated attribute value"));
            }
            let value = unescape_xml(&body[val_start..j]);
            j += 1;

            match name {
                "class" => class = Some(value),
                "version" => {} // implied by the binary form
                other => props.push((other.to_owned(), CArgument::String(Some(value)))),
            }
        }

        let class = class.ok_or_else(|| {
            Error::argument("<IPermission> element is missing its 'class' attribute")
        })?;
        out.push((class, props));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical sample shaped after the decsec fixtures' permission sets.
    const SAMPLE: &str = concat!(
        "<PermissionSet class=\"System.Security.PermissionSet\" version=\"1\">\r\n",
        "<IPermission class=\"System.Security.Permissions.SecurityPermission, mscorlib, ",
        "Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\" version=\"1\" ",
        "Flags=\"UnmanagedCode\"/>\r\n",
        "<IPermission class=\"System.Security.Permissions.FileDialogPermission, mscorlib\" ",
        "version=\"1\" Access=\"Open\"/>\r\n",
        "</PermissionSet>\r\n"
    );

    #[test]
    fn roundtrip_through_binary_form() {
        let blob = encode_security_xml(SAMPLE).expect("encode");
        assert_eq!(blob[0], b'.');
        let xml = decode_security_xml(&blob).expect("decode");
        assert_eq!(xml, SAMPLE);
    }

    #[test]
    fn legacy_utf16_blob_decodes_verbatim() {
        let mut blob: Vec<u8> = Vec::new();
        for unit in SAMPLE.encode_utf16() {
            blob.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(decode_security_xml(&blob).expect("decode"), SAMPLE);
    }

    #[test]
    fn escaping_survives_roundtrip() {
        let xml = concat!(
            "<PermissionSet class=\"System.Security.PermissionSet\" version=\"1\">\r\n",
            "<IPermission class=\"Some.Permission\" version=\"1\" ",
            "Note=\"a&amp;b&lt;c&gt;d&quot;e&apos;s\"/>\r\n",
            "</PermissionSet>\r\n"
        );
        let blob = encode_security_xml(xml).unwrap();
        assert_eq!(decode_security_xml(&blob).unwrap(), xml);
    }

    #[test]
    fn malformed_blobs_are_errors() {
        assert!(decode_security_xml(&[]).is_err());
        // Odd number of bytes cannot be UTF-16.
        assert!(decode_security_xml(&[0x3c]).is_err());
        // Binary marker but truncated attribute count.
        assert!(decode_security_xml(b".").is_err());
        // Binary marker + count but truncated class name.
        assert!(decode_security_xml(&[b'.', 0x01, 0x05, b'A']).is_err());
        // Truncated named-argument section.
        assert!(decode_security_xml(&[
            b'.', 0x01, // one attribute
            0x03, b'A', b'B', b'C', // class "ABC" (len 3)
            0x00, // declared length (informational)
            0x01, // one named argument
            0x54, // property kind
            0x08, // ELEMENT_TYPE_I32
            0x03, b'F', b'l', b'a', // name "Fla", value truncated away
        ])
        .is_err());
    }

    #[test]
    fn xml_without_permissions_is_rejected() {
        assert!(encode_security_xml("<PermissionSet></PermissionSet>").is_err());
        assert!(encode_security_xml("").is_err());
        // Missing 'class' attribute.
        assert!(encode_security_xml("<PermissionSet><IPermission version=\"1\"/></PermissionSet>")
            .is_err());
    }
}
