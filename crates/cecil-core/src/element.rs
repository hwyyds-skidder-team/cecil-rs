//! ECMA-335 `ElementType` codes and OLE `VARENUM` variant types.

/// Signature element type byte (ECMA-335 II §23.1.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ElementType {
    End = 0x00,
    Void = 0x01,
    Boolean = 0x02,
    Char = 0x03,
    I1 = 0x04,
    U1 = 0x05,
    I2 = 0x06,
    U2 = 0x07,
    I4 = 0x08,
    U4 = 0x09,
    I8 = 0x0A,
    U8 = 0x0B,
    R4 = 0x0C,
    R8 = 0x0D,
    String = 0x0E,
    Ptr = 0x0F,
    ByRef = 0x10,
    ValueType = 0x11,
    Class = 0x12,
    Var = 0x13,
    Array = 0x14,
    GenericInst = 0x15,
    TypedByRef = 0x16,
    I = 0x18,
    U = 0x19,
    FnPtr = 0x1B,
    Object = 0x1C,
    SzArray = 0x1D,
    MVar = 0x1E,
    CmodReqd = 0x1F,
    CmodOpt = 0x20,
    Internal = 0x21,
    Module = 0x39,
    Sentinel = 0x41,
    Pinned = 0x45,
}

impl ElementType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x00 => ElementType::End,
            0x01 => ElementType::Void,
            0x02 => ElementType::Boolean,
            0x03 => ElementType::Char,
            0x04 => ElementType::I1,
            0x05 => ElementType::U1,
            0x06 => ElementType::I2,
            0x07 => ElementType::U2,
            0x08 => ElementType::I4,
            0x09 => ElementType::U4,
            0x0A => ElementType::I8,
            0x0B => ElementType::U8,
            0x0C => ElementType::R4,
            0x0D => ElementType::R8,
            0x0E => ElementType::String,
            0x0F => ElementType::Ptr,
            0x10 => ElementType::ByRef,
            0x11 => ElementType::ValueType,
            0x12 => ElementType::Class,
            0x13 => ElementType::Var,
            0x14 => ElementType::Array,
            0x15 => ElementType::GenericInst,
            0x16 => ElementType::TypedByRef,
            0x18 => ElementType::I,
            0x19 => ElementType::U,
            0x1B => ElementType::FnPtr,
            0x1C => ElementType::Object,
            0x1D => ElementType::SzArray,
            0x1E => ElementType::MVar,
            0x1F => ElementType::CmodReqd,
            0x20 => ElementType::CmodOpt,
            0x21 => ElementType::Internal,
            0x39 => ElementType::Module,
            0x41 => ElementType::Sentinel,
            0x45 => ElementType::Pinned,
            _ => return None,
        })
    }

    pub fn is_primitive(self) -> bool {
        matches!(
            self,
            ElementType::Boolean
                | ElementType::Char
                | ElementType::I1
                | ElementType::U1
                | ElementType::I2
                | ElementType::U2
                | ElementType::I4
                | ElementType::U4
                | ElementType::I8
                | ElementType::U8
                | ElementType::R4
                | ElementType::R8
                | ElementType::I
                | ElementType::U
        )
    }
}

/// OLE `VARENUM`, used by constant tables and marshaling metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum VariantType {
    None = 0x00,
    Null = 0x01,
    Boolean = 0x02,
    Char = 0x03,
    I1 = 0x04,
    U1 = 0x05,
    I2 = 0x06,
    U2 = 0x07,
    I4 = 0x08,
    U4 = 0x09,
    I8 = 0x0A,
    U8 = 0x0B,
    R4 = 0x0C,
    R8 = 0x0D,
    String = 0x14,
    Ptr = 0x26,
    Int = 0x16,
    UInt = 0x17,
    Currency = 0x06_00, // VT_CY
    Date = 0x07_00,     // VT_DATE
    BStr = 0x08_00,     // VT_BSTR
    Dispatch = 0x09_00, // VT_DISPATCH
    Error = 0x0A_00,    // VT_ERROR
    Bool = 0x0B_00,     // VT_BOOL
    Variant = 0x0C_00,  // VT_VARIANT
    Unknown = 0x0D_00,  // VT_UNKNOWN
    Decimal = 0x0E_00,  // VT_DECIMAL
    Void = 0x18_00,     // VT_VOID
    HResult = 0x19_00,  // VT_HRESULT
    SafeArray = 0x1B_00,
    CArray = 0x1C_00,
    UserDefined = 0x1D_00,
    Record = 0x24_00,
    FileTime = 0x40_00,
    Blob = 0x41_00,
    Stream = 0x42_00,
    Storage = 0x43_00,
    StreamedObject = 0x44_00,
    StoredObject = 0x45_00,
    BlobObject = 0x46_00,
    Clsid = 0x48_00,
}

impl VariantType {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0x00 => VariantType::None,
            0x01 => VariantType::Null,
            0x02 => VariantType::Boolean,
            0x03 => VariantType::Char,
            0x04 => VariantType::I1,
            0x05 => VariantType::U1,
            0x06 => VariantType::I2,
            0x07 => VariantType::U2,
            0x08 => VariantType::I4,
            0x09 => VariantType::U4,
            0x0A => VariantType::I8,
            0x0B => VariantType::U8,
            0x0C => VariantType::R4,
            0x0D => VariantType::R8,
            0x14 => VariantType::String,
            0x16 => VariantType::Int,
            0x17 => VariantType::UInt,
            0x26 => VariantType::Ptr,
            0x06_00 => VariantType::Currency,
            0x07_00 => VariantType::Date,
            0x08_00 => VariantType::BStr,
            0x09_00 => VariantType::Dispatch,
            0x0A_00 => VariantType::Error,
            0x0B_00 => VariantType::Bool,
            0x0C_00 => VariantType::Variant,
            0x0D_00 => VariantType::Unknown,
            0x0E_00 => VariantType::Decimal,
            0x18_00 => VariantType::Void,
            0x19_00 => VariantType::HResult,
            0x1B_00 => VariantType::SafeArray,
            0x1C_00 => VariantType::CArray,
            0x1D_00 => VariantType::UserDefined,
            0x24_00 => VariantType::Record,
            0x40_00 => VariantType::FileTime,
            0x41_00 => VariantType::Blob,
            0x42_00 => VariantType::Stream,
            0x43_00 => VariantType::Storage,
            0x44_00 => VariantType::StreamedObject,
            0x45_00 => VariantType::StoredObject,
            0x46_00 => VariantType::BlobObject,
            0x48_00 => VariantType::Clsid,
            _ => return None,
        })
    }

    /// The element type a constant of this variant decodes to.
    pub fn to_element_type(self) -> Option<ElementType> {
        Some(match self {
            VariantType::Boolean | VariantType::Bool => ElementType::Boolean,
            VariantType::Char => ElementType::Char,
            VariantType::I1 => ElementType::I1,
            VariantType::U1 => ElementType::U1,
            VariantType::I2 => ElementType::I2,
            VariantType::U2 => ElementType::U2,
            VariantType::I4 | VariantType::Int | VariantType::Error | VariantType::HResult => {
                ElementType::I4
            }
            VariantType::U4 | VariantType::UInt => ElementType::U4,
            VariantType::I8 => ElementType::I8,
            VariantType::U8 => ElementType::U8,
            VariantType::R4 => ElementType::R4,
            VariantType::R8 => ElementType::R8,
            VariantType::String | VariantType::BStr => ElementType::String,
            _ => return None,
        })
    }

    /// The variant encoding for a primitive element type.
    pub fn from_element_type(et: ElementType) -> Option<Self> {
        Some(match et {
            ElementType::Boolean => VariantType::Boolean,
            ElementType::Char => VariantType::Char,
            ElementType::I1 => VariantType::I1,
            ElementType::U1 => VariantType::U1,
            ElementType::I2 => VariantType::I2,
            ElementType::U2 => VariantType::U2,
            ElementType::I4 => VariantType::I4,
            ElementType::U4 => VariantType::U4,
            ElementType::I8 => VariantType::I8,
            ElementType::U8 => VariantType::U8,
            ElementType::R4 => VariantType::R4,
            ElementType::R8 => VariantType::R8,
            ElementType::String => VariantType::String,
            _ => return None,
        })
    }
}
