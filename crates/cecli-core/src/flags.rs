//! Metadata attribute flags (ECMA-335 II) and runtime target enums.
//! Values ported verbatim from Mono.Cecil's attribute enums.

use bitflags::bitflags;
use std::fmt;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct TypeAttributes: u32 {
        const VISIBILITY_MASK = 0x0000_0007;
        const NOT_PUBLIC = 0x0000_0000;
        const PUBLIC = 0x0000_0001;
        const NESTED_PUBLIC = 0x0000_0002;
        const NESTED_PRIVATE = 0x0000_0003;
        const NESTED_FAMILY = 0x0000_0004;
        const NESTED_ASSEMBLY = 0x0000_0005;
        const NESTED_FAM_AND_ASSEM = 0x0000_0006;
        const NESTED_FAM_OR_ASSEM = 0x0000_0007;

        const LAYOUT_MASK = 0x0000_0018;
        const AUTO_LAYOUT = 0x0000_0000;
        const SEQUENTIAL_LAYOUT = 0x0000_0008;
        const EXPLICIT_LAYOUT = 0x0000_0010;

        const CLASS_SEMANTIC_MASK = 0x0000_0020;
        const CLASS_SEMANTIC = 0x0000_0000;
        const INTERFACE = 0x0000_0020;

        const ABSTRACT = 0x0000_0080;
        const SEALED = 0x0000_0100;
        const SPECIAL_NAME = 0x0000_0400;
        const RTSPECIAL_NAME = 0x0000_0800;

        const IMPORT = 0x0000_1000;
        const SERIALIZABLE = 0x0000_2000;
        const WINDOWS_RUNTIME = 0x0000_4000;

        const STRING_FORMAT_MASK = 0x0003_0000;
        const ANSI_STRING_FORMAT = 0x0000_0000;
        const UNICODE_STRING_FORMAT = 0x0001_0000;
        const AUTO_STRING_FORMAT = 0x0002_0000;
        const CUSTOM_STRING_FORMAT = 0x0003_0000;

        const HAS_SECURITY = 0x0004_0000;
        const BEFORE_FIELD_INIT = 0x0010_0000;
        const FORWARDER = 0x0020_0000;
    }
}

impl TypeAttributes {
    pub fn visibility(self) -> u32 {
        self.bits() & Self::VISIBILITY_MASK.bits()
    }
    pub fn with_visibility(self, v: u32) -> Self {
        TypeAttributes::from_bits_truncate((self.bits() & !0x7) | v)
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct FieldAttributes: u16 {
        const FIELD_ACCESS_MASK = 0x0007;
        const COMPILER_CONTROLLED = 0x0000;
        const PRIVATE = 0x0001;
        const FAM_AND_ASSEM = 0x0002;
        const ASSEMBLY = 0x0003;
        const FAMILY = 0x0004;
        const FAM_OR_ASSEM = 0x0005;
        const PUBLIC = 0x0006;

        const STATIC = 0x0010;
        const INIT_ONLY = 0x0020;
        const LITERAL = 0x0040;
        const NOT_SERIALIZED = 0x0080;
        const HAS_FIELD_RVA = 0x0100;
        const SPECIAL_NAME = 0x0200;
        const RTSPECIAL_NAME = 0x0400;
        const HAS_FIELD_MARSHAL = 0x1000;
        const PINVOKE_IMPL = 0x2000;
        const HAS_DEFAULT = 0x8000;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct MethodAttributes: u16 {
        const MEMBER_ACCESS_MASK = 0x0007;
        const COMPILER_CONTROLLED = 0x0000;
        const PRIVATE = 0x0001;
        const FAM_AND_ASSEM = 0x0002;
        const ASSEMBLY = 0x0003;
        const FAMILY = 0x0004;
        const FAM_OR_ASSEM = 0x0005;
        const PUBLIC = 0x0006;

        const STATIC = 0x0010;
        const FINAL = 0x0020;
        const VIRTUAL = 0x0040;
        const HIDE_BY_SIG = 0x0080;

        const VTABLE_LAYOUT_MASK = 0x0100;
        const REUSE_SLOT = 0x0000;
        const NEW_SLOT = 0x0100;

        const CHECK_ACCESS_ON_OVERRIDE = 0x0200;
        const ABSTRACT = 0x0400;
        const SPECIAL_NAME = 0x0800;
        const UNMANAGED_EXPORT = 0x0008;
        const RTSPECIAL_NAME = 0x1000;
        const PINVOKE_IMPL = 0x2000;
        const HAS_SECURITY = 0x4000;
        const REQUIRE_SEC_OBJECT = 0x8000;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct ParameterAttributes: u16 {
        const NONE = 0x0000;
        const IN = 0x0001;
        const OUT = 0x0002;
        const LCID = 0x0004;
        const RETVAL = 0x0008;
        const OPTIONAL = 0x0010;
        const HAS_DEFAULT = 0x1000;
        const HAS_FIELD_MARSHAL = 0x2000;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct PropertyAttributes: u16 {
        const NONE = 0x0000;
        const SPECIAL_NAME = 0x0200;
        const RTSPECIAL_NAME = 0x0400;
        const HAS_DEFAULT = 0x1000;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct EventAttributes: u16 {
        const NONE = 0x0000;
        const SPECIAL_NAME = 0x0200;
        const RTSPECIAL_NAME = 0x0400;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct GenericParameterAttributes: u16 {
        const VARIANCE_MASK = 0x0003;
        const NON_VARIANT = 0x0000;
        const COVARIANT = 0x0001;
        const CONTRAVARIANT = 0x0002;

        const SPECIAL_CONSTRAINT_MASK = 0x001C;
        const REFERENCE_TYPE_CONSTRAINT = 0x0004;
        const NOT_NULLABLE_VALUE_TYPE_CONSTRAINT = 0x0008;
        const DEFAULT_CONSTRUCTOR_CONSTRAINT = 0x0010;
        const ALLOW_BY_REF_LIKE_CONSTRAINT = 0x0020;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct MethodImplAttributes: u16 {
        const CODE_TYPE_MASK = 0x0003;
        const IL = 0x0000;
        const NATIVE = 0x0001;
        const OPTIL = 0x0002;
        const RUNTIME = 0x0003;

        const MANAGED_MASK = 0x0004;
        const UNMANAGED = 0x0004;
        const MANAGED = 0x0000;

        const FORWARD_REF = 0x0010;
        const SYNCHRONIZED = 0x0020;
        const NO_OPTIMIZATION = 0x0040;
        const NO_INLINING = 0x0008;
        const PRESERVE_SIG = 0x0080;
        const AGGRESSIVE_INLINING = 0x0100;
        const AGGRESSIVE_OPTIMIZATION = 0x0200;
        const INTERNAL_CALL = 0x1000;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct MethodSemanticsAttributes: u16 {
        const NONE = 0x0000;
        const SETTER = 0x0001;
        const GETTER = 0x0002;
        const OTHER = 0x0004;
        const ADD_ON = 0x0008;
        const REMOVE_ON = 0x0010;
        const FIRE = 0x0020;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct PInvokeAttributes: u16 {
        const NO_MANGLE = 0x0001;

        const CHAR_SET_MASK = 0x0006;
        const CHAR_SET_NOT_SPEC = 0x0000;
        const CHAR_SET_ANSI = 0x0002;
        const CHAR_SET_UNICODE = 0x0004;
        const CHAR_SET_AUTO = 0x0006;

        const BEST_FIT_MASK = 0x0030;
        const BEST_FIT_ENABLED = 0x0010;
        const BEST_FIT_DISABLED = 0x0020;

        const SUPPORTS_LAST_ERROR = 0x0040;

        const CALL_CONV_MASK = 0x0700;
        const CALL_CONV_WINAPI = 0x0100;
        const CALL_CONV_CDECL = 0x0200;
        const CALL_CONV_STDCALL = 0x0300;
        const CALL_CONV_THISCALL = 0x0400;
        const CALL_CONV_FASTCALL = 0x0500;

        const THROW_ON_UNMAPPABLE_CHAR_MASK = 0x3000;
        const THROW_ON_UNMAPPABLE_CHAR_ENABLED = 0x1000;
        const THROW_ON_UNMAPPABLE_CHAR_DISABLED = 0x2000;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct ManifestResourceAttributes: u32 {
        const VISIBILITY_MASK = 0x0000_0007;
        const PUBLIC = 0x0000_0001;
        const PRIVATE = 0x0000_0002;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct AssemblyAttributes: u32 {
        const PUBLIC_KEY = 0x0001;
        const SIDE_BY_SIDE_COMPATIBLE = 0x0000;
        const RETARGETABLE = 0x0100;
        const WINDOWS_RUNTIME = 0x0200;
        const DISABLE_JIT_COMPILE_OPTIMIZER = 0x4000;
        const ENABLE_JIT_COMPILE_TRACKING = 0x8000;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct FileRowAttributes: u32 {
        const CONTAINS_METADATA = 0x0000;
        const CONTAINS_NO_METADATA = 0x0001;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct ModuleAttributes: u32 {
        const IL_ONLY = 0x0000_0001;
        const REQUIRED_32_BIT = 0x0000_0002;
        const IL_LIBRARY = 0x0000_0004;
        const STRONG_NAME_SIGNED = 0x0000_0008;
        const TRACK_DEBUG_DATA = 0x0001_0000;
        const PREFERRED_32_BIT = 0x0002_0000;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct ModuleCharacteristics: u16 {
        const HIGH_ENTROPY_VA = 0x0020;
        const DYNAMIC_BASE = 0x0040;
        const NO_SEH = 0x0400;
        const NX_COMPAT = 0x0100;
        const APP_CONTAINER = 0x1000;
        const TERMINAL_SERVER_AWARE = 0x8000;
    }
}

/// CLI header runtime kind (`ModuleKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModuleKind {
    Dll,
    Console,
    Windows,
    NetModule,
}

/// What kind of metadata a module carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetadataKind {
    Ecma335,
    WindowsMetadata,
    ManagedWindowsMetadata,
}

/// Target CPU architecture (PE machine discriminator).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetArchitecture {
    I386,
    AMD64,
    IA64,
    ARM,
    ARMv7,
    ARM64,
}

impl TargetArchitecture {
    pub fn from_machine(machine: u16) -> Option<Self> {
        Some(match machine {
            0x014c => TargetArchitecture::I386,
            0x8664 => TargetArchitecture::AMD64,
            0x0200 => TargetArchitecture::IA64,
            0x01c0 => TargetArchitecture::ARM,
            0x01c4 => TargetArchitecture::ARMv7,
            0xaa64 => TargetArchitecture::ARM64,
            _ => return None,
        })
    }

    pub fn machine(self) -> u16 {
        match self {
            TargetArchitecture::I386 => 0x014c,
            TargetArchitecture::AMD64 => 0x8664,
            TargetArchitecture::IA64 => 0x0200,
            TargetArchitecture::ARM => 0x01c0,
            TargetArchitecture::ARMv7 => 0x01c4,
            TargetArchitecture::ARM64 => 0xaa64,
        }
    }
}

/// CLR runtime version a module targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetRuntime {
    Net10,
    Net11,
    Net20,
    Net40,
}

/// DeclSecurity / hash algorithm enumerations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum AssemblyHashAlgorithm {
    None = 0,
    Md5 = 0x8003,
    Sha1 = 0x8004,
    Sha256 = 0x800C,
    Sha384 = 0x800D,
    Sha512 = 0x800E,
}

impl AssemblyHashAlgorithm {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => AssemblyHashAlgorithm::None,
            0x8003 => AssemblyHashAlgorithm::Md5,
            0x8004 => AssemblyHashAlgorithm::Sha1,
            0x800C => AssemblyHashAlgorithm::Sha256,
            0x800D => AssemblyHashAlgorithm::Sha384,
            0x800E => AssemblyHashAlgorithm::Sha512,
            _ => return None,
        })
    }
}

/// DeclSecurity action codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SecurityAction {
    Request = 1,
    Demand = 2,
    Assert = 3,
    Deny = 4,
    PermitOnly = 5,
    LinkDemand = 6,
    InheritanceDemand = 7,
    RequestMinimum = 8,
    RequestOptional = 9,
    RequestRefuse = 10,
    PreJitGrant = 11,
    PreJitDeny = 12,
    NonCasDemand = 13,
    NonCasLinkDemand = 14,
    NonCasInheritance = 15,
}

impl SecurityAction {
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            1 => SecurityAction::Request,
            2 => SecurityAction::Demand,
            3 => SecurityAction::Assert,
            4 => SecurityAction::Deny,
            5 => SecurityAction::PermitOnly,
            6 => SecurityAction::LinkDemand,
            7 => SecurityAction::InheritanceDemand,
            8 => SecurityAction::RequestMinimum,
            9 => SecurityAction::RequestOptional,
            10 => SecurityAction::RequestRefuse,
            11 => SecurityAction::PreJitGrant,
            12 => SecurityAction::PreJitDeny,
            13 => SecurityAction::NonCasDemand,
            14 => SecurityAction::NonCasLinkDemand,
            15 => SecurityAction::NonCasInheritance,
            _ => return None,
        })
    }
}

impl fmt::Display for SecurityAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// First bytes of a method signature: calling convention (ECMA-335 II §23.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SignatureCallingConvention {
    Default = 0x0,
    /// Native C declaration (`CALLCONV_C`), unmanaged mixed-mode images.
    C = 0x1,
    /// Native stdcall (`CALLCONV_STDCALL`).
    StdCall = 0x2,
    /// Native thiscall (`CALLCONV_THISCALL`).
    ThisCall = 0x3,
    /// Native fastcall (`CALLCONV_FASTCALL`).
    FastCall = 0x4,
    VarArg = 0x5,
    Field = 0x6,
    LocalSig = 0x7,
    Property = 0x8,
    Unmanaged = 0x9,
    Generic = 0x10,
}

pub const CALL_CONVENTION_HAS_THIS: u8 = 0x20;
pub const CALL_CONVENTION_EXPLICIT_THIS: u8 = 0x40;

#[cfg(test)]
mod tests {
    use super::*;

    /// The DeclSecurity action codes 11–15 (PreJit/NonCas family) are
    /// constructible, display under their Cecil names, and round-trip
    /// through the reader-side [`SecurityAction::from_u16`] helper.
    #[test]
    fn prejit_and_noncas_actions_construct_and_display() {
        let actions = [
            (11u16, SecurityAction::PreJitGrant, "PreJitGrant"),
            (12, SecurityAction::PreJitDeny, "PreJitDeny"),
            (13, SecurityAction::NonCasDemand, "NonCasDemand"),
            (14, SecurityAction::NonCasLinkDemand, "NonCasLinkDemand"),
            (
                15,
                SecurityAction::NonCasInheritance,
                "NonCasInheritance",
            ),
        ];
        for (code, action, name) in actions {
            assert_eq!(action as u16, code);
            assert_eq!(SecurityAction::from_u16(code), Some(action));
            assert_eq!(action.to_string(), name);
        }
    }

    #[test]
    fn security_action_from_u16_rejects_unknown() {
        assert_eq!(SecurityAction::from_u16(0), None);
        assert_eq!(SecurityAction::from_u16(16), None);
        // Known low codes still resolve.
        assert_eq!(SecurityAction::from_u16(2), Some(SecurityAction::Demand));
    }
}
