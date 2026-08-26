//! Metadata tokens, table indices, coded index groups, and signature calling conventions.

use std::fmt;

/// A CLI metadata token: high byte = table, low 24 bits = row id (1-based).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Token(pub u32);

impl Token {
    pub const NIL: Token = Token(0);

    pub fn new(table: TableIndex, rid: u32) -> Self {
        Token(((table as u32) << 24) | (rid & 0x00FF_FFFF))
    }

    pub fn is_nil(self) -> bool {
        self.0 == 0
    }

    pub fn table(self) -> TableIndex {
        TableIndex::from_u8((self.0 >> 24) as u8).expect("valid table in token")
    }

    /// Raw table discriminator byte (works for portable-PDB tables too).
    pub fn table_byte(self) -> u8 {
        (self.0 >> 24) as u8
    }

    /// 1-based row identifier.
    pub fn rid(self) -> u32 {
        self.0 & 0x00FF_FFFF
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}", self.0)
    }
}

/// All metadata table identifiers, including the Portable PDB debug tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum TableIndex {
    Module = 0x00,
    TypeRef = 0x01,
    TypeDef = 0x02,
    FieldPtr = 0x03,
    Field = 0x04,
    MethodPtr = 0x05,
    MethodDef = 0x06,
    ParamPtr = 0x07,
    Param = 0x08,
    InterfaceImpl = 0x09,
    MemberRef = 0x0A,
    Constant = 0x0B,
    CustomAttribute = 0x0C,
    FieldMarshal = 0x0D,
    DeclSecurity = 0x0E,
    ClassLayout = 0x0F,
    FieldLayout = 0x10,
    StandAloneSig = 0x11,
    EventMap = 0x12,
    EventPtr = 0x13,
    Event = 0x14,
    PropertyMap = 0x15,
    PropertyPtr = 0x16,
    Property = 0x17,
    MethodSemantics = 0x18,
    MethodImpl = 0x19,
    ModuleRef = 0x1A,
    TypeSpec = 0x1B,
    ImplMap = 0x1C,
    FieldRva = 0x1D,
    EncLog = 0x1E,
    EncMap = 0x1F,
    Assembly = 0x20,
    AssemblyProcessor = 0x21,
    AssemblyOS = 0x22,
    AssemblyRef = 0x23,
    AssemblyRefProcessor = 0x24,
    AssemblyRefOS = 0x25,
    File = 0x26,
    ExportedType = 0x27,
    ManifestResource = 0x28,
    NestedClass = 0x29,
    GenericParam = 0x2A,
    MethodSpec = 0x2B,
    GenericParamConstraint = 0x2C,
    // Portable PDB tables.
    Document = 0x30,
    MethodDebugInformation = 0x31,
    LocalScope = 0x32,
    LocalVariable = 0x33,
    LocalConstant = 0x34,
    ImportScope = 0x35,
    StateMachineMethod = 0x36,
    CustomDebugInformation = 0x37,
}

impl TableIndex {
    pub const PORTABLE_PDB_FIRST: u8 = 0x30;

    pub fn from_u8(v: u8) -> Option<Self> {
        use TableIndex::*;
        let t = match v {
            0x00 => Module,
            0x01 => TypeRef,
            0x02 => TypeDef,
            0x03 => FieldPtr,
            0x04 => Field,
            0x05 => MethodPtr,
            0x06 => MethodDef,
            0x07 => ParamPtr,
            0x08 => Param,
            0x09 => InterfaceImpl,
            0x0A => MemberRef,
            0x0B => Constant,
            0x0C => CustomAttribute,
            0x0D => FieldMarshal,
            0x0E => DeclSecurity,
            0x0F => ClassLayout,
            0x10 => FieldLayout,
            0x11 => StandAloneSig,
            0x12 => EventMap,
            0x13 => EventPtr,
            0x14 => Event,
            0x15 => PropertyMap,
            0x16 => PropertyPtr,
            0x17 => Property,
            0x18 => MethodSemantics,
            0x19 => MethodImpl,
            0x1A => ModuleRef,
            0x1B => TypeSpec,
            0x1C => ImplMap,
            0x1D => FieldRva,
            0x1E => EncLog,
            0x1F => EncMap,
            0x20 => Assembly,
            0x21 => AssemblyProcessor,
            0x22 => AssemblyOS,
            0x23 => AssemblyRef,
            0x24 => AssemblyRefProcessor,
            0x25 => AssemblyRefOS,
            0x26 => File,
            0x27 => ExportedType,
            0x28 => ManifestResource,
            0x29 => NestedClass,
            0x2A => GenericParam,
            0x2B => MethodSpec,
            0x2C => GenericParamConstraint,
            0x30 => Document,
            0x31 => MethodDebugInformation,
            0x32 => LocalScope,
            0x33 => LocalVariable,
            0x34 => LocalConstant,
            0x35 => ImportScope,
            0x36 => StateMachineMethod,
            0x37 => CustomDebugInformation,
            _ => return None,
        };
        Some(t)
    }

    pub fn name(self) -> &'static str {
        use TableIndex::*;
        match self {
            Module => "Module",
            TypeRef => "TypeRef",
            TypeDef => "TypeDef",
            FieldPtr => "FieldPtr",
            Field => "Field",
            MethodPtr => "MethodPtr",
            MethodDef => "MethodDef",
            ParamPtr => "ParamPtr",
            Param => "Param",
            InterfaceImpl => "InterfaceImpl",
            MemberRef => "MemberRef",
            Constant => "Constant",
            CustomAttribute => "CustomAttribute",
            FieldMarshal => "FieldMarshal",
            DeclSecurity => "DeclSecurity",
            ClassLayout => "ClassLayout",
            FieldLayout => "FieldLayout",
            StandAloneSig => "StandAloneSig",
            EventMap => "EventMap",
            EventPtr => "EventPtr",
            Event => "Event",
            PropertyMap => "PropertyMap",
            PropertyPtr => "PropertyPtr",
            Property => "Property",
            MethodSemantics => "MethodSemantics",
            MethodImpl => "MethodImpl",
            ModuleRef => "ModuleRef",
            TypeSpec => "TypeSpec",
            ImplMap => "ImplMap",
            FieldRva => "FieldRVA",
            EncLog => "EncLog",
            EncMap => "EncMap",
            Assembly => "Assembly",
            AssemblyProcessor => "AssemblyProcessor",
            AssemblyOS => "AssemblyOS",
            AssemblyRef => "AssemblyRef",
            AssemblyRefProcessor => "AssemblyRefProcessor",
            AssemblyRefOS => "AssemblyRefOS",
            File => "File",
            ExportedType => "ExportedType",
            ManifestResource => "ManifestResource",
            NestedClass => "NestedClass",
            GenericParam => "GenericParam",
            MethodSpec => "MethodSpec",
            GenericParamConstraint => "GenericParamConstraint",
            Document => "Document",
            MethodDebugInformation => "MethodDebugInformation",
            LocalScope => "LocalScope",
            LocalVariable => "LocalVariable",
            LocalConstant => "LocalConstant",
            ImportScope => "ImportScope",
            StateMachineMethod => "StateMachineMethod",
            CustomDebugInformation => "CustomDebugInformation",
        }
    }

    pub fn is_portable_pdb_table(byte: u8) -> bool {
        byte >= TableIndex::PORTABLE_PDB_FIRST && byte <= 0x37
    }
}

/// High nibble of a token (`MetadataTokenType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenType {
    Module,
    TypeRef,
    TypeDef,
    Field,
    MethodDef,
    Param,
    InterfaceImpl,
    MemberRef,
    Constant,
    CustomAttribute,
    FieldMarshal,
    DeclSecurity,
    ClassLayout,
    FieldLayout,
    StandAloneSig,
    EventMap,
    Event,
    PropertyMap,
    Property,
    MethodSemantics,
    MethodImpl,
    ModuleRef,
    TypeSpec,
    ImplMap,
    FieldRva,
    Assembly,
    AssemblyProcessor,
    AssemblyOS,
    AssemblyRef,
    AssemblyRefProcessor,
    AssemblyRefOS,
    File,
    ExportedType,
    ManifestResource,
    NestedClass,
    GenericParam,
    MethodSpec,
    GenericParamConstraint,
}

impl TokenType {
    pub fn value(self) -> u32 {
        match self {
            TokenType::Module => 0x0000_0000,
            TokenType::TypeRef => 0x0100_0000,
            TokenType::TypeDef => 0x0200_0000,
            TokenType::Field => 0x0400_0000,
            TokenType::MethodDef => 0x0600_0000,
            TokenType::Param => 0x0800_0000,
            TokenType::InterfaceImpl => 0x0900_0000,
            TokenType::MemberRef => 0x0A00_0000,
            TokenType::Constant => 0x0B00_0000,
            TokenType::CustomAttribute => 0x0C00_0000,
            TokenType::FieldMarshal => 0x0D00_0000,
            TokenType::DeclSecurity => 0x0E00_0000,
            TokenType::ClassLayout => 0x0F00_0000,
            TokenType::FieldLayout => 0x1000_0000,
            TokenType::StandAloneSig => 0x1100_0000,
            TokenType::EventMap => 0x1200_0000,
            TokenType::Event => 0x1400_0000,
            TokenType::PropertyMap => 0x1500_0000,
            TokenType::Property => 0x1700_0000,
            TokenType::MethodSemantics => 0x1800_0000,
            TokenType::MethodImpl => 0x1900_0000,
            TokenType::ModuleRef => 0x1A00_0000,
            TokenType::TypeSpec => 0x1B00_0000,
            TokenType::ImplMap => 0x1C00_0000,
            TokenType::FieldRva => 0x1D00_0000,
            TokenType::Assembly => 0x2000_0000,
            TokenType::AssemblyProcessor => 0x2100_0000,
            TokenType::AssemblyOS => 0x2200_0000,
            TokenType::AssemblyRef => 0x2300_0000,
            TokenType::AssemblyRefProcessor => 0x2400_0000,
            TokenType::AssemblyRefOS => 0x2500_0000,
            TokenType::File => 0x2600_0000,
            TokenType::ExportedType => 0x2700_0000,
            TokenType::ManifestResource => 0x2800_0000,
            TokenType::NestedClass => 0x2900_0000,
            TokenType::GenericParam => 0x2A00_0000,
            TokenType::MethodSpec => 0x2B00_0000,
            TokenType::GenericParamConstraint => 0x2C00_0000,
        }
    }

    pub fn from_value(v: u32) -> Option<Self> {
        Some(match v & 0xFF00_0000 {
            0x0100_0000 => TokenType::TypeRef,
            0x0200_0000 => TokenType::TypeDef,
            0x0400_0000 => TokenType::Field,
            0x0600_0000 => TokenType::MethodDef,
            0x0800_0000 => TokenType::Param,
            0x0900_0000 => TokenType::InterfaceImpl,
            0x0A00_0000 => TokenType::MemberRef,
            0x0B00_0000 => TokenType::Constant,
            0x0C00_0000 => TokenType::CustomAttribute,
            0x0D00_0000 => TokenType::FieldMarshal,
            0x0E00_0000 => TokenType::DeclSecurity,
            0x0F00_0000 => TokenType::ClassLayout,
            0x1000_0000 => TokenType::FieldLayout,
            0x1100_0000 => TokenType::StandAloneSig,
            0x1200_0000 => TokenType::EventMap,
            0x1400_0000 => TokenType::Event,
            0x1500_0000 => TokenType::PropertyMap,
            0x1700_0000 => TokenType::Property,
            0x1800_0000 => TokenType::MethodSemantics,
            0x1900_0000 => TokenType::MethodImpl,
            0x1A00_0000 => TokenType::ModuleRef,
            0x1B00_0000 => TokenType::TypeSpec,
            0x1C00_0000 => TokenType::ImplMap,
            0x1D00_0000 => TokenType::FieldRva,
            0x2000_0000 => TokenType::Assembly,
            0x2100_0000 => TokenType::AssemblyProcessor,
            0x2200_0000 => TokenType::AssemblyOS,
            0x2300_0000 => TokenType::AssemblyRef,
            0x2400_0000 => TokenType::AssemblyRefProcessor,
            0x2500_0000 => TokenType::AssemblyRefOS,
            0x2600_0000 => TokenType::File,
            0x2700_0000 => TokenType::ExportedType,
            0x2800_0000 => TokenType::ManifestResource,
            0x2900_0000 => TokenType::NestedClass,
            0x2A00_0000 => TokenType::GenericParam,
            0x2B00_0000 => TokenType::MethodSpec,
            0x2C00_0000 => TokenType::GenericParamConstraint,
            _ => return None,
        })
    }

    pub fn table(self) -> TableIndex {
        TableIndex::from_u8((self.value() >> 24) as u8).expect("TokenType maps to a table")
    }
}

/// A coded-index group: several tables compressed into one column with tag bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodedIndexGroup {
    pub name: &'static str,
    /// Tables participating, in tag order.
    pub tables: &'static [TableIndex],
    /// Number of low bits used by the tag.
    pub tag_bits: u32,
}

impl CodedIndexGroup {
    pub const fn new(name: &'static str, tables: &'static [TableIndex]) -> Self {
        let bits = match tables.len() {
            1..=2 => 1,
            3..=4 => 2,
            5..=8 => 3,
            9..=16 => 4,
            _ => 5,
        };
        CodedIndexGroup { name, tables, tag_bits: bits }
    }

    /// Number of low bits the encoded row-id must be shifted by.
    pub fn shift_bits(&self) -> u32 {
        self.tag_bits
    }
}

macro_rules! group {
    ($name:expr, $($t:ident),+) => {
        CodedIndexGroup::new($name, &[$(TableIndex::$t),+])
    };
}

/// All coded-index groups defined by ECMA-335 and the Portable PDB spec.
pub mod coded {
    use super::{CodedIndexGroup, TableIndex};

    pub const TYPE_DEF_OR_REF: CodedIndexGroup =
        group!("TypeDefOrRef", TypeDef, TypeRef, TypeSpec);
    pub const HAS_CONSTANT: CodedIndexGroup = group!("HasConstant", Field, Param, Property);
    pub const HAS_CUSTOM_ATTRIBUTE: CodedIndexGroup = group!(
        "HasCustomAttribute", MethodDef, Field, TypeRef, TypeDef, Param, InterfaceImpl,
        MemberRef, Module, DeclSecurity, Property, Event, StandAloneSig,
        ModuleRef, TypeSpec, Assembly, AssemblyRef, File, ExportedType, ManifestResource,
        GenericParam, GenericParamConstraint, MethodSpec
    );
    pub const HAS_FIELD_MARSHAL: CodedIndexGroup = group!("HasFieldMarshal", Field, Param);
    pub const HAS_DECL_SECURITY: CodedIndexGroup =
        group!("HasDeclSecurity", TypeDef, MethodDef, Assembly);
    pub const MEMBER_REF_PARENT: CodedIndexGroup = group!(
        "MemberRefParent", TypeDef, TypeRef, ModuleRef, MethodDef, TypeSpec
    );
    pub const HAS_SEMANTICS: CodedIndexGroup = group!("HasSemantics", Event, Property);
    pub const METHOD_DEF_OR_REF: CodedIndexGroup = group!("MethodDefOrRef", MethodDef, MemberRef);
    pub const MEMBER_FORWARDED: CodedIndexGroup = group!("MemberForwarded", Field, MethodDef);
    pub const IMPLEMENTATION: CodedIndexGroup =
        group!("Implementation", File, AssemblyRef, ExportedType);
    pub const CUSTOM_ATTRIBUTE_TYPE: CodedIndexGroup = CodedIndexGroup::new(
        "CustomAttributeType",
        &[TableIndex::MethodDef, TableIndex::MemberRef],
    );
    pub const RESOLUTION_SCOPE: CodedIndexGroup =
        group!("ResolutionScope", Module, ModuleRef, AssemblyRef, TypeRef);
    pub const TYPE_OR_METHOD_DEF: CodedIndexGroup =
        group!("TypeOrMethodDef", TypeDef, MethodDef);
    // Portable PDB coded indexes.
    pub const HAS_CUSTOM_DEBUG_INFORMATION: CodedIndexGroup = group!(
        "HasCustomDebugInformation", MethodDef, Field, TypeRef, TypeDef, Param, InterfaceImpl,
        MemberRef, Module, DeclSecurity, Property, Event, StandAloneSig, ModuleRef, TypeSpec,
        Assembly, AssemblyRef, File, ExportedType, ManifestResource, GenericParam,
        GenericParamConstraint, MethodSpec, Document, LocalScope, LocalVariable, LocalConstant,
        ImportScope
    );
}
