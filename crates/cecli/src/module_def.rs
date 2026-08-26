//! Module definition: arena-based ownership of every metadata entity.

use crate::model::types::*;

use cecli_core::flags::TypeAttributes;
#[derive(Debug, Clone)]
pub struct Module {
    /// Simple name from the `Module` row.
    pub name: String,
    /// Module version id (`MVID` guid).
    pub guid: [u8; 16],
    pub kind: cecli_core::flags::ModuleKind,
    pub runtime: cecli_core::flags::TargetRuntime,
    pub architecture: cecli_core::flags::TargetArchitecture,
    pub attributes: cecli_core::flags::ModuleAttributes,
    pub characteristics: cecli_core::flags::ModuleCharacteristics,
    pub metadata_kind: cecli_core::flags::MetadataKind,
    /// Runtime version string as found in metadata (`v4.0.30319`).
    pub runtime_version: String,

    // Arenas. Indices are the handle values.
    pub types: Vec<TypeDefinition>,
    pub methods: Vec<MethodDefinition>,
    pub fields: Vec<FieldDefinition>,
    pub properties: Vec<PropertyDefinition>,
    pub events: Vec<EventDefinition>,
    pub generic_parameters: Vec<GenericParameter>,

    /// Referenced assemblies in `AssemblyRef` order.
    pub assembly_refs: Vec<AssemblyNameReference>,
    /// `ModuleRef` names (native modules for P/Invoke).
    pub module_refs: Vec<String>,
    /// Manifest resources.
    pub resources: Vec<Resource>,
    /// Raw rows preserved for multi-module assemblies (`File` table).
    pub file_rows: Vec<FileRow>,
    /// `ExportedType` rows (types forwarded from or declared in other modules).
    pub exported_types: Vec<ExportedTypeRow>,

    /// Entry point token recorded at read time (facade resolves to MethodId).
    pub entry_point_token: cecli_core::Token,
}

impl Default for Module {
    fn default() -> Self {
        Module {
            name: String::new(),
            guid: [0; 16],
            kind: cecli_core::flags::ModuleKind::Dll,
            runtime: cecli_core::flags::TargetRuntime::Net40,
            architecture: cecli_core::flags::TargetArchitecture::I386,
            attributes: cecli_core::flags::ModuleAttributes::empty(),
            characteristics: cecli_core::flags::ModuleCharacteristics::empty(),
            metadata_kind: cecli_core::flags::MetadataKind::Ecma335,
            runtime_version: String::new(),
            types: Vec::new(),
            methods: Vec::new(),
            fields: Vec::new(),
            properties: Vec::new(),
            events: Vec::new(),
            generic_parameters: Vec::new(),
            assembly_refs: Vec::new(),
            module_refs: Vec::new(),
            resources: Vec::new(),
            file_rows: Vec::new(),
            exported_types: Vec::new(),
            entry_point_token: cecli_core::Token::NIL,
        }
    }
}

/// A manifest resource.
#[derive(Debug, Clone)]
pub enum Resource {
    Embedded {
        name: String,
        attributes: cecli_core::flags::ManifestResourceAttributes,
        data: Vec<u8>,
    },
    Linked {
        name: String,
        attributes: cecli_core::flags::ManifestResourceAttributes,
        /// File row name containing the payload.
        file: String,
    },
    AssemblyLinked {
        name: String,
        attributes: cecli_core::flags::ManifestResourceAttributes,
        assembly: AssemblyNameReference,
    },
}

impl Resource {
    pub fn name(&self) -> &str {
        match self {
            Resource::Embedded { name, .. }
            | Resource::Linked { name, .. }
            | Resource::AssemblyLinked { name, .. } => name,
        }
    }

    pub fn attributes(&self) -> cecli_core::flags::ManifestResourceAttributes {
        match self {
            Resource::Embedded { attributes, .. }
            | Resource::Linked { attributes, .. }
            | Resource::AssemblyLinked { attributes, .. } => *attributes,
        }
    }
}

/// `File` table row for multi-module assemblies.
#[derive(Debug, Clone)]
pub struct FileRow {
    pub name: String,
    pub attributes: cecli_core::flags::FileRowAttributes,
    pub hash: Vec<u8>,
}

/// `ExportedType` table row.
#[derive(Debug, Clone)]
pub struct ExportedTypeRow {
    pub namespace: String,
    pub name: String,
    pub attributes: TypeAttributes,
    /// Implementation: file name, assembly ref index, or exported-type nesting parent.
    pub implementation: ExportedImpl,
    /// TypeDef rid within the implementing module (0 when unknown).
    pub type_def_id: u32,
}

/// Implementation target of an exported type.
#[derive(Debug, Clone)]
pub enum ExportedImpl {
    /// Index into `file_rows`.
    File(usize),
    /// Index into `assembly_refs`.
    AssemblyRef(usize),
    /// Nested inside another exported type (rid).
    ExportedType(u32),
}
