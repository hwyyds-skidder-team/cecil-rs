//! Module definition: arena-based ownership of every metadata entity.

use std::collections::BTreeMap;

use cecli_pdb::document::Document;
use crate::model::types::*;

use cecli_pdb::portable_reader::{LocalScope, SequencePoint};

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
    /// Debug symbol information attached by the facade reader
    /// (`ReaderParameters::read_symbols`); `None` unless symbols were read.
    pub debug: Option<ModuleDebugInfo>,
    /// Raw `calli` (`StandAloneSig`) signature blobs captured at read time,
    /// keyed by the original table rid; consumed by the IL writer to re-emit
    /// `calli` operands through its own deduplicated signature rows.
    pub sas_blobs: std::collections::BTreeMap<u32, Vec<u8>>,
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
            characteristics: cecli_core::flags::ModuleCharacteristics::DYNAMIC_BASE
                | cecli_core::flags::ModuleCharacteristics::NX_COMPAT
                | cecli_core::flags::ModuleCharacteristics::TERMINAL_SERVER_AWARE
                | cecli_core::flags::ModuleCharacteristics::HIGH_ENTROPY_VA,
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
            debug: None,
            sas_blobs: std::collections::BTreeMap::new(),
        }
    }
}

/// Debug information of one module, gathered from a portable PDB sidecar.
///
/// Port of the symbol state Mono.Cecil keeps on `ModuleDefinition` through its
/// `ISymbolReader` (`Mono.Cecil.Cil/Symbols.cs`): source documents, per-method
/// sequence points and local scopes, keyed by the owning method's 1-based
/// `MethodDef` rid so they survive module roundtrips.
#[derive(Debug, Clone, Default)]
pub struct ModuleDebugInfo {
    /// Every `Document` row in table order.
    pub documents: Vec<Document>,
    /// Sequence points per method rid. Each entry is a `(document index,
    /// points)` pair where the document index is 0-based into [`Self::documents`].
    pub points: BTreeMap<u32, Vec<(u32, Vec<SequencePoint>)>>,
    /// Local scopes per method rid, in table order.
    pub scopes: BTreeMap<u32, Vec<LocalScope>>,
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

// ---------------------------------------------------------------------------
// Navigation and mutation API
// ---------------------------------------------------------------------------

impl Module {
    /// Iterates every type in arena order (= metadata row order).
    pub fn iter_types(&self) -> impl Iterator<Item = (TypeId, &TypeDefinition)> + '_ {
        self.types
            .iter()
            .enumerate()
            .map(|(i, t)| (TypeId(i as u32), t))
    }

    /// Resolves a type handle to its definition (panics on a stale handle,
    /// which cannot arise while the owning `Module` lives).
    pub fn type_def(&self, id: TypeId) -> &TypeDefinition {
        &self.types[id.index()]
    }

    /// Mutable access to one type definition; `None` when out of range.
    pub fn type_mut(&mut self, id: TypeId) -> Option<&mut TypeDefinition> {
        self.types.get_mut(id.index())
    }

    /// Iterates every method in arena order.
    pub fn iter_methods(&self) -> impl Iterator<Item = (MethodId, &MethodDefinition)> + '_ {
        self.methods
            .iter()
            .enumerate()
            .map(|(i, m)| (MethodId(i as u32), m))
    }

    /// Resolves a method handle to its definition.
    pub fn method_def(&self, id: MethodId) -> &MethodDefinition {
        &self.methods[id.index()]
    }

    /// Mutable access to one method definition; `None` when out of range.
    pub fn method_mut(&mut self, id: MethodId) -> Option<&mut MethodDefinition> {
        self.methods.get_mut(id.index())
    }

    /// Iterates every field in arena order.
    pub fn iter_fields(&self) -> impl Iterator<Item = (FieldId, &FieldDefinition)> + '_ {
        self.fields
            .iter()
            .enumerate()
            .map(|(i, f)| (FieldId(i as u32), f))
    }

    /// Resolves a field handle to its definition.
    pub fn field_def(&self, id: FieldId) -> &FieldDefinition {
        &self.fields[id.index()]
    }

    /// Mutable access to one field definition; `None` when out of range.
    pub fn field_mut(&mut self, id: FieldId) -> Option<&mut FieldDefinition> {
        self.fields.get_mut(id.index())
    }

    /// Iterates every property in arena order.
    pub fn iter_properties(&self) -> impl Iterator<Item = (PropertyId, &PropertyDefinition)> + '_ {
        self.properties
            .iter()
            .enumerate()
            .map(|(i, p)| (PropertyId(i as u32), p))
    }

    /// Resolves a property handle to its definition.
    pub fn property_def(&self, id: PropertyId) -> &PropertyDefinition {
        &self.properties[id.index()]
    }

    /// Mutable access to one property definition; `None` when out of range.
    pub fn property_mut(&mut self, id: PropertyId) -> Option<&mut PropertyDefinition> {
        self.properties.get_mut(id.index())
    }

    /// Iterates every event in arena order.
    pub fn iter_events(&self) -> impl Iterator<Item = (EventId, &EventDefinition)> + '_ {
        self.events
            .iter()
            .enumerate()
            .map(|(i, e)| (EventId(i as u32), e))
    }

    /// Resolves an event handle to its definition.
    pub fn event_def(&self, id: EventId) -> &EventDefinition {
        &self.events[id.index()]
    }

    /// Mutable access to one event definition; `None` when out of range.
    pub fn event_mut(&mut self, id: EventId) -> Option<&mut EventDefinition> {
        self.events.get_mut(id.index())
    }

    /// Iterates every generic parameter in arena order.
    pub fn iter_generic_parameters(
        &self,
    ) -> impl Iterator<Item = (GenericParamId, &GenericParameter)> + '_ {
        self.generic_parameters
            .iter()
            .enumerate()
            .map(|(i, g)| (GenericParamId(i as u32), g))
    }

    /// Resolves a generic-parameter handle to its definition.
    pub fn generic_parameter_def(&self, id: GenericParamId) -> &GenericParameter {
        &self.generic_parameters[id.index()]
    }

    /// Mutable access to one generic parameter; `None` when out of range.
    pub fn generic_parameter_mut(&mut self, id: GenericParamId) -> Option<&mut GenericParameter> {
        self.generic_parameters.get_mut(id.index())
    }

    /// Finds a *top-level* type by namespace and simple name
    /// (port of `ModuleDefinition.GetType(string, string)`).
    pub fn get_type(&self, ns: &str, name: &str) -> Option<&TypeDefinition> {
        self.types.iter().find(|t| {
            t.declaring_type.is_none() && t.namespace == ns && t.name == name
        })
    }

    /// Like [`Module::get_type`] but returns the handle instead.
    pub fn get_type_id(&self, ns: &str, name: &str) -> Option<TypeId> {
        self.types
            .iter()
            .position(|t| t.declaring_type.is_none() && t.namespace == ns && t.name == name)
            .map(|i| TypeId(i as u32))
    }

    /// Resolves a fully qualified type name to its handle, walking the
    /// nesting chain. Accepts `Namespace.Name`, `Namespace.Outer/Nested`
    /// and `Namespace.Outer+Nested` spellings (`None` when no such type).
    pub fn find_type_full(&self, full: &str) -> Option<TypeId> {
        // Split into nesting levels; the head segment still carries the
        // namespace prefix ("Ns.Outer", tail segments are plain names).
        let mut parts = full.split(['/', '+']);
        let head = parts.next()?;
        // A head without a dot is a global-namespace type; `rfind` alone
        // would short-circuit the whole lookup to None.
        let (ns, name) = match head.rfind('.') {
            Some(dot) => (&head[..dot], &head[dot + 1..]),
            None => ("", head),
        };

        let mut current =
            self.types
                .iter()
                .position(|t| t.declaring_type.is_none() && t.namespace == ns && t.name == name)?;
        for part in parts {
            let parent = &self.types[current];
            let child = parent
                .nested_types
                .iter()
                .copied()
                .find(|id| self.types[id.index()].name == part)?;
            current = child.index();
        }
        Some(TypeId(current as u32))
    }

    /// Every type handle, depth-first: each type followed by its nested
    /// types (recursively), roots in arena order.
    pub fn all_types(&self) -> Vec<TypeId> {
        fn walk(m: &Module, ids: &[TypeId], out: &mut Vec<TypeId>) {
            for id in ids {
                out.push(*id);
                let nested = m.types[id.index()].nested_types.clone();
                walk(m, &nested, out);
            }
        }
        let roots: Vec<TypeId> = self
            .types
            .iter()
            .enumerate()
            .filter(|(_, t)| t.declaring_type.is_none())
            .map(|(i, _)| TypeId(i as u32))
            .collect();
        let mut out = Vec::with_capacity(self.types.len());
        walk(self, &roots, &mut out);
        out
    }

    /// Appends a type to the arena. When the definition carries a declaring
    /// type, the new handle is wired into the parent's `nested_types`.
    pub fn add_type(&mut self, mut t: TypeDefinition) -> TypeId {
        let parent = t.declaring_type;
        let id = TypeId(self.types.len() as u32);
        if let Some(p) = parent {
            if p.index() < self.types.len() {
                self.types[p.index()].nested_types.push(id);
            } else {
                // Dangling parent reference: drop it rather than corrupting
                // the nesting tree.
                t.declaring_type = None;
            }
        }
        self.types.push(t);
        id
    }

    /// Appends a method to the arena and registers it on `owner`.
    pub fn add_method(&mut self, owner: TypeId, mut m: MethodDefinition) -> MethodId {
        m.declaring_type = owner;
        let id = MethodId(self.methods.len() as u32);
        self.methods.push(m);
        self.type_mut(owner).map(|t| t.methods.push(id));
        id
    }

    /// Appends a field to the arena and registers it on `owner`.
    pub fn add_field(&mut self, owner: TypeId, f: FieldDefinition) -> FieldId {
        let id = FieldId(self.fields.len() as u32);
        self.fields.push(f);
        self.type_mut(owner).map(|t| t.fields.push(id));
        id
    }

    /// Appends a property to the arena and registers it on `owner`.
    pub fn add_property(&mut self, owner: TypeId, p: PropertyDefinition) -> PropertyId {
        let id = PropertyId(self.properties.len() as u32);
        self.properties.push(p);
        self.type_mut(owner).map(|t| t.properties.push(id));
        id
    }

    /// Appends an event to the arena and registers it on `owner`.
    pub fn add_event(&mut self, owner: TypeId, e: EventDefinition) -> EventId {
        let id = EventId(self.events.len() as u32);
        self.events.push(e);
        self.type_mut(owner).map(|t| t.events.push(id));
        id
    }

    /// Appends a generic parameter to the arena and registers it on its
    /// owner (a type or a method, per [`GenericParameter::owner`]).
    pub fn add_generic_parameter(&mut self, g: GenericParameter) -> GenericParamId {
        let owner = g.owner;
        let id = GenericParamId(self.generic_parameters.len() as u32);
        self.generic_parameters.push(g);
        match owner {
            GenericOwner::Type(t) => {
                self.type_mut(t).map(|ty| ty.generic_parameters.push(id));
            }
            GenericOwner::Method(m) => {
                self.method_mut(m).map(|me| me.generic_parameters.push(id));
            }
        }
        id
    }

    /// Full name of a type: `Namespace.Name` with nesting levels separated
    /// by `/` (Mono.Cecil's `FullName` spelling).
    pub fn type_full_name(&self, id: TypeId) -> String {
        let mut chain = Vec::new();
        let mut cur = Some(id);
        while let Some(cid) = cur {
            let t = self.type_def(cid);
            chain.push(t.name.as_str());
            cur = t.declaring_type;
        }
        chain.reverse();
        let root_ns = self.type_def(id).namespace.clone();
        let mut s = String::new();
        if !root_ns.is_empty() {
            s.push_str(&root_ns);
            s.push('.');
        }
        s.push_str(&chain.join("/"));
        s
    }

    /// Renders a method as `Ns.Type::Name` (nested levels joined by `/`),
    /// e.g. `System.Console::WriteLine`.
    pub fn method_name_chain(&self, id: MethodId) -> String {
        let m = self.method_def(id);
        format!("{}::{}", self.type_full_name(m.declaring_type), m.name)
    }
}

impl std::fmt::Display for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Module {} ({} types, {} methods, {} fields, {} properties, {} events)",
            if self.name.is_empty() { "<unnamed>" } else { &self.name },
            self.types.len(),
            self.methods.len(),
            self.fields.len(),
            self.properties.len(),
            self.events.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::*;

    fn named_type(ns: &str, name: &str, declaring: Option<TypeId>) -> TypeDefinition {
        let mut t = TypeDefinition::default();
        t.namespace = ns.into();
        t.name = name.into();
        t.declaring_type = declaring;
        t
    }

    fn sample_module() -> Module {
        let mut m = Module::default();
        let outer = m.add_type(named_type("Ns", "Outer", None));
        let _inner = m.add_type(named_type("Ns", "Inner", Some(outer)));
        let _other = m.add_type(named_type("Other", "Thing", None));
        m
    }

    #[test]
    fn add_type_wires_nesting() {
        let m = sample_module();
        let outer = m.get_type_id("Ns", "Outer").unwrap();
        let inner = m.find_type_full("Ns.Outer+Inner").unwrap();
        assert_eq!(m.type_def(inner).declaring_type, Some(outer));
        assert_eq!(m.type_def(outer).nested_types, vec![inner]);
        // get_type only matches top-level types.
        assert!(m.get_type("Ns", "Inner").is_none());
        assert!(m.get_type("Ns", "Outer").is_some());
    }

    #[test]
    fn find_type_full_walks_nesting() {
        let m = sample_module();
        let inner = m.find_type_full("Ns.Outer+Inner").expect("+ spelling");
        assert_eq!(m.find_type_full("Ns.Outer/Inner"), Some(inner), "/ spelling");
        assert_eq!(m.find_type_full("Ns.Outer"), m.get_type_id("Ns", "Outer"));
        assert!(m.find_type_full("Ns.Missing").is_none());
        assert!(m.find_type_full("Ns.Outer.Wrong").is_none());
    }

    #[test]
    fn all_types_is_depth_first() {
        let m = sample_module();
        let ids = m.all_types();
        assert_eq!(ids.len(), 3);
        // Outer first (arena order), immediately followed by its nested Inner.
        assert_eq!(m.type_def(ids[0]).name, "Outer");
        assert_eq!(m.type_def(ids[1]).name, "Inner");
        assert_eq!(m.type_def(ids[2]).name, "Thing");
    }

    #[test]
    fn add_method_field_property_event_wire_into_owner() {
        let mut m = sample_module();
        let outer = m.get_type_id("Ns", "Outer").unwrap();

        let mut meth = MethodDefinition::default();
        meth.name = "Do".into();
        // A stale declaring type gets overwritten by add_method.
        meth.declaring_type = TypeId(99);
        let mid = m.add_method(outer, meth);
        assert_eq!(m.method_def(mid).name, "Do");
        assert_eq!(m.method_def(mid).declaring_type, outer);
        assert_eq!(m.type_def(outer).methods, vec![mid]);

        let fid = m.add_field(outer, FieldDefinition::default());
        assert_eq!(m.type_def(outer).fields, vec![fid]);
        assert_eq!(m.field_def(fid).signature.0, TypeDesc::Sentinel);

        let pid = m.add_property(outer, PropertyDefinition::default());
        assert_eq!(m.type_def(outer).properties, vec![pid]);

        let eid = m.add_event(outer, EventDefinition::default());
        assert_eq!(m.type_def(outer).events, vec![eid]);

        // Mutating through the handle is visible in the arena.
        m.method_mut(mid).unwrap().name = "Did".into();
        assert_eq!(m.method_def(mid).name, "Did");
        assert!(m.method_mut(MethodId(999)).is_none());
    }

    #[test]
    fn generic_parameters_register_on_their_owner() {
        let mut m = Module::default();
        let ty = {
            let mut t = TypeDefinition::default();
            t.name = "Box".into();
            m.add_type(t)
        };
        let mut gp_t = GenericParameter::default();
        gp_t.name = "T".into();
        gp_t.owner = GenericOwner::Type(ty);
        let gid = m.add_generic_parameter(gp_t);
        assert_eq!(m.type_def(ty).generic_parameters, vec![gid]);

        let mut meth = MethodDefinition::default();
        meth.name = "Get".into();
        let mid = m.add_method(ty, meth);
        let mut gp_m = GenericParameter::default();
        gp_m.name = "R".into();
        gp_m.owner = GenericOwner::Method(mid);
        let gid2 = m.add_generic_parameter(gp_m);
        assert_eq!(m.method_def(mid).generic_parameters, vec![gid2]);
        assert_eq!(m.generic_parameter_def(gid2).owner, GenericOwner::Method(mid));
    }

    #[test]
    fn method_name_chain_and_display() {
        let mut m = Module::default();
        let outer = m.add_type(named_type("Ns", "Outer", None));
        let inner = m.add_type(named_type("Ns", "Inner", Some(outer)));
        let mut meth = MethodDefinition::default();
        meth.name = "Bar".into();
        let mid = m.add_method(inner, meth);
        assert_eq!(m.method_name_chain(mid), "Ns.Outer/Inner::Bar");

        let top = m.add_type(named_type("Sys", "Console", None));
        let mut w = MethodDefinition::default();
        w.name = "WriteLine".into();
        let wid = m.add_method(top, w);
        assert_eq!(m.method_name_chain(wid), "Sys.Console::WriteLine");

        let displayed = format!("{}", m);
        assert!(displayed.contains("Module <unnamed>"));
        assert!(displayed.contains("3 types"));
        assert!(displayed.contains("2 methods"));
    }
}
