//! Resolution engine: the Rust port of `Mono.Cecil/MetadataResolver.cs`.
//!
//! [`ResolutionEngine`] turns the model-level references ([`TypeDesc`],
//! [`MethodRef`], [`FieldRef`]) into concrete arena handles, either inside the
//! primary [`Module`] or inside referenced assemblies that are read on demand
//! through an [`AssemblyBytesLoader`] and cached as parsed [`Module`]s.
//!
//! Matching rules are ported verbatim from `MetadataResolver.cs`:
//! - methods match on name, generic-parameter arity, return type, `has_this`,
//!   calling convention/vararg shape and parameter types (`GetMethod`);
//! - fields match on name plus field-type identity (`GetField`);
//! - member searches walk the base-type chain of the declaring type;
//! - types match on namespace, simple name and nesting chain
//!   (`GetTypeDefinition`, incl. the `ExportedType` fallback of `GetType`).
//!
//! Value-type classification (`is_value_type`) ports
//! `TypeDefinition.IsValueType`: the base-type chain is walked until a
//! `System.ValueType` / `System.Enum` sentinel (value type), `System.Object`
//! or an interface definition (reference type) is reached. An external type
//! that cannot be resolved is an error, mirroring Cecil throwing
//! `NotSupportedException` / `ResolutionException` instead of silently
//! answering `false`.

use std::borrow::Cow;

use cecli_core::flags::SignatureCallingConvention;
use cecli_core::flags::TypeAttributes;
use cecli_core::{Error, Result};

use crate::model::types::{
    ExternalField, ExternalMethod, ExternalType, FieldRef, MethodRef, MethodSignature, TypeDesc,
};
use crate::module_def::Module;

/// Supplies raw image bytes for a referenced assembly on demand.
///
/// The engine hands the exact [`crate::model::types::AssemblyNameReference`]
/// row found in the referencing module to [`AssemblyBytesLoader::load`]; the
/// implementation decides how to locate the image (search directories, an
/// in-memory registry, a network store, ...). Returning `Ok(None)` means
/// "assembly not available"; parse results are cached by the engine, so
/// `load` is invoked at most once per distinct reference.
pub trait AssemblyBytesLoader {
    /// Returns the raw PE/CLI image bytes for `reference`, if available.
    fn load(
        &mut self,
        reference: &crate::model::types::AssemblyNameReference,
    ) -> Result<Option<Cow<'_, [u8]>>>;
}

/// A successfully resolved type: the module holding it plus the arena handle.
///
/// `module_index` indexes the engine's module space: `0` is the primary module
/// passed to [`ResolutionEngine::new`], and `i > 0` refers to
/// [`ResolutionEngine::loaded_modules`][`i - 1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedType {
    /// Module space index (`0` = primary module).
    pub module_index: usize,
    /// Handle of the resolved type inside that module's type arena.
    pub id: crate::model::types::TypeId,
}

/// Resolves type/method/field references against the primary module and
/// lazily-loaded referenced assemblies.
///
/// Port of `Mono.Cecil.MetadataResolver`.
pub struct ResolutionEngine<'a> {
    primary: &'a Module,
    /// Parsed referenced assemblies, in load order. `cache[i]` corresponds to
    /// module-space index `i + 1`.
    cache: Vec<Module>,
    /// The assembly reference each cached module was loaded for (parallel to
    /// `cache`), used to identify cached modules without re-parsing.
    cache_refs: Vec<crate::model::types::AssemblyNameReference>,
    loader: Option<Box<dyn AssemblyBytesLoader + 'a>>,
}

impl<'a> ResolutionEngine<'a> {
    /// Creates an engine that only ever resolves inside `primary`; external
    /// scopes stay unresolved.
    pub fn new(primary: &'a Module) -> Self {
        ResolutionEngine { primary, cache: Vec::new(), cache_refs: Vec::new(), loader: None }
    }

    /// Creates an engine that reads referenced assemblies through `loader`
    /// (via [`crate::assembly::AssemblyDefinition::read`]) and caches them.
    pub fn with_loader(loader: Box<dyn AssemblyBytesLoader + 'a>) -> Self {
        ResolutionEngine {
            primary: dead_primary(),
            cache: Vec::new(),
            cache_refs: Vec::new(),
            loader: Some(loader),
        }
    }

    /// Every module loaded through the loader so far, in load order.
    ///
    /// Module-space index of `loaded_modules()[i]` is `i + 1`.
    pub fn loaded_modules(&self) -> &[Module] {
        &self.cache
    }

    /// Resolves a type descriptor to its defining arena entry.
    ///
    /// Signature modifiers, arrays, pointers, by-refs and generic
    /// instantiations are stripped down to their element type first (the port
    /// of `TypeReference.GetElementType`). Unresolvable references yield
    /// `Ok(None)`.
    pub fn resolve_type(&mut self, ty: &TypeDesc) -> Result<Option<ResolvedType>> {
        let element = element_type(ty);
        match element {
            TypeDesc::Def(id) => {
                // Out-of-range handles only arise for the placeholder primary
                // module of `with_loader` engines; treat them as unresolvable
                // rather than panicking.
                if id.index() < self.primary.types.len() {
                    Ok(Some(ResolvedType { module_index: 0, id: *id }))
                } else {
                    Ok(None)
                }
            }
            TypeDesc::External(ext) => self.resolve_external(ext),
            // Var/MVar/FnPtr/Sentinel/TypedByRef/Internal have no definition
            // to resolve to.
            _ => Ok(None),
        }
    }

    /// Resolves a method reference to `(module_index, MethodId)`.
    ///
    /// `Spec` instantiations are collapsed onto their element method (the
    /// port of `MethodReference.GetElementMethod`); the search then walks the
    /// declaring type's base chain like `MetadataResolver.GetMethod`.
    pub fn resolve_method(
        &mut self,
        r: &MethodRef,
    ) -> Result<Option<(usize, crate::model::types::MethodId)>> {
        match r {
            MethodRef::Def(id) => Ok(Some((0, *id))),
            // GetElementMethod: collapse Spec onto its element method.
            MethodRef::Spec { method, .. } => self.resolve_method(method),
            MethodRef::External(ext) => {
                let Some(rt) = self.resolve_type(&ext.parent)? else {
                    return Ok(None);
                };
                self.walk_methods(rt.module_index, rt.id, ext)
            }
        }
    }

    /// Resolves a field reference to `(module_index, FieldId)` walking the
    /// declaring type's base chain like `MetadataResolver.GetField`.
    pub fn resolve_field(
        &mut self,
        r: &FieldRef,
    ) -> Result<Option<(usize, crate::model::types::FieldId)>> {
        let FieldRef::External(ext) = r else {
            return match r {
                FieldRef::Def(id) => Ok(Some((0, *id))),
                _ => Ok(None),
            };
        };
        let Some(rt) = self.resolve_type(&ext.parent)? else {
            return Ok(None);
        };
        self.walk_fields(rt.module_index, rt.id, ext)
    }

    /// Authoritative value-type classification.
    ///
    /// Walks the base-type chain of the (resolved) definition until a
    /// `System.ValueType` / `System.Enum` sentinel (`true`), `System.Object`
    /// or an interface definition (`false`) is reached. A reference that
    /// cannot be resolved (unknown external scope, missing loader, loader
    /// miss) yields `Err(Error::unsupported(..))`, mirroring Cecil throwing
    /// instead of guessing.
    pub fn is_value_type(&mut self, ty: &TypeDesc) -> Result<bool> {
        let element = element_type(ty);
        match element {
            TypeDesc::Def(id) => {
                if id.index() < self.primary.types.len() {
                    self.is_value_type_def(0, *id)
                } else {
                    Ok(false)
                }
            }
            TypeDesc::External(ext) => match self.resolve_external(ext)? {
                Some(rt) => self.is_value_type_def(rt.module_index, rt.id),
                None => Err(Error::unsupported(format!(
                    "could not resolve type {}",
                    ext_full_name(ext)
                ))),
            },
            // Generic parameters, function pointers and the exotic forms carry
            // no value-type semantics of their own.
            _ => Ok(false),
        }
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    fn module_at(&self, index: usize) -> &Module {
        if index == 0 {
            self.primary
        } else {
            &self.cache[index - 1]
        }
    }

    /// Locates an external type in the primary module, a cached module, or a
    /// module loaded on demand for its scope assembly.
    fn resolve_external(&mut self, ext: &ExternalType) -> Result<Option<ResolvedType>> {
        match &ext.scope {
            crate::model::types::ScopeRef::ThisModule => {
                Ok(find_external_in_module(self.primary, ext)
                    .map(|id| ResolvedType { module_index: 0, id }))
            }
            crate::model::types::ScopeRef::OtherModule(name) => {
                // Netmodules of the current assembly: matched against already
                // loaded/cached modules by module name (Cecil looks the name
                // up in `AssemblyDefinition.Modules`).
                for i in 0..self.cache.len() {
                    if self.cache[i].name == *name {
                        if let Some(id) = find_external_in_module(&self.cache[i], ext) {
                            return Ok(Some(ResolvedType { module_index: i + 1, id }));
                        }
                    }
                }
                Ok(None)
            }
            crate::model::types::ScopeRef::Assembly(anr) => {
                let Some(index) = self.ensure_loaded(anr)? else {
                    return Ok(None);
                };
                Ok(find_external_in_module(self.module_at(index), ext)
                    .map(|id| ResolvedType { module_index: index, id }))
            }
            crate::model::types::ScopeRef::Moduleless => {
                // Exported-type edge case: probe every known module.
                if let Some(id) = find_external_in_module(self.primary, ext) {
                    return Ok(Some(ResolvedType { module_index: 0, id }));
                }
                for i in 0..self.cache.len() {
                    if let Some(id) = find_external_in_module(&self.cache[i], ext) {
                        return Ok(Some(ResolvedType { module_index: i + 1, id }));
                    }
                }
                Ok(None)
            }
        }
    }

    /// Returns the module-space index of the module loaded for `anr`, reading
    /// and caching it through the loader when necessary.
    ///
    /// Cached candidates with the same simple name are disambiguated by
    /// version: the highest version satisfying the request wins, falling back
    /// to the highest version overall. Without a loader (or on a loader miss)
    /// this returns `Ok(None)`.
    fn ensure_loaded(
        &mut self,
        anr: &crate::model::types::AssemblyNameReference,
    ) -> Result<Option<usize>> {
        let mut best: Option<usize> = None;
        for (i, cached) in self.cache_refs.iter().enumerate() {
            if cached.name != anr.name {
                continue;
            }
            best = Some(match best {
                None => i,
                Some(b) => {
                    if prefer_version(cached, &self.cache_refs[b], anr) {
                        i
                    } else {
                        b
                    }
                }
            });
        }
        if best.is_some() {
            return Ok(best.map(|i| i + 1));
        }

        let Some(loader) = self.loader.as_mut() else {
            return Ok(None);
        };
        let Some(bytes) = loader.load(anr)? else {
            return Ok(None);
        };
        let assembly = crate::assembly::AssemblyDefinition::read(&bytes)?;
        // Only the main module is cached; satellites are reachable through a
        // later OtherModule-scope load of their own image.
        self.cache_refs.push(anr.clone());
        self.cache.push(assembly.main);
        Ok(Some(self.cache.len()))
    }

    /// Resolves a type descriptor that lives *inside* the module at
    /// `context_index` (a base type, interface, or constraint of one of its
    /// definitions). Bare `Def` handles are interpreted in the context module
    /// first, falling back to the primary; external scopes go through the
    /// loader as usual.
    fn resolve_in_context(
        &mut self,
        context_index: usize,
        ty: &TypeDesc,
    ) -> Result<Option<ResolvedType>> {
        let element = element_type(ty);
        match element {
            TypeDesc::Def(id) => {
                if id.index() < self.module_at(context_index).types.len() {
                    return Ok(Some(ResolvedType { module_index: context_index, id: *id }));
                }
                if context_index != 0 && id.index() < self.primary.types.len() {
                    return Ok(Some(ResolvedType { module_index: 0, id: *id }));
                }
                Ok(None)
            }
            TypeDesc::External(ext) => self.resolve_external(ext),
            _ => Ok(None),
        }
    }

    /// `MetadataResolver.GetMethod` over the base-type chain.
    fn walk_methods(
        &mut self,
        start_index: usize,
        start: crate::model::types::TypeId,
        reference: &ExternalMethod,
    ) -> Result<Option<(usize, crate::model::types::MethodId)>> {
        let mut index = start_index;
        let mut current = start;
        loop {
            let module = self.module_at(index);
            let def = module.type_def(current);

            let found = def.methods.iter().copied().find(|mid| {
                let m = module.method_def(*mid);
                method_matches(module, m, self.primary, &reference.name, &reference.signature)
            });
            if let Some(mid) = found {
                return Ok(Some((index, mid)));
            }

            let Some(base) = def.base_type.clone() else {
                return Ok(None);
            };
            let Some(rt) = self.resolve_in_context(index, &base)? else {
                return Ok(None);
            };
            index = rt.module_index;
            current = rt.id;
        }
    }

    /// `MetadataResolver.GetField` over the base-type chain.
    fn walk_fields(
        &mut self,
        start_index: usize,
        start: crate::model::types::TypeId,
        reference: &ExternalField,
    ) -> Result<Option<(usize, crate::model::types::FieldId)>> {
        let mut index = start_index;
        let mut current = start;
        loop {
            let module = self.module_at(index);
            let def = module.type_def(current);

            let found = def.fields.iter().copied().find(|fid| {
                let f = module.field_def(*fid);
                f.name == reference.name
                    && are_same(module, &f.signature.0, self.primary, &reference.signature.0)
            });
            if let Some(fid) = found {
                return Ok(Some((index, fid)));
            }

            let Some(base) = def.base_type.clone() else {
                return Ok(None);
            };
            let Some(rt) = self.resolve_in_context(index, &base)? else {
                return Ok(None);
            };
            index = rt.module_index;
            current = rt.id;
        }
    }

    /// `TypeDefinition.IsValueType` generalized into a base-chain walk.
    fn is_value_type_def(&mut self, index: usize, id: crate::model::types::TypeId) -> Result<bool> {
        let def = self.module_at(index).type_def(id);
        // Interfaces are reference types regardless of any (absent) base row.
        if def.attributes.contains(TypeAttributes::INTERFACE) {
            return Ok(false);
        }
        let Some(base) = def.base_type.clone() else {
            return Ok(false);
        };

        // Sentinel check on the spelled-out full name first: this classifies
        // every direct child of ValueType/Enum/Object without touching the
        // loader (Cecil's `IsTypeOf` string comparison).
        if let Some(name) = base_external_full_name(&base) {
            if name == "System.Enum" || name == "System.ValueType" {
                return Ok(true);
            }
            if name == "System.Object" {
                return Ok(false);
            }
        }

        match &base {
            // A generic parameter as base type carries no value-type fact.
            TypeDesc::Var(_) | TypeDesc::MVar(_) => Ok(false),
            _ => {
                let Some(rt) = self.resolve_in_context(index, &base)? else {
                    return Err(Error::unsupported(format!(
                        "could not resolve type {}",
                        type_display(&base, self.module_at(index))
                    )));
                };
                // Same sentinels, checked against the resolved definition:
                // internal `Def` base links carry no external spelling, so
                // the identity test must happen on the definition itself.
                let base_def = self.module_at(rt.module_index).type_def(rt.id);
                if base_def.namespace == "System" {
                    match base_def.name.as_str() {
                        "ValueType" | "Enum" => return Ok(true),
                        "Object" => return Ok(false),
                        _ => {}
                    }
                }
                self.is_value_type_def(rt.module_index, rt.id)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Type lookup helpers
// ---------------------------------------------------------------------------

/// Strips arrays, pointers, by-refs, pinned, custom modifiers and generic
/// instantiations down to the underlying element type
/// (`TypeReference.GetElementType`).
fn element_type(ty: &TypeDesc) -> &TypeDesc {
    let mut current = ty;
    loop {
        match current {
            TypeDesc::SzArray(inner)
            | TypeDesc::Ptr(inner)
            | TypeDesc::ByRef(inner)
            | TypeDesc::Pinned(inner) => current = inner,
            TypeDesc::Array { element, .. } => current = element,
            TypeDesc::CMod { unmodified, .. } => current = unmodified,
            TypeDesc::GenericInstance { definition, .. } => current = definition,
            _ => return current,
        }
    }
}

/// Full name of an external type: `Namespace.Outer/Inner` (Mono.Cecil
/// spelling with `/` nesting separators).
fn ext_full_name(ext: &ExternalType) -> String {
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
/// Placeholder primary module for engines built with
/// [`ResolutionEngine::with_loader`]; such engines resolve exclusively in
/// modules read through their loader.
static DEAD_PRIMARY: std::sync::LazyLock<Module> = std::sync::LazyLock::new(Module::default);

fn dead_primary() -> &'static Module {
    &DEAD_PRIMARY
}

/// Full name of a base-type reference when it is spelled externally
/// (`None` for `Def` and non-nominal forms).
fn base_external_full_name(ty: &TypeDesc) -> Option<String> {
    match element_type(ty) {
        TypeDesc::External(ext) => Some(ext_full_name(ext)),
        _ => None,
    }
}

/// Human-readable name of any nominal type reference (error messages).
fn type_display(ty: &TypeDesc, module: &Module) -> String {
    match element_type(ty) {
        TypeDesc::Def(id) => module.type_full_name(*id),
        TypeDesc::External(ext) => ext_full_name(ext),
        other => format!("{other:?}"),
    }
}

/// Finds a top-level-or-nested external type inside `module` by walking the
/// nesting chain (`GetTypeDefinition`).
///
/// Falls back to the module's `ExportedType` rows for top-level names,
/// following `AssemblyRef` implementations (port of `MetadataResolver.GetType`).
fn find_external_in_module(
    module: &Module,
    ext: &ExternalType,
) -> Option<crate::model::types::TypeId> {
    // Outermost-first chain ending with `ext` itself.
    let mut chain: Vec<&ExternalType> = ext.nesting.iter().map(|b| &**b).collect();
    chain.push(ext);

    let root = chain[0];
    let mut current = module.get_type_id(&root.namespace, &root.name)?;

    for step in &chain[1..] {
        let parent = module.type_def(current);
        // Nested rows repeat the namespace in some producers; match on the
        // simple name like `TypeDefinition.GetNestedType`.
        current = parent
            .nested_types
            .iter()
            .copied()
            .find(|id| module.type_def(*id).name == step.name)?;
    }
    Some(current)
}

/// Picks the cached reference that better satisfies the request: versions
/// greater or equal win over lower ones, higher versions win otherwise.
fn prefer_version(
    candidate: &crate::model::types::AssemblyNameReference,
    incumbent: &crate::model::types::AssemblyNameReference,
    request: &crate::model::types::AssemblyNameReference,
) -> bool {
    let c_satisfies = candidate.version >= request.version;
    let i_satisfies = incumbent.version >= request.version;
    match (c_satisfies, i_satisfies) {
        (true, false) => true,
        (false, true) => false,
        _ => candidate.version > incumbent.version,
    }
}

// ---------------------------------------------------------------------------
// Member matching (port of MetadataResolver.AreSame family)
// ---------------------------------------------------------------------------

/// `MetadataResolver.GetMethod` predicate: name, generic arity, return type,
/// `has_this`, vararg shape and parameter types must agree.
fn method_matches(
    module: &Module,
    candidate: &crate::model::types::MethodDefinition,
    reference_module: &Module,
    name: &str,
    signature: &MethodSignature,
) -> bool {
    if candidate.name != name {
        return false;
    }

    // Generic arity: presence and count (privatescope handling and the
    // MethodDefinition fast path of the C# resolver do not apply here; the
    // engine only ever sees external references).
    let candidate_arity = candidate.generic_parameters.len();
    let reference_arity = signature.generic_count as usize;
    if candidate_arity != reference_arity {
        return false;
    }

    if !are_same(module, &candidate.signature.return_type, reference_module, &signature.return_type)
    {
        return false;
    }

    if candidate.signature.has_this != signature.has_this {
        return false;
    }

    let candidate_vararg = candidate.signature.convention == SignatureCallingConvention::VarArg;
    let reference_vararg = signature.convention == SignatureCallingConvention::VarArg;
    if candidate_vararg != reference_vararg {
        return false;
    }

    let fixed = &candidate.signature.parameters;
    if candidate_vararg {
        // `IsVarArgCallTo`: the call site passes the fixed parameters plus
        // additional ones after the sentinel position.
        if fixed.len() >= signature.parameters.len() {
            return false;
        }
        if signature.vararg_start != fixed.len() {
            return false;
        }
        for (i, param) in fixed.iter().enumerate() {
            if !are_same(module, param, reference_module, &signature.parameters[i]) {
                return false;
            }
        }
        return true;
    }

    if fixed.len() != signature.parameters.len() {
        return false;
    }
    for (param, expected) in fixed.iter().zip(signature.parameters.iter()) {
        if !are_same(module, param, reference_module, expected) {
            return false;
        }
    }
    true
}

/// Structural type identity, port of `MetadataResolver.AreSame(TypeReference,
/// TypeReference)` and its `TypeSpecification` overloads.
///
/// Nominal references (definitions and external spellings) compare by
/// namespace + nesting-chain names; the scope is deliberately ignored, exactly
/// like the upstream TODO ("check scope"). Generic parameters compare by
/// position alone (`AreSame(GenericParameter, GenericParameter)`).
pub(crate) fn are_same(m_a: &Module, a: &TypeDesc, m_b: &Module, b: &TypeDesc) -> bool {
    use TypeDesc::*;
    match (a, b) {
        (Var(x), Var(y)) | (MVar(x), MVar(y)) => x == y,
        (SzArray(x), SzArray(y))
        | (Ptr(x), Ptr(y))
        | (ByRef(x), ByRef(y))
        | (Pinned(x), Pinned(y)) => are_same(m_a, x, m_b, y),
        (
            Array { element: e1, sizes: s1, lobounds: l1 },
            Array { element: e2, sizes: s2, lobounds: l2 },
        ) => {
            // Rank only; dimensions are not compared upstream either.
            s1.len() == s2.len() && l1.len() == l2.len() && are_same(m_a, e1, m_b, e2)
        }
        (
            GenericInstance { definition: d1, arguments: g1 },
            GenericInstance { definition: d2, arguments: g2 },
        ) => {
            g1.len() == g2.len()
                && are_same(m_a, d1, m_b, d2)
                && g1.iter().zip(g2.iter()).all(|(x, y)| are_same(m_a, x, m_b, y))
        }
        (FnPtr(s1), FnPtr(s2)) => fnptr_signatures_same(m_a, s1, m_b, s2),
        (
            CMod { required: r1, modifier: m1, unmodified: u1 },
            CMod { required: r2, modifier: m2, unmodified: u2 },
        ) => r1 == r2 && are_same(m_a, m1, m_b, m2) && are_same(m_a, u1, m_b, u2),
        (Sentinel, Sentinel) | (TypedByRef, TypedByRef) => true,
        (Internal(s1), Internal(s2)) => s1 == s2,
        // Nominal forms (including Def <-> External cross-comparisons between
        // the referencing module and the resolved definition module).
        _ => match (nominal_identity(m_a, a), nominal_identity(m_b, b)) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        },
    }
}

fn fnptr_signatures_same(
    m_a: &Module,
    a: &MethodSignature,
    m_b: &Module,
    b: &MethodSignature,
) -> bool {
    a.has_this == b.has_this
        && a.explicit_this == b.explicit_this
        && a.convention == b.convention
        && a.generic_count == b.generic_count
        && are_same(m_a, &a.return_type, m_b, &b.return_type)
        && a.parameters.len() == b.parameters.len()
        && a.parameters.iter().zip(b.parameters.iter()).all(|(x, y)| are_same(m_a, x, m_b, y))
}

/// Namespace + outermost-to-innermost name chain of a nominal reference;
/// `None` for non-nominal forms (compared structurally above).
fn nominal_identity(m: &Module, ty: &TypeDesc) -> Option<(String, Vec<String>)> {
    match ty {
        TypeDesc::Def(id) => {
            let mut names = Vec::new();
            let mut current = Some(*id);
            while let Some(cid) = current {
                let def = m.type_def(cid);
                names.push(def.name.clone());
                current = def.declaring_type;
            }
            names.reverse();
            Some((m.type_def(*id).namespace.clone(), names))
        }
        TypeDesc::External(ext) => {
            let mut names: Vec<String> = ext.nesting.iter().map(|b| b.name.clone()).collect();
            names.push(ext.name.clone());
            Some((ext.namespace.clone(), names))
        }
        TypeDesc::Internal(s) => Some((String::new(), vec![s.clone()])),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::AssemblyDefinition;
    use crate::model::types::{AssemblyNameReference, Version};
    use crate::model::types::{
        ExternalField, ExternalMethod, ExternalType, FieldDefinition, FieldSignature,
        MethodDefinition, ScopeRef, TypeDefinition,
    };
    use cecli_core::flags::{AssemblyAttributes, AssemblyHashAlgorithm, MethodAttributes};

    fn anr(name: &str, major: u16) -> AssemblyNameReference {
        let mut a = AssemblyNameReference::new(name);
        a.version = Version::new(major, 0, 0, 0);
        a
    }

    fn ext(ns: &str, name: &str, scope: ScopeRef) -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: ns.to_string(),
            name: name.to_string(),
            nesting: Vec::new(),
            scope,
        }))
    }

    fn named_ext(
        ns: &str,
        name: &str,
        nesting: Vec<Box<ExternalType>>,
        scope: ScopeRef,
    ) -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: ns.to_string(),
            name: name.to_string(),
            nesting,
            scope,
        }))
    }

    fn void_sig(params: Vec<TypeDesc>) -> MethodSignature {
        MethodSignature {
            has_this: true,
            explicit_this: false,
            convention: SignatureCallingConvention::Default,
            generic_count: 0,
            return_type: ext("System", "Void", ScopeRef::ThisModule),
            parameters: params,
            vararg_start: 0,
        }
    }

    fn add_method(
        m: &mut Module,
        owner: crate::model::types::TypeId,
        name: &str,
        sig: MethodSignature,
    ) -> crate::model::types::MethodId {
        m.add_method(
            owner,
            MethodDefinition {
                name: name.to_string(),
                attributes: MethodAttributes::PUBLIC,
                signature: sig,
                ..MethodDefinition::default()
            },
        )
    }

    fn add_field(m: &mut Module, owner: crate::model::types::TypeId, name: &str, ty: TypeDesc) {
        m.add_field(
            owner,
            FieldDefinition {
                name: name.to_string(),
                signature: FieldSignature(ty),
                ..FieldDefinition::default()
            },
        );
    }

    fn string_ty() -> TypeDesc {
        ext("System", "String", ScopeRef::ThisModule)
    }

    fn i32_ty() -> TypeDesc {
        ext("System", "Int32", ScopeRef::ThisModule)
    }

    #[test]
    fn resolves_inside_the_module() {
        let mut m = Module::default();

        let t_base = m.add_type(TypeDefinition {
            namespace: "Ns".into(),
            name: "Base".into(),
            ..TypeDefinition::default()
        });
        add_method(&mut m, t_base, "Foo", void_sig(vec![string_ty()]));
        add_field(&mut m, t_base, "count", i32_ty());

        let t_derived = m.add_type(TypeDefinition {
            namespace: "Ns".into(),
            name: "Derived".into(),
            base_type: Some(TypeDesc::Def(t_base)),
            ..TypeDefinition::default()
        });

        // Nested type: Ns.Outer/Inner.
        let t_outer = m.add_type(TypeDefinition {
            namespace: "Ns".into(),
            name: "Outer".into(),
            ..TypeDefinition::default()
        });
        let t_inner = m.add_type(TypeDefinition {
            name: "Inner".into(),
            declaring_type: Some(t_outer),
            ..TypeDefinition::default()
        });

        // Generic arity participates in the match.
        let mut generic_sig = void_sig(vec![]);
        generic_sig.generic_count = 1;
        let gen = add_method(&mut m, t_base, "Gen", generic_sig.clone());
        m.add_generic_parameter(crate::model::types::GenericParameter {
            name: "T".into(),
            position: 0,
            owner: crate::model::types::GenericOwner::Method(gen),
            ..crate::model::types::GenericParameter::default()
        });
        let mut wrong_arity = void_sig(vec![]);
        wrong_arity.generic_count = 2;
        let mut engine = ResolutionEngine::new(&m);

        // Def passthrough.
        assert_eq!(
            engine.resolve_type(&TypeDesc::Def(t_derived)).unwrap(),
            Some(ResolvedType { module_index: 0, id: t_derived })
        );

        // Top-level external spelling with ThisModule scope.
        assert_eq!(
            engine.resolve_type(&ext("Ns", "Base", ScopeRef::ThisModule)).unwrap(),
            Some(ResolvedType { module_index: 0, id: t_base })
        );

        // Nested chain resolves to the innermost definition.
        let outer_ext = Box::new(ExternalType {
            namespace: "Ns".into(),
            name: "Outer".into(),
            nesting: Vec::new(),
            scope: ScopeRef::ThisModule,
        });
        assert_eq!(
            engine
                .resolve_type(&named_ext("Ns", "Inner", vec![outer_ext], ScopeRef::ThisModule))
                .unwrap(),
            Some(ResolvedType { module_index: 0, id: t_inner })
        );

        // Method found on the base type through the derived declaring type.
        let found = engine
            .resolve_method(&MethodRef::External(ExternalMethod {
                parent: TypeDesc::Def(t_derived),
                name: "Foo".into(),
                signature: void_sig(vec![string_ty()]),
            }))
            .unwrap();
        assert_eq!(found.map(|(_, id)| m.method_def(id).name.clone()), Some("Foo".into()));

        // Wrong parameter type must not match.
        let missed = engine
            .resolve_method(&MethodRef::External(ExternalMethod {
                parent: TypeDesc::Def(t_derived),
                name: "Foo".into(),
                signature: void_sig(vec![i32_ty()]),
            }))
            .unwrap();
        assert!(missed.is_none());

        // Wrong generic arity must not match.
        let missed = engine
            .resolve_method(&MethodRef::External(ExternalMethod {
                parent: TypeDesc::Def(t_base),
                name: "Gen".into(),
                signature: wrong_arity,
            }))
            .unwrap();
        assert!(missed.is_none());
        let hit = engine
            .resolve_method(&MethodRef::External(ExternalMethod {
                parent: TypeDesc::Def(t_base),
                name: "Gen".into(),
                signature: generic_sig,
            }))
            .unwrap();
        assert!(hit.is_some());

        // Field found on the base type, matched by name + field type.
        let found = engine
            .resolve_field(&FieldRef::External(ExternalField {
                parent: TypeDesc::Def(t_derived),
                name: "count".into(),
                signature: FieldSignature(i32_ty()),
            }))
            .unwrap();
        assert_eq!(found.map(|(_, id)| m.field_def(id).name.clone()), Some("count".into()));
    }

    /// Builds a tiny "mscorlib-like" assembly image in memory (through the
    /// regular writer + `MetadataBuilder` pipeline) for the loader stub.
    fn corlib_image() -> Vec<u8> {
        let mut m = Module {
            name: "mscorlib".into(),
            runtime_version: "v4.0.30319".into(),
            ..Default::default()
        };

        let t_object = m.add_type(TypeDefinition {
            namespace: "System".into(),
            name: "Object".into(),
            ..TypeDefinition::default()
        });
        let t_vt = m.add_type(TypeDefinition {
            namespace: "System".into(),
            name: "ValueType".into(),
            base_type: Some(TypeDesc::Def(t_object)),
            ..TypeDefinition::default()
        });
        m.add_type(TypeDefinition {
            namespace: "System".into(),
            name: "Enum".into(),
            base_type: Some(TypeDesc::Def(t_vt)),
            ..TypeDefinition::default()
        });
        m.add_type(TypeDefinition {
            namespace: "System".into(),
            name: "Int32".into(),
            base_type: Some(TypeDesc::Def(t_vt)),
            ..TypeDefinition::default()
        });
        m.add_type(TypeDefinition {
            namespace: "System".into(),
            name: "String".into(),
            base_type: Some(TypeDesc::Def(t_object)),
            ..TypeDefinition::default()
        });
        m.add_type(TypeDefinition {
            namespace: "System".into(),
            name: "IDictionary".into(),
            attributes: TypeAttributes::INTERFACE | TypeAttributes::PUBLIC,
            ..TypeDefinition::default()
        });

        let assembly = AssemblyDefinition {
            name: crate::assembly::AssemblyNameDefinition {
                name: "mscorlib".into(),
                version: Version::new(4, 0, 0, 0),
                hash_algorithm: AssemblyHashAlgorithm::None,
                attributes: AssemblyAttributes::empty(),
                ..crate::assembly::AssemblyNameDefinition::default()
            },
            main: m,
            modules: Vec::new(),
            entry_point: None,
        };
        assembly.write().expect("corlib image builds")
    }

    struct StubLoader(Vec<u8>);

    impl AssemblyBytesLoader for StubLoader {
        fn load(&mut self, reference: &AssemblyNameReference) -> Result<Option<Cow<'_, [u8]>>> {
            if reference.name == "mscorlib" {
                Ok(Some(Cow::Borrowed(&self.0)))
            } else {
                Ok(None)
            }
        }
    }

    #[test]
    fn resolves_external_type_through_loader_and_classifies_value_types() {
        let corlib = corlib_image();
        let mut primary = Module::default();
        let mscorlib_ref = anr("mscorlib", 4);
        primary.assembly_refs.push(mscorlib_ref.clone());

        let mut engine = ResolutionEngine::with_loader(Box::new(StubLoader(corlib)));

        let int32 = ext("System", "Int32", ScopeRef::Assembly(mscorlib_ref.clone()));
        let rt = engine.resolve_type(&int32).unwrap().expect("Int32 resolves");
        assert_eq!(rt.module_index, 1);
        let loaded = &engine.loaded_modules()[rt.module_index - 1];
        assert_eq!(loaded.type_def(rt.id).name, "Int32");

        // Classification: value type vs reference type vs interface, all via
        // the resolved definitions' base chains.
        assert!(engine.is_value_type(&int32).unwrap());
        assert!(!engine
            .is_value_type(&ext("System", "String", ScopeRef::Assembly(mscorlib_ref.clone())))
            .unwrap());
        assert!(!engine
            .is_value_type(&ext("System", "IDictionary", ScopeRef::Assembly(mscorlib_ref.clone())))
            .unwrap());

        // Stripping: SZARRAY of Int32 is still a value type element-wise.
        assert!(engine.is_value_type(&TypeDesc::SzArray(Box::new(int32.clone()))).unwrap());

        // The loader is consulted once per reference: a second query hits the
        // cache (same result, no growth).
        engine.resolve_type(&int32).unwrap().expect("cached");
        assert_eq!(engine.loaded_modules().len(), 1);
    }

    #[test]
    fn unresolvable_without_loader_is_an_unsupported_error() {
        let mut primary = Module::default();
        let mscorlib_ref = anr("mscorlib", 4);
        primary.assembly_refs.push(mscorlib_ref.clone());

        let mut engine = ResolutionEngine::new(&primary);

        // Plain resolution reports absence without error...
        assert!(engine
            .resolve_type(&ext("System", "Int32", ScopeRef::Assembly(mscorlib_ref)))
            .unwrap()
            .is_none());

        // ...but classification cannot guess and fails loudly, like Cecil.
        let err = engine
            .is_value_type(&ext("System", "Int32", ScopeRef::Assembly(anr("mscorlib", 4))))
            .unwrap_err();
        assert!(err.to_string().contains("could not resolve type"), "{err}");
    }

    #[test]
    fn in_module_value_type_classification() {
        let mut m = Module::default();

        let t_object = m.add_type(TypeDefinition {
            namespace: "System".into(),
            name: "Object".into(),
            ..TypeDefinition::default()
        });
        let t_vt = m.add_type(TypeDefinition {
            namespace: "System".into(),
            name: "ValueType".into(),
            base_type: Some(TypeDesc::Def(t_object)),
            ..TypeDefinition::default()
        });
        let t_enum = m.add_type(TypeDefinition {
            namespace: "System".into(),
            name: "Enum".into(),
            base_type: Some(TypeDesc::Def(t_vt)),
            ..TypeDefinition::default()
        });

        let t_color = m.add_type(TypeDefinition {
            namespace: "Demo".into(),
            name: "Color".into(),
            base_type: Some(TypeDesc::Def(t_enum)),
            ..TypeDefinition::default()
        });
        // Struct two levels below ValueType exercises the chain walk.
        let t_point = m.add_type(TypeDefinition {
            namespace: "Demo".into(),
            name: "Point".into(),
            base_type: Some(TypeDesc::Def(t_color)),
            ..TypeDefinition::default()
        });
        let t_widget = m.add_type(TypeDefinition {
            namespace: "Demo".into(),
            name: "Widget".into(),
            base_type: Some(TypeDesc::Def(t_object)),
            ..TypeDefinition::default()
        });
        let t_iface = m.add_type(TypeDefinition {
            namespace: "Demo".into(),
            name: "IShape".into(),
            attributes: TypeAttributes::INTERFACE,
            base_type: Some(TypeDesc::Def(t_object)),
            ..TypeDefinition::default()
        });

        let mut engine = ResolutionEngine::new(&m);
        assert!(!engine.is_value_type(&TypeDesc::Def(t_object)).unwrap());
        assert!(!engine.is_value_type(&TypeDesc::Def(t_vt)).unwrap());
        assert!(engine.is_value_type(&TypeDesc::Def(t_enum)).unwrap());
        assert!(engine.is_value_type(&TypeDesc::Def(t_color)).unwrap());
        assert!(engine.is_value_type(&TypeDesc::Def(t_point)).unwrap());
        assert!(!engine.is_value_type(&TypeDesc::Def(t_widget)).unwrap());
        assert!(!engine.is_value_type(&TypeDesc::Def(t_iface)).unwrap());

        // Generic parameters and sentinels are simply not value types.
        assert!(!engine.is_value_type(&TypeDesc::Var(0)).unwrap());
        assert!(!engine.is_value_type(&TypeDesc::MVar(1)).unwrap());
    }
}
