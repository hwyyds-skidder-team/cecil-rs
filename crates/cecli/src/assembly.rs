//! Assembly definition: the public facade over one or more modules.

use crate::model::types::*;
use crate::module_def::Module;

/// Assembly-level identity (`Assembly` row equivalent).
#[derive(Debug, Clone)]
pub struct AssemblyNameDefinition {
    pub name: String,
    pub version: Version,
    pub culture: Option<String>,
    /// Public key (full key, not the token, for `Assembly` rows).
    pub public_key: Vec<u8>,
    pub hash: Vec<u8>,
    pub hash_algorithm: AssemblyHashAlgorithm,
    pub attributes: AssemblyAttributes,
    pub custom_attributes: Vec<CustomAttribute>,
    pub security_declarations: Vec<SecurityDeclaration>,
}

impl Default for AssemblyNameDefinition {
    fn default() -> Self {
        AssemblyNameDefinition {
            name: String::new(),
            version: Version::new(0, 0, 0, 0),
            culture: None,
            public_key: Vec::new(),
            hash: Vec::new(),
            hash_algorithm: AssemblyHashAlgorithm::None,
            attributes: AssemblyAttributes::empty(),
            custom_attributes: Vec::new(),
            security_declarations: Vec::new(),
        }
    }
}

/// An assembly: main module plus optional satellite netmodules.
#[derive(Debug, Clone)]
pub struct AssemblyDefinition {
    pub name: AssemblyNameDefinition,
    pub main: Module,
    /// Additional netmodules of a multi-module assembly.
    pub modules: Vec<Module>,
    /// Entry point as a method arena index into `main`.
    pub entry_point: Option<MethodId>,
}

impl Default for AssemblyDefinition {
    fn default() -> Self {
        AssemblyDefinition {
            name: AssemblyNameDefinition::default(),
            main: Module::default(),
            modules: Vec::new(),
            entry_point: None,
        }
    }
}
