//! Object model: frozen data types plus codecs built on them.
//!
//! Consumers use full paths (`cecli::model::signature::parse_method_signature`)
//! so sibling modules never collide in this file.

pub mod custom_attribute;
pub mod marshal;
pub mod removal;
pub mod security;
pub mod signature;
pub mod types;

pub use types::*;
pub mod substitution;
