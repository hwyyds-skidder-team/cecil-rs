//! Local variable model (`Mono.Cecil.Cil/VariableDefinition.cs`,
//! `VariableReference.cs`), decoupled from the object model.

use cecli_core::Token;

/// A local variable slot of a method body.
///
/// Cecil attaches a `TypeReference` to each local; to keep this crate free
/// of the object model the type is carried as the stand-in token recorded in
/// [`variable_type`] (resolved later by the `cecli` facade; `Token::NIL`
/// while unknown).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VariableDefinition {
    /// Zero-based slot index, identical to the index encoded by
    /// `ldloc`/`stloc` operands.
    pub index: u16,
    /// Stand-in for the variable's type; resolved by the object-model layer.
    pub variable_type: Token,
}

impl VariableDefinition {
    /// Creates a local variable with the given slot index and type token.
    pub fn new(index: u16, variable_type: Token) -> Self {
        VariableDefinition { index, variable_type }
    }
}

impl std::fmt::Display for VariableDefinition {
    /// Formats like Cecil's `VariableReference`: `V_0`, `V_1`, ...
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "V_{}", self.index)
    }
}
