//! Portable PDB document model: one source file described by a `Document`
//! metadata table row (ECMA-335 §V.C).

use std::fmt;

/// A source document referenced by debug information.
///
/// Mirrors `Mono.Cecil.Cil.Document` for the fields carried by the portable
/// PDB `Document` table: a name, the hash algorithm GUID, the source hash,
/// and the language GUID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// Document name decoded from the name blob (separator-joined segments,
    /// e.g. `/src/lib/program.cs`).
    pub name: String,
    /// Hash algorithm GUID (`Document` column 2). All zeroes when absent.
    pub hash_algorithm: [u8; 16],
    /// Source hash bytes (`Document` column 3).
    pub hash: Vec<u8>,
    /// Language GUID (`Document` column 4). All zeroes when absent.
    pub language: [u8; 16],
}

impl Document {
    /// Creates an empty document with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Document { name: name.into(), hash_algorithm: [0; 16], hash: Vec::new(), language: [0; 16] }
    }
}

impl fmt::Display for Document {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_uses_name() {
        let doc = Document::new("/src/main.cs");
        assert_eq!(doc.to_string(), "/src/main.cs");
        assert_eq!(doc.hash, Vec::<u8>::new());
        assert_eq!(doc.language, [0; 16]);
    }
}
