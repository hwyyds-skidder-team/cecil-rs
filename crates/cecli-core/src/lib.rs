pub mod element;
pub mod error;
pub mod flags;
pub mod io;
pub mod token;

pub use element::{ElementType, VariantType};
pub use error::{Error, Result};
pub use token::{CodedIndexGroup, TableIndex, Token, TokenType};

/// Path to the workspace-level `fixtures/` directory (real .NET assemblies used by tests).
pub fn fixtures_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
}
