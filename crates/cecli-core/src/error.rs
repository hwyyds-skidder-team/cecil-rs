use std::fmt;

/// Error type shared by every `cecli` crate.
#[derive(Debug)]
pub enum Error {
    /// Underlying IO failure.
    Io(std::io::Error),
    /// The input is not a valid PE / CLI image or metadata root.
    BadImage(String),
    /// A feature exists in the format but is not supported by this build.
    Unsupported(String),
    /// An operation is invalid for the current state of an object.
    InvalidOperation(String),
    /// An argument passed by the caller is invalid.
    Argument(String),
}

impl Error {
    pub fn bad_image(msg: impl Into<String>) -> Self {
        Error::BadImage(msg.into())
    }
    pub fn unsupported(msg: impl Into<String>) -> Self {
        Error::Unsupported(msg.into())
    }
    pub fn invalid_op(msg: impl Into<String>) -> Self {
        Error::InvalidOperation(msg.into())
    }
    pub fn argument(msg: impl Into<String>) -> Self {
        Error::Argument(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::BadImage(m) => write!(f, "bad image: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
            Error::InvalidOperation(m) => write!(f, "invalid operation: {m}"),
            Error::Argument(m) => write!(f, "bad argument: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
