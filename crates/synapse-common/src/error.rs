//! Crate-wide error type.

use std::path::PathBuf;

/// All fallible operations in `synapse-common` return this error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error on {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("config parse error: {0}")]
    ConfigParse(#[from] toml::de::Error),

    #[error("invalid configuration:{}", format_problems(.0))]
    ConfigInvalid(Vec<String>),

    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("value out of range for storage: {0}")]
    OutOfRange(&'static str),

    #[error("database schema version {found} is newer than the supported version {supported}")]
    SchemaTooNew { found: i64, supported: i64 },

    #[error("database is not in WAL mode (got {0:?})")]
    NotWal(String),

    #[error("self-protection: {0}")]
    SelfProtection(String),

    #[error("logging initialisation failed: {0}")]
    Logging(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Convenience constructor attaching a path to an I/O error.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}

fn format_problems(problems: &[String]) -> String {
    let mut out = String::new();
    for p in problems {
        out.push_str("\n  - ");
        out.push_str(p);
    }
    out
}
