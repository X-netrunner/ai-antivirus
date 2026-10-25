//! Detection content for the Synapse engine (spec 7): behavior rules in TOML (L3), YARA-X scanning (L2), file hashing for
//! the hash table (L1) and pacman's per-package file lists for trust (L0). No I/O happens here unless asked: the engine
//! decides what to read and when.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod matcher;
pub mod mtree;
pub mod rule;
pub mod scan;
pub mod window;

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error on {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid rules:{}", .0.iter().map(|p| format!("\n  - {p}")).collect::<String>())]
    Rules(Vec<String>),
    #[error("scan failed: {0}")]
    Scan(String),
    #[error("pacman mtree: {0}")]
    Mtree(String),
}

impl Error {
    pub fn io(path: &Path, source: std::io::Error) -> Error {
        Error::Io { path: path.to_path_buf(), source }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
