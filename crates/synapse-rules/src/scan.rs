//! Layer L1 (SHA-256 of a file, looked up in the hash table by the caller) and L2 (YARA-X).
//!
//! Files are opened with `O_NOFOLLOW | O_NONBLOCK` and must be regular files: a FIFO or device named like a binary cannot
//! hang the scanner, and a symlink swapped in after the event is not followed. Size is capped before reading. YARA-X runs
//! with a timeout, so a pathological rule or file costs at most that long.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256 as Sha256Hasher};
use synapse_common::event::Sha256;

use crate::{Error, Result};

/// Longest accepted YARA source file.
const MAX_YARA_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Open `path` for reading if it is a regular file of at most `max_bytes`. `Ok(None)` = skipped (not a regular file, too
/// large); errors are real I/O errors (permission denied, gone).
pub fn open_regular(path: &Path, max_bytes: u64) -> std::io::Result<Option<(File, fs::Metadata)>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > max_bytes {
        return Ok(None);
    }
    Ok(Some((file, meta)))
}

/// SHA-256 of an open file, from its start.
pub fn sha256_file(mut file: &File) -> std::io::Result<Sha256> {
    let mut h = Sha256Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    Ok(Sha256(out))
}

/// Compiled YARA-X rules from one directory.
pub struct Yara {
    rules: yara_x::Rules,
    files: Vec<PathBuf>,
    timeout: Duration,
}

impl std::fmt::Debug for Yara {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Yara").field("files", &self.files).field("timeout", &self.timeout).finish()
    }
}

/// One matching YARA rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraHit {
    pub namespace: String,
    pub rule: String,
    /// The rule's `severity` meta (`low`, `medium`, `high`, `critical`), when it has one.
    pub severity: Option<String>,
}

impl Yara {
    /// Compile every `*.yar` / `*.yara` in `dir` (not recursive), each file in its own namespace (its file stem). Problems in
    /// any file fail the whole load, with all compiler messages.
    pub fn load_dir(dir: &Path, timeout: Duration) -> Result<Yara> {
        let mut files: Vec<PathBuf> = match fs::read_dir(dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "yar" || x == "yara"))
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(Error::io(dir, e)),
        };
        files.sort();
        let mut compiler = yara_x::Compiler::new();
        let mut problems = Vec::new();
        for f in &files {
            let meta = fs::metadata(f).map_err(|e| Error::io(f, e))?;
            if meta.len() > MAX_YARA_FILE_BYTES {
                problems.push(format!("{}: larger than {MAX_YARA_FILE_BYTES} bytes", f.display()));
                continue;
            }
            let src = fs::read_to_string(f).map_err(|e| Error::io(f, e))?;
            let ns: String = f
                .file_stem()
                .map(|s| s.to_string_lossy().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect())
                .unwrap_or_else(|| "rules".into());
            compiler.new_namespace(&ns);
            if let Err(e) = compiler.add_source(yara_x::SourceCode::from(src.as_str()).with_origin(f.display().to_string())) {
                problems.push(e.to_string());
            }
        }
        if !problems.is_empty() {
            return Err(Error::Rules(problems));
        }
        Ok(Yara { rules: compiler.build(), files, timeout })
    }

    /// Compile one source string (tests, `synapsectl rules`).
    pub fn from_source(src: &str, timeout: Duration) -> Result<Yara> {
        let rules = yara_x::compile(src).map_err(|e| Error::Rules(vec![e.to_string()]))?;
        Ok(Yara { rules, files: Vec::new(), timeout })
    }

    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    pub fn rule_count(&self) -> usize {
        self.rules.iter().count()
    }

    /// Scan bytes already read into memory.
    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraHit>> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        scanner.set_timeout(self.timeout);
        let results = scanner.scan(data).map_err(|e| Error::Scan(e.to_string()))?;
        Ok(results
            .matching_rules()
            .map(|r| YaraHit {
                namespace: r.namespace().to_string(),
                rule: r.identifier().to_string(),
                severity: r.metadata().find_map(|(k, v)| match (k, v) {
                    ("severity", yara_x::MetaValue::String(s)) => Some(s.to_string()),
                    _ => None,
                }),
            })
            .collect())
    }

    /// Read an open file (already checked by `open_regular`) and scan it.
    pub fn scan_file(&self, mut file: &File, len: u64) -> Result<Vec<YaraHit>> {
        let mut data = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        file.read_to_end(&mut data).map_err(|e| Error::Scan(e.to_string()))?;
        self.scan_bytes(&data)
    }
}

/// The EICAR anti-virus test string (harmless by design; every scanner detects it).
pub const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const EICAR_RULE: &str = r#"
rule eicar_test_file {
  meta:
    severity = "low"
  strings:
    $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
  condition:
    $e at 32 or $e
}"#;

    #[test]
    fn eicar_is_found_and_clean_data_is_not() {
        let y = Yara::from_source(EICAR_RULE, Duration::from_secs(5)).unwrap();
        let hits = y.scan_bytes(EICAR).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, "eicar_test_file");
        assert_eq!(hits[0].severity.as_deref(), Some("low"));
        assert!(y.scan_bytes(b"#!/bin/sh\necho hello\n").unwrap().is_empty());
    }

    #[test]
    fn a_directory_compiles_into_namespaces_and_bad_rules_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("eicar.yar"), EICAR_RULE).unwrap();
        let y = Yara::load_dir(dir.path(), Duration::from_secs(5)).unwrap();
        assert_eq!(y.scan_bytes(EICAR).unwrap()[0].namespace, "eicar");
        fs::write(dir.path().join("broken.yar"), "rule x { condition: nonsense_identifier }").unwrap();
        assert!(matches!(Yara::load_dir(dir.path(), Duration::from_secs(5)), Err(Error::Rules(_))));
    }

    #[test]
    fn files_are_hashed_and_non_regular_files_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a");
        File::create(&p).unwrap().write_all(b"abc").unwrap();
        let (f, meta) = open_regular(&p, 1024).unwrap().unwrap();
        assert_eq!(meta.len(), 3);
        assert_eq!(
            sha256_file(&f).unwrap().to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(open_regular(&p, 2).unwrap().is_none(), "too large");
        assert!(open_regular(dir.path(), 1024).unwrap().is_none(), "a directory");
        std::os::unix::fs::symlink(&p, dir.path().join("link")).unwrap();
        assert!(open_regular(&dir.path().join("link"), 1024).is_err(), "symlinks are not followed");
    }
}
