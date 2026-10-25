//! Layers L0 to L2 for one file (spec 7), cheapest first:
//!
//! - L0 trust: pacman owns the file and its SHA-256 matches the package's mtree. Trusted files are not YARA-scanned (this
//!   is what keeps scanning off most of `/usr`). A pacman file whose content no longer matches is itself a finding, after
//!   the package's current mtree has been re-read (so an upgrade the trust cache has not caught up with is not reported).
//! - L1 hash table: a known-bad hash is a finding, a known-good one ends the check.
//! - L2 YARA-X.
//!
//! Results are cached per (device, inode, size, mtime, ctime), so a binary that runs a thousand times is checked once.
//! Automatic checks are rate limited (`engine.max_scans_per_sec`); skipped ones are counted.

use std::collections::HashMap;
use std::io::{Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use synapse_common::event::Sha256;
use synapse_common::model::HashClass;
use synapse_common::store::{Store, TrustEntry};
use synapse_rules::mtree::{self, LocalPackage};
use synapse_rules::scan::{self, Yara, YaraHit};
use tracing::{debug, warn};

const MAX_CACHE: usize = 8192;
const NS_PER_SEC: u64 = 1_000_000_000;

#[derive(Debug, Clone, PartialEq)]
pub enum Finding {
    /// L0: a pacman-owned file whose content differs from its package.
    Modified {
        package: String,
        expected: Sha256,
        actual: Sha256,
    },
    /// L1: the hash table lists this file as bad.
    KnownBad {
        sha256: Sha256,
        label: Option<String>,
    },
    /// L2: YARA-X rules matched.
    Yara { sha256: Sha256, hits: Vec<YaraHit> },
}

/// How a check ended (for statistics and `synapsectl scan`).
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Trusted {
        package: String,
    },
    KnownGood,
    Clean,
    Findings(Vec<Finding>),
    /// Not checked: not a regular file, too large, unreadable, or over the rate limit.
    Skipped(&'static str),
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FileStats {
    pub checked: u64,
    pub cached: u64,
    pub trusted: u64,
    pub skipped_rate: u64,
    pub skipped_unreadable: u64,
    pub findings: u64,
}

type FileId = (u64, u64, u64, i64, i64);

pub struct FileCheck {
    yara: Option<Yara>,
    max_bytes: u64,
    cache: HashMap<FileId, Outcome>,
    per_sec: u32,
    bucket: (Instant, u32),
    /// package name -> its pacman database directory (rebuilt when a name is missing)
    packages: HashMap<String, PathBuf>,
    pacman_local: PathBuf,
    pub stats: FileStats,
}

fn file_id(m: &std::fs::Metadata) -> FileId {
    (
        m.dev(),
        m.ino(),
        m.size(),
        m.mtime_nsec() + m.mtime() * 1_000_000_000,
        m.ctime(),
    )
}

impl FileCheck {
    pub fn new(yara: Option<Yara>, max_bytes: u64, per_sec: u32) -> FileCheck {
        FileCheck {
            yara,
            max_bytes,
            cache: HashMap::new(),
            per_sec,
            bucket: (Instant::now(), 0),
            packages: HashMap::new(),
            pacman_local: PathBuf::from(mtree::PACMAN_LOCAL),
            stats: FileStats::default(),
        }
    }

    #[cfg(test)]
    pub fn with_pacman_local(mut self, dir: &Path) -> FileCheck {
        self.pacman_local = dir.to_path_buf();
        self
    }

    pub fn yara(&self) -> Option<&Yara> {
        self.yara.as_ref()
    }

    fn take_token(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.bucket.0).as_secs() >= 1 {
            self.bucket = (now, 0);
        }
        if self.bucket.1 >= self.per_sec {
            return false;
        }
        self.bucket.1 += 1;
        true
    }

    /// Check one file. `limited` = an automatic check (rate limited; `synapsectl scan` is not). `pacman_active` = a
    /// transaction runs, so a changed package file is expected.
    pub fn check(
        &mut self,
        store: &mut Store,
        path: &Path,
        limited: bool,
        pacman_active: bool,
        now_ns: u64,
    ) -> Outcome {
        let (mut file, meta) = match scan::open_regular(path, self.max_bytes) {
            Ok(Some(x)) => x,
            Ok(None) => return Outcome::Skipped("not a regular file or too large"),
            Err(e) => {
                debug!(path = %path.display(), error = %e, "cannot open file to check");
                self.stats.skipped_unreadable += 1;
                return Outcome::Skipped("unreadable");
            }
        };
        let id = file_id(&meta);
        if let Some(o) = self.cache.get(&id) {
            self.stats.cached += 1;
            return o.clone();
        }
        if limited && !self.take_token() {
            self.stats.skipped_rate += 1;
            return Outcome::Skipped("rate limit");
        }
        self.stats.checked += 1;
        let sha = match scan::sha256_file(&file) {
            Ok(s) => s,
            Err(_) => {
                self.stats.skipped_unreadable += 1;
                return Outcome::Skipped("unreadable");
            }
        };
        let raw = path.as_os_str().as_bytes();

        // L0
        let mut findings = Vec::new();
        match store.trust_get(raw) {
            Ok(Some(entry)) if entry.sha256 == sha => {
                if entry.verified_ns == 0 {
                    let _ = store.trust_mark_verified(raw, now_ns);
                }
                return self.remember(
                    id,
                    Outcome::Trusted {
                        package: entry.package,
                    },
                );
            }
            Ok(Some(entry)) => {
                if pacman_active {
                    return Outcome::Skipped("package being updated");
                }
                match self.refresh_package(store, &entry.package, raw) {
                    Some(fresh) if fresh == sha => {
                        return self.remember(
                            id,
                            Outcome::Trusted {
                                package: entry.package,
                            },
                        );
                    }
                    fresh => findings.push(Finding::Modified {
                        package: entry.package,
                        expected: fresh.unwrap_or(entry.sha256),
                        actual: sha,
                    }),
                }
            }
            Ok(None) => {}
            Err(e) => warn!(error = %e, "trust cache lookup failed"),
        }

        // L1
        match store.hash_class(&sha) {
            Ok(Some((HashClass::Good, _))) if findings.is_empty() => {
                return self.remember(id, Outcome::KnownGood)
            }
            Ok(Some((HashClass::Bad, label))) => {
                findings.push(Finding::KnownBad { sha256: sha, label })
            }
            Ok(_) => {}
            Err(e) => warn!(error = %e, "hash table lookup failed"),
        }

        // L2
        if let Some(y) = &self.yara {
            if file.seek(SeekFrom::Start(0)).is_ok() {
                match y.scan_file(&file, meta.len()) {
                    Ok(hits) if !hits.is_empty() => {
                        findings.push(Finding::Yara { sha256: sha, hits })
                    }
                    Ok(_) => {}
                    Err(e) => warn!(path = %path.display(), error = %e, "YARA scan failed"),
                }
            }
        }
        let outcome = if findings.is_empty() {
            Outcome::Clean
        } else {
            Outcome::Findings(findings)
        };
        if matches!(outcome, Outcome::Findings(_)) {
            self.stats.findings += 1;
        }
        self.remember(id, outcome)
    }

    fn remember(&mut self, id: FileId, o: Outcome) -> Outcome {
        if self.cache.len() >= MAX_CACHE {
            self.cache.clear();
        }
        if matches!(o, Outcome::Trusted { .. }) {
            self.stats.trusted += 1;
        }
        self.cache.insert(id, o.clone());
        o
    }

    /// Re-read `package`'s mtree from the pacman database and store it; returns the hash it now lists for `path`.
    fn refresh_package(&mut self, store: &mut Store, package: &str, path: &[u8]) -> Option<Sha256> {
        if !self.packages.contains_key(package) {
            let list: Vec<LocalPackage> = mtree::local_packages(&self.pacman_local).ok()?;
            self.packages = list.into_iter().map(|p| (p.name, p.dir)).collect();
        }
        let dir = self.packages.get(package)?.clone();
        let files = mtree::package_files(&LocalPackage {
            name: package.to_owned(),
            dir,
        })
        .ok()?;
        let entries: Vec<TrustEntry> = files.iter().map(|f| trust_entry(package, f, 0)).collect();
        if let Err(e) = store.trust_replace_package(package, &entries) {
            warn!(error = %e, package, "cannot refresh the trust cache");
        }
        files
            .into_iter()
            .find(|f| f.path.as_os_str().as_bytes() == path)
            .map(|f| f.sha256)
    }
}

pub fn trust_entry(package: &str, f: &mtree::MtreeEntry, verified_ns: u64) -> TrustEntry {
    TrustEntry {
        path: f.path.as_os_str().as_bytes().to_vec(),
        sha256: f.sha256,
        package: package.to_owned(),
        size: f.size,
        mtime_ns: u64::try_from(f.mtime_s)
            .unwrap_or(0)
            .saturating_mul(NS_PER_SEC),
        verified_ns,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use std::fs;
    use std::io::Write;
    use std::time::Duration;

    fn yara() -> Yara {
        Yara::from_source(
            "rule eicar { meta: severity = \"low\" strings: $e = \"EICAR-STANDARD-ANTIVIRUS-TEST-FILE\" condition: $e }",
            Duration::from_secs(5),
        )
        .unwrap()
    }

    fn sha_of(b: &[u8]) -> Sha256 {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x");
        fs::write(&p, b).unwrap();
        scan::sha256_file(&fs::File::open(&p).unwrap()).unwrap()
    }

    #[test]
    fn eicar_is_found_once_and_cached() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("eicar.com");
        fs::write(&p, scan::EICAR).unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let mut fc = FileCheck::new(Some(yara()), 1 << 20, 100);
        let Outcome::Findings(f) = fc.check(&mut store, &p, true, false, 1) else {
            panic!("not found")
        };
        assert!(matches!(&f[0], Finding::Yara { hits, .. } if hits[0].rule == "eicar"));
        assert!(matches!(
            fc.check(&mut store, &p, true, false, 2),
            Outcome::Findings(_)
        ));
        assert_eq!(fc.stats.checked, 1);
        assert_eq!(fc.stats.cached, 1);
    }

    #[test]
    fn known_good_and_known_bad_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tool");
        fs::write(&p, b"#!/bin/sh\necho hi\n").unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let sha = sha_of(b"#!/bin/sh\necho hi\n");
        store
            .put_hash(&sha, HashClass::Bad, Some("test"), "unit", 0)
            .unwrap();
        let mut fc = FileCheck::new(None, 1 << 20, 100);
        assert!(
            matches!(fc.check(&mut store, &p, false, false, 0), Outcome::Findings(f) if matches!(f[0], Finding::KnownBad { .. }))
        );
        store
            .put_hash(&sha, HashClass::Good, None, "unit", 0)
            .unwrap();
        let mut fc = FileCheck::new(None, 1 << 20, 100);
        assert_eq!(
            fc.check(&mut store, &p, false, false, 0),
            Outcome::KnownGood
        );
    }

    #[test]
    fn package_files_are_trusted_and_changes_are_found_after_a_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("tool");
        fs::write(&bin, b"original").unwrap();
        // a fake pacman database that lists the file with its real hash
        let local = dir.path().join("local");
        let pkg = local.join("tool-1-1");
        fs::create_dir_all(&pkg).unwrap();
        fs::write(pkg.join("desc"), "%NAME%\ntool\n").unwrap();
        let write_mtree = |content: &[u8]| {
            let line = format!(
                "#mtree\n/set type=file uid=0 gid=0 mode=644\n./{} time=1.0 size={} sha256digest={}\n",
                bin.strip_prefix("/").unwrap().display(),
                content.len(),
                sha_of(content)
            );
            let mut gz = GzEncoder::new(
                fs::File::create(pkg.join("mtree")).unwrap(),
                flate2::Compression::default(),
            );
            gz.write_all(line.as_bytes()).unwrap();
            gz.finish().unwrap();
        };
        write_mtree(b"original");
        let mut store = Store::open_in_memory().unwrap();
        let mut fc = FileCheck::new(Some(yara()), 1 << 20, 100).with_pacman_local(&local);
        // seed the cache with an OLD hash: the refresh must pick up the current mtree and trust the file
        let stale = TrustEntry {
            path: bin.as_os_str().as_bytes().to_vec(),
            sha256: Sha256([1; 32]),
            package: "tool".into(),
            size: 1,
            mtime_ns: 0,
            verified_ns: 0,
        };
        store.trust_replace_package("tool", &[stale]).unwrap();
        assert_eq!(
            fc.check(&mut store, &bin, false, false, 5),
            Outcome::Trusted {
                package: "tool".into()
            }
        );

        // now the file really changes behind pacman's back
        fs::write(&bin, b"tampered!").unwrap();
        let Outcome::Findings(f) = fc.check(&mut store, &bin, false, false, 6) else {
            panic!("change not found")
        };
        assert!(matches!(&f[0], Finding::Modified { package, .. } if package == "tool"));
        // during a pacman transaction the same change is expected
        let mut fc2 = FileCheck::new(None, 1 << 20, 100).with_pacman_local(&local);
        assert!(matches!(
            fc2.check(&mut store, &bin, false, true, 7),
            Outcome::Skipped(_)
        ));
    }

    #[test]
    fn automatic_checks_are_rate_limited_and_odd_files_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let mut fc = FileCheck::new(None, 1 << 20, 2);
        for i in 0..5 {
            fs::write(dir.path().join(format!("f{i}")), format!("{i}")).unwrap();
        }
        let skipped = (0..5)
            .filter(|i| {
                fc.check(
                    &mut store,
                    &dir.path().join(format!("f{i}")),
                    true,
                    false,
                    0,
                ) == Outcome::Skipped("rate limit")
            })
            .count();
        assert_eq!(skipped, 3);
        assert!(matches!(
            fc.check(&mut store, dir.path(), false, false, 0),
            Outcome::Skipped(_)
        ));
        assert!(matches!(
            fc.check(&mut store, Path::new("/nonexistent/x"), false, false, 0),
            Outcome::Skipped("unreadable")
        ));
    }
}
