//! M7 commands used by the pacman hooks and for AUR safety.
//!
//! - `pacman-begin` (PreTransaction hook): pacman holds `/var/lib/pacman/db.lck` for the whole transaction, hooks
//!   included, and AI Antivirus's engine, responder and self-checks already treat that lock as "do not act". The command only
//!   confirms this and says so in the journal, so the hook's purpose is visible.
//! - `pacman-end` (PostTransaction hook, `NeedsTargets`): the package names arrive on stdin; their file records are read
//!   again into the trust cache (and dropped for removed packages), so files an upgrade replaced are trusted again at once.
//!   It never fails the transaction.
//! - `scan-pkgbuild DIR`: looks at a PKGBUILD and its `.install` scripts before they are built.

use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ai_antivirus_common::config::Config;
use ai_antivirus_engined::files::trust_entry;
use ai_antivirus_rules::mtree;
use ai_antivirus_rules::scan::Yara;

use crate::detect::{open_db, Res};
use crate::render::sanitize;

fn s<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

pub fn pacman_begin() -> Res {
    if mtree::pacman_active() {
        println!("ai-antivirus: pacman transaction started; AI Antivirus takes no destructive action until pacman releases db.lck");
    } else {
        println!(
            "ai-antivirus: pacman-begin ran outside a pacman transaction (no db.lck); nothing to do"
        );
    }
    Ok(())
}

fn valid_pkg_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 255
        && !n.starts_with('-')
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._+-".contains(&b))
}

/// Refresh the trust cache for the named packages. Returns (refreshed, removed).
pub fn refresh_packages(
    store: &mut ai_antivirus_common::store::Store,
    local: &Path,
    names: &BTreeSet<String>,
) -> Result<(usize, usize), String> {
    let installed = mtree::local_packages(local).map_err(s)?;
    let (mut refreshed, mut removed) = (0, 0);
    for name in names {
        match installed.iter().find(|p| &p.name == name) {
            Some(pkg) => {
                let entries: Vec<_> = mtree::package_files(pkg)
                    .map_err(s)?
                    .iter()
                    .map(|f| trust_entry(name, f, 0))
                    .collect();
                store.trust_replace_package(name, &entries).map_err(s)?;
                refreshed += 1;
            }
            None => {
                store.trust_replace_package(name, &[]).map_err(s)?;
                removed += 1;
            }
        }
    }
    Ok((refreshed, removed))
}

pub fn pacman_end(
    cfg: &Path,
    db: Option<&Path>,
    local: Option<&Path>,
    input: &mut dyn BufRead,
) -> Res {
    let names: BTreeSet<String> = input
        .lines()
        .map_while(Result::ok)
        .map(|l| l.trim().to_owned())
        .filter(|n| valid_pkg_name(n))
        .collect();
    if names.is_empty() {
        println!("ai-antivirus: no package names on stdin; nothing to refresh (use `ai-antivirus trust-baseline` for everything)");
        return Ok(());
    }
    // a hook must not fail the transaction: problems are reported and the exit status stays 0
    let outcome = open_db(cfg, db).and_then(|mut store| {
        refresh_packages(
            &mut store,
            local.unwrap_or(Path::new(mtree::PACMAN_LOCAL)),
            &names,
        )
    });
    match outcome {
        Ok((r, d)) => println!("ai-antivirus: trust cache refreshed for {r} package(s), dropped for {d} removed package(s)"),
        Err(e) => eprintln!("ai-antivirus: could not refresh the trust cache ({e}); run `ai-antivirus trust-baseline` later"),
    }
    Ok(())
}

pub fn stdin_is_terminal() -> bool {
    std::io::stdin().is_terminal()
}

// ------------------------------------------------------------------------------------------------ scan-pkgbuild

#[derive(Debug, PartialEq, Eq)]
pub struct PkgFinding {
    pub file: String,
    pub what: String,
}

/// Values inside `name=( ... )` of a PKGBUILD (possibly over several lines), each with surrounding quotes removed.
fn array_values(text: &str, name: &str) -> Vec<String> {
    let Some(start) = text.find(&format!("{name}=(")) else {
        return Vec::new();
    };
    let rest = &text[start + name.len() + 2..];
    let Some(end) = rest.find(')') else {
        return Vec::new();
    };
    rest[..end]
        .split_whitespace()
        .map(|v| v.trim_matches(|c| c == '\'' || c == '"').to_owned())
        .filter(|v| !v.is_empty() && !v.starts_with('#'))
        .collect()
}

/// Packaging hygiene findings for one PKGBUILD text (structure, not content).
pub fn pkgbuild_hygiene(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let sources = array_values(text, "source");
    let sums = [
        "sha256sums",
        "sha512sums",
        "b2sums",
        "sha384sums",
        "sha224sums",
        "sha1sums",
        "md5sums",
    ]
    .iter()
    .flat_map(|n| array_values(text, n))
    .collect::<Vec<_>>();
    for src in &sources {
        let url = src.rsplit_once("::").map_or(src.as_str(), |(_, u)| u);
        if url.starts_with("http://") || url.starts_with("ftp://") {
            out.push(format!("source {url} is fetched without encryption"));
        }
    }
    let vcs = |s: &str| {
        ["git+", "svn+", "hg+", "bzr+", "fossil+"]
            .iter()
            .any(|p| s.contains(p))
    };
    let unchecked = sums.iter().filter(|s| s.as_str() == "SKIP").count();
    let plain = sources.iter().filter(|s| !vcs(s)).count();
    if plain > 0 && unchecked >= plain && !sources.is_empty() {
        out.push("downloaded sources are not verified (every checksum is SKIP)".into());
    }
    if !sources.is_empty() && sums.is_empty() && !sources.iter().all(|s| vcs(s)) {
        out.push("there are downloaded sources but no checksums".into());
    }
    if text.contains("install=") {
        out.push("the package has an .install script, which runs as root when the package is installed: read it".into());
    }
    out
}

pub fn scan_pkgbuild(cfg: &Path, dir: &Path, rules: Option<&Path>) -> Result<bool, String> {
    let c = if cfg.exists() {
        Config::load(cfg).map_err(s)?
    } else {
        Config::default()
    };
    let rules_dir = rules.map_or_else(|| c.engine.rules_dir.clone(), Path::to_path_buf);
    let yara = Yara::load_dir(
        &rules_dir.join("yara"),
        Duration::from_millis(u64::from(c.engine.yara_timeout_ms)),
    )
    .map_err(s)?;
    let pkgbuild = dir.join("PKGBUILD");
    if !pkgbuild.is_file() {
        return Err(format!("{} has no PKGBUILD", dir.display()));
    }
    let mut files: Vec<PathBuf> = vec![pkgbuild.clone()];
    if let Ok(rd) = fs::read_dir(dir) {
        let mut extra: Vec<PathBuf> = rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .is_some_and(|x| x == "install" || x == "sh" || x == "patch" || x == "diff")
            })
            .collect();
        extra.sort();
        files.extend(extra);
    }
    let mut found = Vec::new();
    let text = fs::read_to_string(&pkgbuild).map_err(|e| format!("{}: {e}", pkgbuild.display()))?;
    for what in pkgbuild_hygiene(&text) {
        found.push(PkgFinding {
            file: "PKGBUILD".into(),
            what,
        });
    }
    for f in &files {
        let data = fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?;
        if data.len() > 4 * 1024 * 1024 {
            continue;
        }
        for hit in yara.scan_bytes(&data).map_err(s)? {
            found.push(PkgFinding {
                file: f
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                what: format!("YARA rule {}.{} matches", hit.namespace, hit.rule),
            });
        }
    }
    for f in &found {
        println!("{:<22} {}", sanitize(&f.file), sanitize(&f.what));
    }
    eprintln!(
        "{} files looked at, {} findings{}",
        files.len(),
        found.len(),
        if found.is_empty() {
            " (this is not a guarantee: read the PKGBUILD)"
        } else {
            ""
        }
    );
    Ok(!found.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_antivirus_common::store::Store;

    #[test]
    fn hygiene_reads_arrays_over_several_lines() {
        let t = "pkgname=x\nsource=('https://a.example/x.tar.gz'\n        \"fix.patch::http://b.example/fix.patch\")\nsha256sums=('abc'\n 'SKIP')\ninstall=x.install\n";
        let f = pkgbuild_hygiene(t);
        assert!(
            f.iter()
                .any(|m| m.contains("http://b.example/fix.patch")
                    && m.contains("without encryption")),
            "{f:?}"
        );
        assert!(f.iter().any(|m| m.contains(".install script")), "{f:?}");
        assert!(
            !f.iter().any(|m| m.contains("not verified")),
            "one real checksum is present: {f:?}"
        );
        let g = pkgbuild_hygiene("source=('https://a.example/x.tgz')\nsha256sums=('SKIP')\n");
        assert!(g.iter().any(|m| m.contains("not verified")), "{g:?}");
        assert!(
            pkgbuild_hygiene("source=('git+https://a.example/x.git')\nsha256sums=('SKIP')\n")
                .is_empty(),
            "VCS sources are normally SKIP"
        );
        assert!(pkgbuild_hygiene("source=('https://a.example/x.tgz')\n")
            .iter()
            .any(|m| m.contains("no checksums")));
        assert!(pkgbuild_hygiene("pkgname=clean\npackage() { :; }\n").is_empty());
    }

    #[test]
    fn scan_pkgbuild_runs_yara_over_the_scripts_too() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("PKGBUILD"),
            "pkgname=x\nsource=('https://a.example/x.tgz')\nsha256sums=('0000')\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("x.install"),
            "post_install() { echo ok; }\n",
        )
        .unwrap();
        let rules = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let none = Path::new("/nonexistent/ai-antivirus.toml");
        assert!(!scan_pkgbuild(none, dir.path(), Some(&rules)).unwrap());
        // the EICAR test string in an install script is found by the signature rules
        fs::write(
            dir.path().join("x.install"),
            ai_antivirus_rules::scan::EICAR,
        )
        .unwrap();
        assert!(scan_pkgbuild(none, dir.path(), Some(&rules)).unwrap());
        assert!(scan_pkgbuild(none, &dir.path().join("missing"), Some(&rules)).is_err());
    }

    #[test]
    fn pacman_end_refreshes_upgraded_packages_and_forgets_removed_ones() {
        use flate2::write::GzEncoder;
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("local");
        let mk = |name: &str, content: &str| {
            let p = local.join(format!("{name}-1-1"));
            fs::create_dir_all(&p).unwrap();
            fs::write(p.join("desc"), format!("%NAME%\n{name}\n")).unwrap();
            let line = format!("#mtree\n/set type=file uid=0 gid=0 mode=644\n./usr/bin/{name} time=1.0 size={} sha256digest={}\n", content.len(), ai_antivirus_common::event::Sha256(sha(content)));
            let mut gz = GzEncoder::new(
                fs::File::create(p.join("mtree")).unwrap(),
                flate2::Compression::default(),
            );
            gz.write_all(line.as_bytes()).unwrap();
            gz.finish().unwrap();
        };
        fn sha(s: &str) -> [u8; 32] {
            use sha2::Digest;
            sha2::Sha256::digest(s.as_bytes()).into()
        }
        mk("alpha", "one");
        let cfgp = dir.path().join("ai-antivirus.toml");
        fs::write(
            &cfgp,
            format!("[paths]\nstate_dir = '{}'\n", dir.path().display()),
        )
        .unwrap();
        let db = dir.path().join("t.db");
        let mut store = Store::open(&db).unwrap();
        store
            .trust_replace_package(
                "gone",
                &[trust_entry(
                    "gone",
                    &mtree::MtreeEntry {
                        path: "/usr/bin/gone".into(),
                        size: 1,
                        mtime_s: 1,
                        sha256: ai_antivirus_common::event::Sha256([1; 32]),
                        mode: 0o644,
                        uid: 0,
                        gid: 0,
                    },
                    0,
                )],
            )
            .unwrap();
        drop(store);
        let mut input = std::io::Cursor::new("alpha\ngone\n--bad\n../x\n\n");
        pacman_end(&cfgp, Some(&db), Some(&local), &mut input).unwrap();
        let store = Store::open(&db).unwrap();
        assert_eq!(
            store.trust_packages().unwrap(),
            vec![("alpha".to_owned(), 1)]
        );
        // a broken database never fails the hook
        let mut input = std::io::Cursor::new("alpha\n");
        pacman_end(
            &cfgp,
            Some(&dir.path().join("no/such/dir/t.db")),
            Some(&local),
            &mut input,
        )
        .unwrap();
    }
}
