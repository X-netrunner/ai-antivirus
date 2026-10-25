//! Rule updates: `rules-update DIR` validates a new rules directory (behavior + YARA), checks its signature when the
//! config requires signed rules, shows what changes, and installs it in one rename, keeping the previous set as
//! `<rules_dir>.prev` for `rules-rollback`. The engine reloads changed behavior rules by itself; YARA changes need a
//! restart of ai-antivirus-engined.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ai_antivirus_common::config::Config;
use ai_antivirus_rules::rule::RuleSet;
use ai_antivirus_rules::scan::Yara;
use ai_antivirus_rules::signing;

use crate::detect::Res;

/// Deepest directory level copied, and the most files: a rules tree is small, anything else is a mistake.
const MAX_DEPTH: usize = 4;
const MAX_FILES: usize = 2000;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
    pub yara_changed: bool,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.changed.is_empty()
            && !self.yara_changed
    }
}

fn s<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn config(cfg: &Path) -> Result<Config, String> {
    if cfg.exists() {
        Config::load(cfg).map_err(s)
    } else {
        Ok(Config::default())
    }
}

/// Behavior rules by id (serialized, to compare), empty when the directory has none.
fn behavior(dir: &Path) -> Result<BTreeMap<String, String>, String> {
    let b = dir.join("behavior");
    if !b.exists() {
        return Ok(BTreeMap::new());
    }
    let set = RuleSet::load_dir(&b).map_err(|e| format!("{}: {e}", b.display()))?;
    set.rules
        .iter()
        .map(|r| Ok((r.id.clone(), serde_json::to_string(r).map_err(s)?)))
        .collect()
}

/// YARA files by name -> contents.
fn yara_files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    if let Ok(rd) = std::fs::read_dir(dir.join("yara")) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_file() {
                if let Ok(b) = std::fs::read(&p) {
                    out.insert(e.file_name().to_string_lossy().into_owned(), b);
                }
            }
        }
    }
    out
}

/// Everything that must hold before a directory may replace the running rules.
pub fn validate(src: &Path, cfg: &Config) -> Result<(), String> {
    if !src.join("behavior").is_dir() {
        return Err(format!("{} has no behavior/ directory", src.display()));
    }
    behavior(src)?;
    let y = src.join("yara");
    if y.exists() {
        Yara::load_dir(
            &y,
            Duration::from_millis(u64::from(cfg.engine.yara_timeout_ms)),
        )
        .map_err(|e| format!("{}: {e}", y.display()))?;
    }
    if cfg.engine.require_signed_rules {
        signing::verify(src, &cfg.engine.rules_pubkey).map_err(|e| {
            format!(
                "engine.require_signed_rules is on and {} is not validly signed: {e}",
                src.display()
            )
        })?;
    }
    Ok(())
}

pub fn diff(old: &Path, new: &Path) -> Result<Diff, String> {
    let a = if old.exists() {
        behavior(old)?
    } else {
        BTreeMap::new()
    };
    let b = behavior(new)?;
    let ka: BTreeSet<_> = a.keys().cloned().collect();
    let kb: BTreeSet<_> = b.keys().cloned().collect();
    Ok(Diff {
        added: kb.difference(&ka).cloned().collect(),
        removed: ka.difference(&kb).cloned().collect(),
        changed: ka
            .intersection(&kb)
            .filter(|k| a.get(*k) != b.get(*k))
            .cloned()
            .collect(),
        yara_changed: yara_files(old) != yara_files(new),
    })
}

/// Copy regular files and directories only (no symlinks, devices or sockets), with root-friendly modes.
fn copy_tree(src: &Path, dst: &Path, depth: usize, count: &mut usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!(
            "{} is nested too deeply for a rules directory",
            src.display()
        ));
    }
    std::fs::create_dir(dst).map_err(|e| format!("{}: {e}", dst.display()))?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o755)).map_err(s)?;
    for e in std::fs::read_dir(src).map_err(|e| format!("{}: {e}", src.display()))? {
        let e = e.map_err(s)?;
        let t = e.file_type().map_err(s)?;
        let to = dst.join(e.file_name());
        if t.is_dir() {
            copy_tree(&e.path(), &to, depth + 1, count)?;
        } else if t.is_file() {
            *count += 1;
            if *count > MAX_FILES {
                return Err(format!(
                    "more than {MAX_FILES} files: not a rules directory"
                ));
            }
            std::fs::copy(e.path(), &to).map_err(|err| format!("{}: {err}", e.path().display()))?;
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o644)).map_err(s)?;
        }
    }
    Ok(())
}

fn sibling(dir: &Path, suffix: &str) -> PathBuf {
    let mut name = dir.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    dir.with_file_name(name)
}

/// Put `src` in place of `target`; the old set becomes `target.prev`.
pub fn install(src: &Path, target: &Path) -> Result<(), String> {
    let staging = sibling(target, &format!(".new-{}", std::process::id()));
    let prev = sibling(target, ".prev");
    if staging.exists() {
        std::fs::remove_dir_all(&staging).map_err(s)?;
    }
    if let Err(e) = copy_tree(src, &staging, 0, &mut 0) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }
    if target.exists() {
        if prev.exists() {
            std::fs::remove_dir_all(&prev).map_err(|e| format!("{}: {e}", prev.display()))?;
        }
        std::fs::rename(target, &prev).map_err(|e| format!("{}: {e}", target.display()))?;
    }
    if let Err(e) = std::fs::rename(&staging, target) {
        // put the old set back rather than leave no rules at all
        if prev.exists() {
            let _ = std::fs::rename(&prev, target);
        }
        return Err(format!("{}: {e}", target.display()));
    }
    Ok(())
}

/// Swap `target` and `target.prev`.
pub fn rollback_dir(target: &Path) -> Result<(), String> {
    let prev = sibling(target, ".prev");
    if !prev.is_dir() {
        return Err(format!(
            "no previous rule set ({} does not exist)",
            prev.display()
        ));
    }
    let tmp = sibling(target, &format!(".swap-{}", std::process::id()));
    std::fs::rename(target, &tmp).map_err(|e| format!("{}: {e}", target.display()))?;
    if let Err(e) = std::fs::rename(&prev, target) {
        let _ = std::fs::rename(&tmp, target);
        return Err(format!("{}: {e}", prev.display()));
    }
    std::fs::rename(&tmp, &prev).map_err(s)
}

fn print_diff(d: &Diff) {
    let list = |v: &[String]| {
        if v.is_empty() {
            "-".to_string()
        } else {
            v.join(" ")
        }
    };
    println!("added    {}", list(&d.added));
    println!("removed  {}", list(&d.removed));
    println!("changed  {}", list(&d.changed));
    println!(
        "yara     {}",
        if d.yara_changed { "changed" } else { "same" }
    );
}

fn after(d: &Diff) {
    if d.yara_changed {
        println!("YARA rules changed: sudo systemctl restart ai-antivirus-engined to load them");
    } else {
        println!("the engine reloads behavior rules by itself");
    }
}

pub fn rules_update(cfg: &Path, src: &Path, dry_run: bool, target: Option<&Path>) -> Res {
    let c = config(cfg)?;
    let target = target.map_or_else(|| c.engine.rules_dir.clone(), Path::to_path_buf);
    validate(src, &c)?;
    let d = diff(&target, src)?;
    print_diff(&d);
    if dry_run {
        println!("dry run: nothing installed");
        return Ok(());
    }
    if d.is_empty() {
        println!("no changes: nothing installed");
        return Ok(());
    }
    install(src, &target)?;
    println!(
        "installed {} (previous set kept as {})",
        target.display(),
        sibling(&target, ".prev").display()
    );
    after(&d);
    Ok(())
}

pub fn rules_rollback(cfg: &Path, target: Option<&Path>) -> Res {
    let c = config(cfg)?;
    let target = target.map_or_else(|| c.engine.rules_dir.clone(), Path::to_path_buf);
    let d = diff(&target, &sibling(&target, ".prev"))?;
    rollback_dir(&target)?;
    println!("rolled back {}", target.display());
    print_diff(&d);
    after(&d);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = include_str!("../../../rules/behavior/00-shipped.toml");

    fn tree(root: &Path, behavior: &str, yara: Option<&str>) -> PathBuf {
        std::fs::create_dir_all(root.join("behavior")).unwrap();
        std::fs::write(root.join("behavior/00.toml"), behavior).unwrap();
        if let Some(y) = yara {
            std::fs::create_dir_all(root.join("yara")).unwrap();
            std::fs::write(root.join("yara/a.yar"), y).unwrap();
        }
        root.to_path_buf()
    }

    /// The shipped file with its first rule left out.
    fn without_first_rule() -> (String, String) {
        let starts: Vec<usize> = RULE.match_indices("[[rule]]").map(|m| m.0).collect();
        let first = &RULE[starts[0]..starts[1]];
        let id = first
            .lines()
            .find_map(|l| {
                l.trim()
                    .strip_prefix("id = ")
                    .map(|v| v.trim_matches(['"', '\'']).to_string())
            })
            .unwrap();
        (format!("{}{}", &RULE[..starts[0]], &RULE[starts[1]..]), id)
    }

    const YARA: &str = "rule t { strings: $a = \"ai-antivirus-test-marker\" condition: $a }";

    #[test]
    fn update_installs_keeps_prev_and_rolls_back() {
        let d = tempfile::tempdir().unwrap();
        let (fewer, first_id) = without_first_rule();
        let live = tree(&d.path().join("rules"), &fewer, Some(YARA));
        let new = tree(&d.path().join("incoming"), RULE, Some(YARA));
        let cfg = Config::default();

        validate(&new, &cfg).unwrap();
        let diff1 = diff(&live, &new).unwrap();
        assert_eq!(diff1.added, vec![first_id.clone()]);
        assert!(diff1.removed.is_empty() && diff1.changed.is_empty() && !diff1.yara_changed);

        install(&new, &live).unwrap();
        assert_eq!(
            std::fs::read_to_string(live.join("behavior/00.toml")).unwrap(),
            RULE
        );
        let prev = d.path().join("rules.prev");
        assert_eq!(
            std::fs::read_to_string(prev.join("behavior/00.toml")).unwrap(),
            fewer
        );
        let mode = std::fs::metadata(live.join("behavior/00.toml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);

        rollback_dir(&live).unwrap();
        assert_eq!(
            std::fs::read_to_string(live.join("behavior/00.toml")).unwrap(),
            fewer
        );
        assert_eq!(
            std::fs::read_to_string(prev.join("behavior/00.toml")).unwrap(),
            RULE
        );
    }

    #[test]
    fn broken_or_unsigned_sets_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let bad = tree(
            &d.path().join("bad"),
            "[[rule]]\nid = \"x\"\nnot valid",
            None,
        );
        assert!(validate(&bad, &Config::default()).is_err());
        let empty = d.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(validate(&empty, &Config::default())
            .unwrap_err()
            .contains("behavior"));
        let good = tree(&d.path().join("good"), RULE, None);
        let mut cfg = Config::default();
        cfg.engine.require_signed_rules = true;
        cfg.engine.rules_pubkey = d.path().join("rules.pub");
        assert!(validate(&good, &cfg)
            .unwrap_err()
            .contains("not validly signed"));
        // a signed set passes
        let (key, _) = signing::write_keypair(d.path()).unwrap();
        signing::sign(&good, &key).unwrap();
        validate(&good, &cfg).unwrap();
    }

    #[test]
    fn symlinks_are_not_copied_and_rollback_needs_prev() {
        let d = tempfile::tempdir().unwrap();
        let src = tree(&d.path().join("src"), RULE, None);
        std::os::unix::fs::symlink("/etc/passwd", src.join("behavior/evil.toml")).unwrap();
        let live = d.path().join("live");
        install(&src, &live).unwrap();
        assert!(!live.join("behavior/evil.toml").exists());
        assert!(rollback_dir(&d.path().join("nothing")).is_err());
    }
}
