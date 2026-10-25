//! `ai-antivirus exceptions`: list, add and remove the programs and folders AI Antivirus leaves alone
//! (`engine.exceptions_file`, see `ai_antivirus_common::exceptions`). Listing works for everyone; changes need root.
//! The engine picks a change up within a few seconds, without a restart.

use std::path::{Path, PathBuf};

use ai_antivirus_common::config::Config;
use ai_antivirus_common::exceptions::{self, Exception, Kind, DEFAULT_EXCEPTIONS_PATH};
use serde_json::json;

/// The exceptions file named by the config, or the default place when the config cannot be read (an ordinary user,
/// a config that is not installed yet).
fn file(config: &Path) -> PathBuf {
    Config::load(config)
        .map(|c| c.engine.exceptions_file)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_EXCEPTIONS_PATH))
}

fn denied(e: &str, what: &str) -> String {
    if e.contains("No such file or directory") {
        format!("{e}\nis AI Antivirus installed? (its /etc/ai-antivirus folder is missing)")
    } else if e.contains("ermission denied") || e.contains("Read-only file system") {
        format!("{e}\nchanging exceptions needs root: sudo ai-antivirus exceptions {what}")
    } else {
        e.to_owned()
    }
}

pub fn list(config: &Path, json_out: bool) -> Result<(), String> {
    let path = file(config);
    let (list, from_file) = exceptions::load(&path)?;
    let defaults = exceptions::defaults();
    if json_out {
        let items: Vec<_> = list
            .iter()
            .map(|e| {
                json!({
                    "kind": e.kind.as_str(),
                    "match": e.pattern,
                    "name": e.name,
                    "default": defaults.iter().any(|d| d.kind == e.kind && d.pattern == e.pattern),
                })
            })
            .collect();
        println!(
            "{}",
            json!({"file": path.display().to_string(), "from_file": from_file, "exceptions": items})
        );
        return Ok(());
    }
    if list.is_empty() {
        println!("no exceptions ({})", path.display());
        return Ok(());
    }
    let w = list
        .iter()
        .map(|e| e.pattern.chars().count())
        .max()
        .unwrap_or(0);
    for e in &list {
        println!("{:<7}  {:<w$}  {}", e.kind.as_str(), e.pattern, e.name);
    }
    if !from_file {
        println!("(built-in defaults: {} does not exist)", path.display());
    }
    Ok(())
}

pub fn add(config: &Path, kind: Kind, pattern: &str, name: Option<&str>) -> Result<(), String> {
    let path = file(config);
    let (mut list, _) = exceptions::load(&path)?;
    let e = Exception {
        kind,
        pattern: pattern.trim().to_owned(),
        name: name.unwrap_or("").trim().to_owned(),
    };
    exceptions::validate(&e).map_err(|m| format!("{:?} not added: {m}", e.pattern))?;
    if let Some(old) = list
        .iter_mut()
        .find(|o| o.kind == e.kind && o.pattern == e.pattern)
    {
        if e.name.is_empty() || old.name == e.name {
            println!("already there: {} {}", e.kind.as_str(), e.pattern);
            return Ok(());
        }
        old.name = e.name.clone();
    } else {
        list.push(e.clone());
    }
    exceptions::save(&path, &list)
        .map_err(|m| denied(&m, &format!("add {} {}", kind.as_str(), pattern)))?;
    println!("added: {} {}", e.kind.as_str(), e.pattern);
    Ok(())
}

pub fn remove(config: &Path, pattern: &str) -> Result<(), String> {
    let path = file(config);
    let (mut list, _) = exceptions::load(&path)?;
    let before = list.len();
    list.retain(|e| e.pattern != pattern.trim());
    if list.len() == before {
        return Err(format!("no exception {pattern:?}"));
    }
    exceptions::save(&path, &list).map_err(|m| denied(&m, &format!("remove {pattern}")))?;
    println!("removed: {pattern}");
    Ok(())
}

pub fn reset(config: &Path) -> Result<(), String> {
    let path = file(config);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(denied(&format!("{}: {e}", path.display()), "reset")),
    }
    println!(
        "back to the built-in exceptions ({})",
        exceptions::defaults().len()
    );
    Ok(())
}
