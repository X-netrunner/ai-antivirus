//! M6 commands: the rule-signing key, signing and verifying the rules directory.

use std::path::Path;

use ai_antivirus_common::config::Config;
use ai_antivirus_rules::signing;

use crate::detect::Res;

fn s<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn rules_dir(cfg: &Path, dir: Option<&Path>) -> Result<std::path::PathBuf, String> {
    match dir {
        Some(d) => Ok(d.to_path_buf()),
        None if cfg.exists() => Ok(Config::load(cfg).map_err(s)?.engine.rules_dir),
        None => Ok(Config::default().engine.rules_dir),
    }
}

pub fn keygen(dir: &Path) -> Res {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let (private, public) = signing::write_keypair(dir).map_err(s)?;
    println!("private key  {}  (mode 0600: keep it off this machine, or at least out of reach of the engine)", private.display());
    println!(
        "public key   {}  (install as /etc/ai-antivirus/rules.pub)",
        public.display()
    );
    println!(
        "then:  ai-antivirus rules-sign --key {}   and set engine.require_signed_rules = true",
        private.display()
    );
    Ok(())
}

pub fn rules_sign(cfg: &Path, dir: Option<&Path>, key: &Path) -> Res {
    let dir = rules_dir(cfg, dir)?;
    let m = signing::sign(&dir, key).map_err(s)?;
    println!("signed {} rule files in {}", m.files.len(), dir.display());
    Ok(())
}

pub fn rules_verify(cfg: &Path, dir: Option<&Path>, pubkey: Option<&Path>) -> Res {
    let pubkey = match pubkey {
        Some(p) => p.to_path_buf(),
        None if cfg.exists() => Config::load(cfg).map_err(s)?.engine.rules_pubkey,
        None => Config::default().engine.rules_pubkey,
    };
    let dir = rules_dir(cfg, dir)?;
    let m = signing::verify(&dir, &pubkey).map_err(s)?;
    println!(
        "signature OK: {} rule files in {} are exactly the signed ones",
        m.files.len(),
        dir.display()
    );
    Ok(())
}
