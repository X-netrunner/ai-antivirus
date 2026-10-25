//! Signed rule bundles (spec 10): the rules directory carries `bundle.manifest` (the SHA-256 of every rule file) and
//! `bundle.sig` (an ed25519 signature over the manifest). The engine verifies them at load, so a rule added, changed or
//! removed by anything that does not hold the signing key is refused. Approving an AI proposal adds a file, so it signs
//! the bundle again (`ai-antivirus approve-rule --key`).
//!
//! Covered: `behavior/**/*.toml` and `yara/*.yar|*.yara`. Anything else in the directory is ignored. The private key is
//! meant to live off the machine, or at least outside the engine's reach (root-only, mode 0600).

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

pub const MANIFEST: &str = "bundle.manifest";
pub const SIGNATURE: &str = "bundle.sig";
const MAX_FILE: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    /// Path relative to the rules directory -> SHA-256 (hex).
    pub files: BTreeMap<String, String>,
}

fn err(msg: impl Into<String>) -> Error {
    Error::Rules(vec![msg.into()])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hash_file(path: &Path) -> Result<String> {
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| Error::io(path, e))?;
    let meta = f.metadata().map_err(|e| Error::io(path, e))?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return Err(err(format!(
            "{}: not a regular file or too large",
            path.display()
        )));
    }
    let mut data = Vec::new();
    f.read_to_end(&mut data).map_err(|e| Error::io(path, e))?;
    Ok(hex(&Sha256::digest(&data)))
}

fn collect_into(
    base: &Path,
    dir: &Path,
    depth: u32,
    out: &mut BTreeMap<String, String>,
) -> Result<()> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::io(dir, e)),
    };
    for entry in rd {
        let entry = entry.map_err(|e| Error::io(dir, e))?;
        let path = entry.path();
        let ft = entry.file_type().map_err(|e| Error::io(&path, e))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if ft.is_dir() {
            if depth < 4 {
                collect_into(base, &path, depth + 1, out)?;
            }
            continue;
        }
        let covered = name.ends_with(".toml") || name.ends_with(".yar") || name.ends_with(".yara");
        if !covered {
            continue;
        }
        if !ft.is_file() {
            return Err(err(format!(
                "{}: a rule file must be a regular file (symlinks are refused)",
                path.display()
            )));
        }
        let rel = path
            .strip_prefix(base)
            .map_err(|_| err("path outside the rules directory"))?;
        out.insert(rel.to_string_lossy().into_owned(), hash_file(&path)?);
    }
    Ok(())
}

/// The manifest for what is in `rules_dir` now.
pub fn collect(rules_dir: &Path) -> Result<Manifest> {
    let mut files = BTreeMap::new();
    collect_into(rules_dir, &rules_dir.join("behavior"), 0, &mut files)?;
    collect_into(rules_dir, &rules_dir.join("yara"), 0, &mut files)?;
    Ok(Manifest { version: 1, files })
}

/// A new key pair from the system's random source: (private key hex, public key hex).
pub fn generate_key() -> Result<(String, String)> {
    let mut seed = [0u8; 32];
    let p = Path::new("/dev/urandom");
    fs::File::open(p)
        .and_then(|mut f| f.read_exact(&mut seed))
        .map_err(|e| Error::io(p, e))?;
    let sk = SigningKey::from_bytes(&seed);
    Ok((hex(&seed), hex(sk.verifying_key().as_bytes())))
}

fn read_key_file(path: &Path) -> Result<[u8; 32]> {
    let text = fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    let bytes = unhex(&text).ok_or_else(|| err(format!("{}: not a hex key", path.display())))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        err(format!(
            "{}: a key is 32 bytes (64 hex digits)",
            path.display()
        ))
    })
}

/// Write the private and public key files (`<dir>/rules-signing.key` mode 0600, `<dir>/rules.pub` mode 0644).
pub fn write_keypair(dir: &Path) -> Result<(PathBuf, PathBuf)> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let (private, public) = generate_key()?;
    let (kp, pp) = (dir.join("rules-signing.key"), dir.join("rules.pub"));
    for (path, text, mode) in [(&kp, private, 0o600), (&pp, public, 0o644)] {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .map_err(|e| Error::io(path, e))?;
        writeln!(f, "{text}").map_err(|e| Error::io(path, e))?;
        f.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| Error::io(path, e))?;
    }
    Ok((kp, pp))
}

/// Sign what is in `rules_dir` now: writes `bundle.manifest` and `bundle.sig`.
pub fn sign(rules_dir: &Path, key_file: &Path) -> Result<Manifest> {
    let sk = SigningKey::from_bytes(&read_key_file(key_file)?);
    let manifest = collect(rules_dir)?;
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| err(e.to_string()))?;
    let sig = sk.sign(&bytes);
    for (name, content) in [
        (MANIFEST, bytes),
        (
            SIGNATURE,
            format!("{}\n", hex(&sig.to_bytes())).into_bytes(),
        ),
    ] {
        let (path, tmp) = (rules_dir.join(name), rules_dir.join(format!(".{name}.new")));
        fs::write(&tmp, content).map_err(|e| Error::io(&tmp, e))?;
        fs::rename(&tmp, &path).map_err(|e| Error::io(&path, e))?;
    }
    Ok(manifest)
}

/// Check the signature and that the files on disk are exactly the signed ones. All differences are reported.
pub fn verify(rules_dir: &Path, pubkey_file: &Path) -> Result<Manifest> {
    let vk = VerifyingKey::from_bytes(&read_key_file(pubkey_file)?)
        .map_err(|e| err(format!("bad public key: {e}")))?;
    let (mp, sp) = (rules_dir.join(MANIFEST), rules_dir.join(SIGNATURE));
    let bytes = fs::read(&mp).map_err(|e| Error::io(&mp, e))?;
    let sig_hex = fs::read_to_string(&sp).map_err(|e| Error::io(&sp, e))?;
    let sig_bytes = unhex(&sig_hex).ok_or_else(|| err("the signature is not hex"))?;
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|_| err("the signature has the wrong length"))?;
    vk.verify(&bytes, &sig).map_err(|_| {
        err("the signature does not match the manifest (wrong key, or the manifest was changed)")
    })?;
    let signed: Manifest =
        serde_json::from_slice(&bytes).map_err(|e| err(format!("manifest: {e}")))?;
    if signed.version != 1 {
        return Err(err(format!("unknown manifest version {}", signed.version)));
    }
    let now = collect(rules_dir)?;
    let mut problems = Vec::new();
    for (path, hash) in &signed.files {
        match now.files.get(path) {
            None => problems.push(format!("{path}: signed but missing")),
            Some(h) if h != hash => problems.push(format!("{path}: changed since it was signed")),
            Some(_) => {}
        }
    }
    for path in now.files.keys() {
        if !signed.files.contains_key(path) {
            problems.push(format!("{path}: not signed"));
        }
    }
    if problems.is_empty() {
        Ok(signed)
    } else {
        Err(Error::Rules(problems))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_dir() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let r = d.path().join("rules");
        fs::create_dir_all(r.join("behavior/local")).unwrap();
        fs::create_dir_all(r.join("yara")).unwrap();
        fs::write(r.join("behavior/a.toml"), "# a\n").unwrap();
        fs::write(r.join("behavior/local/b.toml"), "# b\n").unwrap();
        fs::write(r.join("yara/c.yar"), "// c\n").unwrap();
        fs::write(r.join("README.txt"), "not covered").unwrap();
        (d, r)
    }

    #[test]
    fn a_signed_bundle_verifies_and_every_kind_of_change_is_caught() {
        let (d, r) = rules_dir();
        let (key, public) = write_keypair(d.path()).unwrap();
        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let m = sign(&r, &key).unwrap();
        assert_eq!(m.files.len(), 3);
        assert!(verify(&r, &public).is_ok());

        // an uncovered file is ignored
        fs::write(r.join("README.txt"), "edited").unwrap();
        assert!(verify(&r, &public).is_ok());

        // an edit, an added rule, a removed rule, an added YARA file
        fs::write(r.join("behavior/a.toml"), "# a, edited\n").unwrap();
        let Err(Error::Rules(p)) = verify(&r, &public) else {
            panic!("edit accepted")
        };
        assert_eq!(p, ["behavior/a.toml: changed since it was signed"]);
        fs::write(r.join("behavior/a.toml"), "# a\n").unwrap();
        fs::write(r.join("behavior/local/evil.toml"), "# x\n").unwrap();
        let Err(Error::Rules(p)) = verify(&r, &public) else {
            panic!("added rule accepted")
        };
        assert_eq!(p, ["behavior/local/evil.toml: not signed"]);
        fs::remove_file(r.join("behavior/local/evil.toml")).unwrap();
        fs::remove_file(r.join("behavior/local/b.toml")).unwrap();
        let Err(Error::Rules(p)) = verify(&r, &public) else {
            panic!("removal accepted")
        };
        assert_eq!(p, ["behavior/local/b.toml: signed but missing"]);
        fs::write(r.join("behavior/local/b.toml"), "# b\n").unwrap();
        fs::write(r.join("yara/z.yara"), "// z").unwrap();
        assert!(verify(&r, &public).is_err());
    }

    #[test]
    fn a_forged_manifest_or_the_wrong_key_is_refused() {
        let (d, r) = rules_dir();
        let (key, public) = write_keypair(d.path()).unwrap();
        sign(&r, &key).unwrap();
        // the attacker adds a rule and rewrites the manifest to match, but cannot sign it
        fs::write(r.join("behavior/evil.toml"), "# x\n").unwrap();
        let mut m = collect(&r).unwrap();
        m.version = 1;
        fs::write(r.join(MANIFEST), serde_json::to_vec_pretty(&m).unwrap()).unwrap();
        let Err(Error::Rules(p)) = verify(&r, &public) else {
            panic!("forged manifest accepted")
        };
        assert!(p[0].contains("signature does not match"), "{p:?}");
        // a signature from another key
        let other = tempfile::tempdir().unwrap();
        let (other_key, _) = write_keypair(other.path()).unwrap();
        sign(&r, &other_key).unwrap();
        assert!(verify(&r, &public).is_err());
        // garbage signature, missing files
        fs::write(r.join(SIGNATURE), "zz").unwrap();
        assert!(verify(&r, &public).is_err());
        fs::remove_file(r.join(SIGNATURE)).unwrap();
        assert!(verify(&r, &public).is_err());
    }

    #[test]
    fn symlinked_rule_files_are_refused_and_keys_are_not_overwritten() {
        let (d, r) = rules_dir();
        std::os::unix::fs::symlink("/etc/passwd", r.join("behavior/link.toml")).unwrap();
        assert!(collect(&r).is_err());
        let keys = tempfile::tempdir().unwrap();
        write_keypair(keys.path()).unwrap();
        assert!(
            write_keypair(keys.path()).is_err(),
            "an existing key is never replaced"
        );
        let _ = d;
    }

    use std::os::unix::fs::PermissionsExt;
}
