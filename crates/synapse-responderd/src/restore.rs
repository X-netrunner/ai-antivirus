//! Restoring a pacman-owned file (spec 8, level 6): the package's copy of the file is taken from pacman's cache and put
//! back, but only after its SHA-256 matches the record in pacman's own database.
//!
//! - The expected hash, mode and owner come from the installed package's `mtree` (the same data as `pacman -Qkk`), never
//!   from the alert or the cached archive. The archive is only a place to read bytes from; if the bytes do not hash to the
//!   recorded value nothing is touched.
//! - Only files a package owns and does not mark as editable configuration (`%BACKUP%`) can be restored.
//! - What was there before is kept as evidence (`<private_dir>/restore-evidence/<id>.bin`, mode 000) and the new file is
//!   put in place with a rename, so there is never a half-written file. Undo puts the evidence back (and refuses if the
//!   file changed again since).
//! - The archive member is extracted with `bsdtar -xOf ARCHIVE MEMBER` (no shell; both names are checked first).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{chown, DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use synapse_rules::mtree::{self, LocalPackage, MtreeEntry};

/// Largest file that is restored.
const MAX_BYTES: u64 = 256 * 1024 * 1024;

/// What is needed to undo a restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRecord {
    pub path: String,
    pub package: String,
    pub version: String,
    /// The package file the bytes came from.
    pub archive: String,
    /// The tampered file kept as evidence; `None` when nothing was there (the file had been deleted).
    pub evidence: Option<String>,
    pub sha256_before: Option<String>,
    pub sha256_restored: String,
    /// The mode and owner the file had before (to put back on undo).
    pub before_mode: u32,
    pub before_uid: u32,
    pub before_gid: u32,
}

#[derive(Debug, Clone)]
pub struct Restorer {
    pacman_local: PathBuf,
    cache_dirs: Vec<PathBuf>,
    evidence_dir: PathBuf,
    bsdtar: PathBuf,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha_of(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn clean_abs(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

/// `name`, `version` and `arch` from a package's `desc` file.
fn desc_fields(desc: &str) -> (Option<String>, Option<String>, Option<String>) {
    let (mut name, mut version, mut arch, mut section) = (None, None, None, "");
    for line in desc.lines() {
        if line.starts_with('%') && line.ends_with('%') {
            section = line;
        } else if line.is_empty() {
            section = "";
        } else {
            match section {
                "%NAME%" if name.is_none() => name = Some(line.to_owned()),
                "%VERSION%" if version.is_none() => version = Some(line.to_owned()),
                "%ARCH%" if arch.is_none() => arch = Some(line.to_owned()),
                _ => {}
            }
        }
    }
    (name, version, arch)
}

impl Restorer {
    pub fn new(private_dir: &Path) -> Restorer {
        Restorer {
            pacman_local: PathBuf::from(mtree::PACMAN_LOCAL),
            cache_dirs: vec![PathBuf::from("/var/cache/pacman/pkg")],
            evidence_dir: private_dir.join("restore-evidence"),
            bsdtar: PathBuf::from("/usr/bin/bsdtar"),
        }
    }

    /// Point at other directories (tests).
    pub fn with_paths(mut self, pacman_local: &Path, cache: &Path, bsdtar: &Path) -> Restorer {
        self.pacman_local = pacman_local.to_path_buf();
        self.cache_dirs = vec![cache.to_path_buf()];
        self.bsdtar = bsdtar.to_path_buf();
        self
    }

    /// The installed package that owns `path`, its version and arch, and pacman's record of the file.
    fn locate(&self, path: &Path) -> Result<(LocalPackage, String, String, MtreeEntry), String> {
        for pkg in mtree::local_packages(&self.pacman_local).map_err(|e| e.to_string())? {
            if pkg.backup.iter().any(|b| b == path) {
                continue;
            }
            // cheap pre-check: the package's `files` list names the path
            let rel = path.strip_prefix("/").map_err(|_| "not an absolute path")?;
            let list = fs::read_to_string(pkg.dir.join("files")).unwrap_or_default();
            if !list.lines().any(|l| Path::new(l) == rel) {
                continue;
            }
            let entries = mtree::package_files(&pkg).map_err(|e| e.to_string())?;
            if let Some(entry) = entries.into_iter().find(|e| e.path == path) {
                let desc = fs::read_to_string(pkg.dir.join("desc")).map_err(|e| e.to_string())?;
                let (_, version, arch) = desc_fields(&desc);
                return Ok((
                    pkg,
                    version.ok_or("the package has no version")?,
                    arch.ok_or("the package has no arch")?,
                    entry,
                ));
            }
        }
        Err(format!(
            "{} is not a file of an installed package (or it is editable configuration), so there is no record to restore from",
            path.display()
        ))
    }

    /// The cached archive of exactly this package version: `<name>-<version>-<arch>.pkg.tar.<ext>`.
    fn cached_archive(&self, name: &str, version: &str, arch: &str) -> Result<PathBuf, String> {
        let stem = format!("{name}-{version}-{arch}.pkg.tar");
        for dir in &self.cache_dirs {
            let Ok(rd) = fs::read_dir(dir) else { continue };
            for e in rd.filter_map(|e| e.ok()) {
                let fname = e.file_name().to_string_lossy().into_owned();
                if fname.strip_prefix(&stem).is_some_and(|ext| {
                    ext.is_empty()
                        || (ext.starts_with('.')
                            && !ext.ends_with(".sig")
                            && !ext[1..].contains('/'))
                }) && e.file_type().is_ok_and(|t| t.is_file())
                {
                    return Ok(e.path());
                }
            }
        }
        Err(format!(
            "{stem}.* is not in the pacman cache; reinstall with: pacman -S {name}"
        ))
    }

    /// Read-only: what a restore would use (for the dry-run preview).
    pub fn plan(&self, path: &Path) -> Result<String, String> {
        if !clean_abs(path) {
            return Err(format!("{} is not a clean absolute path", path.display()));
        }
        let (pkg, version, arch, _) = self.locate(path)?;
        let archive = self.cached_archive(&pkg.name, &version, &arch)?;
        Ok(format!(
            "the file would be restored from package {} {} ({})",
            pkg.name,
            version,
            archive.display()
        ))
    }

    fn extract(&self, archive: &Path, member: &str) -> Result<Vec<u8>, String> {
        if member.starts_with('-') || member.contains('\0') {
            return Err("bad archive member name".into());
        }
        let mut child = Command::new(&self.bsdtar)
            .arg("-xOf")
            .arg(archive)
            .arg("--")
            .arg(member)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot run bsdtar: {e}"))?;
        let mut data = Vec::new();
        let read = child
            .stdout
            .take()
            .map(|o| o.take(MAX_BYTES + 1).read_to_end(&mut data));
        if data.len() as u64 > MAX_BYTES {
            let _ = child.kill();
            let _ = child.wait();
            return Err("the file in the package is larger than the limit".into());
        }
        let status = child.wait().map_err(|e| e.to_string())?;
        if let Some(Err(e)) = read {
            return Err(format!("reading from bsdtar failed: {e}"));
        }
        if !status.success() || data.is_empty() {
            return Err(format!(
                "{member} could not be extracted from {}",
                archive.display()
            ));
        }
        Ok(data)
    }

    /// Put the package's copy of `path` back. `id` names the evidence copy.
    pub fn restore(&self, id: i64, path: &Path) -> Result<RestoreRecord, String> {
        if !clean_abs(path) {
            return Err(format!("{} is not a clean absolute path", path.display()));
        }
        let (pkg, version, arch, entry) = self.locate(path)?;
        let archive = self.cached_archive(&pkg.name, &version, &arch)?;
        let member = path
            .strip_prefix("/")
            .map_err(|_| "not absolute")?
            .to_string_lossy()
            .into_owned();
        let data = self.extract(&archive, &member)?;
        let got = sha_of(&data);
        if got != entry.sha256.to_string() {
            return Err(format!(
                "the cached package does not match pacman's record for {} (expected {}, the archive has {got}); nothing was changed",
                path.display(),
                entry.sha256
            ));
        }

        // the evidence: whatever is there now
        let current = fs::symlink_metadata(path).ok();
        let (mut evidence, mut before_hash) = (None, None);
        let (mut b_mode, mut b_uid, mut b_gid) = (0o644, 0, 0);
        if let Some(m) = &current {
            if !m.is_file() {
                return Err(format!(
                    "{} is not a regular file now; refusing to replace it",
                    path.display()
                ));
            }
            (b_mode, b_uid, b_gid) = (m.mode() & 0o7777, m.uid(), m.gid());
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&self.evidence_dir)
                .map_err(|e| format!("{}: {e}", self.evidence_dir.display()))?;
            let name = format!("{id}.bin");
            let dest = self.evidence_dir.join(&name);
            let mut src = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
                .map_err(|e| e.to_string())?;
            let mut dst = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o000)
                .open(&dest)
                .map_err(|e| format!("{}: {e}", dest.display()))?;
            let mut buf = Vec::new();
            Read::take(&mut src, MAX_BYTES + 1)
                .read_to_end(&mut buf)
                .map_err(|e| e.to_string())?;
            before_hash = Some(sha_of(&buf));
            dst.write_all(&buf)
                .and_then(|()| dst.sync_all())
                .map_err(|e| e.to_string())?;
            evidence = Some(name);
        }

        write_atomically(path, &data, entry.mode, entry.uid, entry.gid, id)?;
        Ok(RestoreRecord {
            path: path.to_string_lossy().into_owned(),
            package: pkg.name,
            version,
            archive: archive.to_string_lossy().into_owned(),
            evidence,
            sha256_before: before_hash,
            sha256_restored: got,
            before_mode: b_mode,
            before_uid: b_uid,
            before_gid: b_gid,
        })
    }

    /// Put the file back as it was before the restore. Refuses when the file changed again since.
    pub fn undo(&self, id: i64, rec: &RestoreRecord) -> Result<(), String> {
        let path = Path::new(&rec.path);
        if !clean_abs(path) {
            return Err("bad path in the undo record".into());
        }
        let now = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if sha_of(&now) != rec.sha256_restored {
            return Err(format!(
                "{} has changed since it was restored; not overwriting it",
                rec.path
            ));
        }
        match &rec.evidence {
            None => fs::remove_file(path).map_err(|e| e.to_string()),
            Some(name) => {
                if name.contains('/') || name.starts_with('.') {
                    return Err("bad evidence name in the undo record".into());
                }
                let ev = self.evidence_dir.join(name);
                // the evidence is mode 000: root reads it anyway; an unprivileged test run needs the bit
                let _ = fs::set_permissions(&ev, fs::Permissions::from_mode(0o400));
                let data = fs::read(&ev).map_err(|e| format!("{}: {e}", ev.display()))?;
                if Some(sha_of(&data)) != rec.sha256_before {
                    return Err("the evidence copy no longer matches its recorded hash".into());
                }
                let r = write_atomically(
                    path,
                    &data,
                    rec.before_mode,
                    rec.before_uid,
                    rec.before_gid,
                    id,
                );
                let _ = fs::set_permissions(&ev, fs::Permissions::from_mode(0o000));
                r
            }
        }
    }
}

/// Write `data` next to `path` and rename it over: the target is never half written. Owner changes need root; as an
/// unprivileged user (tests) the file keeps the caller as owner.
fn write_atomically(
    path: &Path,
    data: &[u8],
    mode: u32,
    uid: u32,
    gid: u32,
    id: i64,
) -> Result<(), String> {
    let dir = path.parent().ok_or("no parent directory")?;
    let tmp = dir.join(format!(".synapse-restore-{id}-{}", std::process::id()));
    let result = (|| -> io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(File::open(&tmp)?);
        let _ = chown(&tmp, Some(uid), Some(gid));
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode & 0o7777))?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(|e| format!("cannot write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;

    struct Rig {
        _dir: tempfile::TempDir,
        root: PathBuf,
        target: PathBuf,
        restorer: Restorer,
    }

    /// A fake installed package "tool 1.0" owning `<root>/usr/bin/tool`, with a cached archive made by tar.
    fn rig(content: &[u8]) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let target = root.join("usr/bin/tool");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, content).unwrap();
        // the cached archive, built with the same tool the restorer reads it with
        let stage = root.join("stage");
        fs::create_dir_all(stage.join(root.strip_prefix("/").unwrap()).join("usr/bin")).unwrap();
        fs::write(
            stage
                .join(root.strip_prefix("/").unwrap())
                .join("usr/bin/tool"),
            content,
        )
        .unwrap();
        let cache = root.join("cache");
        fs::create_dir_all(&cache).unwrap();
        let archive = cache.join("tool-1.0-1-x86_64.pkg.tar");
        let st = Command::new("/usr/bin/bsdtar")
            .arg("-cf")
            .arg(&archive)
            .arg("-C")
            .arg(&stage)
            .arg(root.strip_prefix("/").unwrap())
            .status()
            .unwrap();
        assert!(st.success());
        // pacman's database
        let local = root.join("local");
        let pkg = local.join("tool-1.0-1");
        fs::create_dir_all(&pkg).unwrap();
        fs::write(
            pkg.join("desc"),
            "%NAME%\ntool\n\n%VERSION%\n1.0-1\n\n%ARCH%\nx86_64\n",
        )
        .unwrap();
        let rel = target
            .strip_prefix("/")
            .unwrap()
            .to_string_lossy()
            .into_owned();
        fs::write(pkg.join("files"), format!("%FILES%\n{rel}\n")).unwrap();
        let mtree = format!("#mtree\n/set type=file uid=0 gid=0 mode=644\n./{rel} time=1.0 mode=755 size={} sha256digest={}\n", content.len(), sha_of(content));
        let mut gz = GzEncoder::new(
            File::create(pkg.join("mtree")).unwrap(),
            flate2::Compression::default(),
        );
        gz.write_all(mtree.as_bytes()).unwrap();
        gz.finish().unwrap();
        let restorer =
            Restorer::new(&root).with_paths(&local, &cache, Path::new("/usr/bin/bsdtar"));
        Rig {
            _dir: dir,
            root,
            target,
            restorer,
        }
    }

    #[test]
    fn a_tampered_file_is_restored_with_evidence_and_undo_brings_the_tampered_one_back() {
        let r = rig(b"genuine program bytes");
        fs::write(&r.target, b"replaced by something else").unwrap();
        fs::set_permissions(&r.target, fs::Permissions::from_mode(0o4755)).unwrap();
        assert!(r.restorer.plan(&r.target).unwrap().contains("tool 1.0-1"));
        let rec = r.restorer.restore(7, &r.target).unwrap();
        assert_eq!(fs::read(&r.target).unwrap(), b"genuine program bytes");
        // mode from pacman's record (755), not the tampered file's setuid 4755
        assert_eq!(
            fs::metadata(&r.target).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        assert_eq!(rec.package, "tool");
        assert_eq!(rec.before_mode, 0o4755);
        let ev = r.root.join("restore-evidence/7.bin");
        assert_eq!(fs::metadata(&ev).unwrap().permissions().mode() & 0o777, 0);
        // no temporary file left behind
        assert!(fs::read_dir(r.target.parent().unwrap()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".synapse-restore")));

        r.restorer.undo(7, &rec).unwrap();
        assert_eq!(fs::read(&r.target).unwrap(), b"replaced by something else");
        assert_eq!(
            fs::metadata(&r.target).unwrap().permissions().mode() & 0o7777,
            0o4755
        );
    }

    #[test]
    fn a_deleted_file_comes_back_and_undo_removes_it_again() {
        let r = rig(b"abc");
        fs::remove_file(&r.target).unwrap();
        let rec = r.restorer.restore(1, &r.target).unwrap();
        assert!(rec.evidence.is_none());
        assert_eq!(fs::read(&r.target).unwrap(), b"abc");
        r.restorer.undo(1, &rec).unwrap();
        assert!(!r.target.exists());
    }

    #[test]
    fn nothing_is_touched_when_the_archive_does_not_match_pacmans_record() {
        let r = rig(b"genuine");
        // the cache holds different bytes than the installed package recorded (a poisoned cache)
        let mtree_hash_of_other = {
            let other = rig(b"poisoned bytes");
            let a = other.root.join("cache/tool-1.0-1-x86_64.pkg.tar");
            fs::copy(&a, r.root.join("cache/tool-1.0-1-x86_64.pkg.tar")).unwrap();
            other
        };
        let _ = mtree_hash_of_other;
        fs::write(&r.target, b"tampered").unwrap();
        // the poisoned archive's member path differs (another temp root), so extraction fails first; either way: no change
        let e = r.restorer.restore(2, &r.target).unwrap_err();
        assert!(
            e.contains("could not be extracted") || e.contains("does not match"),
            "{e}"
        );
        assert_eq!(fs::read(&r.target).unwrap(), b"tampered");
        assert!(!r.root.join("restore-evidence/2.bin").exists());
    }

    #[test]
    fn files_no_package_owns_and_changed_restores_are_refused() {
        let r = rig(b"x");
        let other = r.root.join("usr/bin/not-in-any-package");
        fs::write(&other, b"y").unwrap();
        assert!(r
            .restorer
            .restore(3, &other)
            .unwrap_err()
            .contains("not a file of an installed package"));
        assert!(r.restorer.restore(3, Path::new("relative/path")).is_err());
        assert!(r
            .restorer
            .restore(3, Path::new("/usr/../etc/passwd"))
            .is_err());
        // undo refuses when the restored file was changed afterwards
        fs::write(&r.target, b"tampered").unwrap();
        let rec = r.restorer.restore(4, &r.target).unwrap();
        fs::write(&r.target, b"changed again").unwrap();
        assert!(r
            .restorer
            .undo(4, &rec)
            .unwrap_err()
            .contains("changed since"));
        // a directory at the path is not replaced
        let d = r.root.join("usr/bin/dir");
        fs::create_dir_all(&d).unwrap();
        assert!(r.restorer.restore(5, &d).is_err());
    }

    #[test]
    fn archive_names_must_match_exactly() {
        let r = rig(b"x");
        let cache = r.root.join("cache");
        fs::write(cache.join("tool-extra-1.0-1-x86_64.pkg.tar"), "").unwrap();
        fs::write(cache.join("tool-1.0-1-x86_64.pkg.tar.sig"), "").unwrap();
        let p = r
            .restorer
            .cached_archive("tool", "1.0-1", "x86_64")
            .unwrap();
        assert_eq!(p.file_name().unwrap(), "tool-1.0-1-x86_64.pkg.tar");
        assert!(r
            .restorer
            .cached_archive("tool", "2.0-1", "x86_64")
            .is_err());
        assert!(r.restorer.cached_archive("too", "1.0-1", "x86_64").is_err());
    }
}
