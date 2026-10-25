//! File quarantine (spec 8, level 4): the file is copied into `<state_dir>/quarantine/<action id>.bin` with mode 000,
//! checked to be the same file that was opened, and only then unlinked. Metadata goes into the action's undo record and
//! a `<id>.json` sidecar next to the copy (so a lost database does not lose the way back). Quarantined files are never
//! deleted automatically; restoring one puts it back with its owner, mode and modification time and never overwrites
//! whatever is at the path by then.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Everything needed to put a quarantined file back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Where the file was.
    pub path: String,
    /// File name of the copy inside the quarantine directory.
    pub stored: String,
    pub sha256: String,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_ns: u64,
    /// Other hard links to the same inode stay where they are; this says how many there were.
    pub nlink: u64,
}

fn err(kind: io::ErrorKind, msg: impl Into<String>) -> io::Error {
    io::Error::new(kind, msg.into())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Copy `src` into `dst`, returning the SHA-256 of what was copied.
fn copy_hashing(mut src: &File, dst: &mut File) -> io::Result<(String, u64)> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = buf.get(..n).unwrap_or(&[]);
        h.update(chunk);
        dst.write_all(chunk)?;
        total += n as u64;
    }
    dst.sync_all()?;
    Ok((hex(&h.finalize()), total))
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    io::copy(&mut f, &mut h)?;
    Ok(hex(&h.finalize()))
}

fn open_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_NONBLOCK)
        .open(path)
}

/// The quarantine directory, created `0700` when missing.
pub struct Quarantine {
    dir: PathBuf,
}

impl Quarantine {
    pub fn new(dir: impl Into<PathBuf>) -> Quarantine {
        Quarantine { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn ensure_dir(&self) -> io::Result<()> {
        match fs::DirBuilder::new().mode(0o700).create(&self.dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let m = fs::symlink_metadata(&self.dir)?;
                if !m.is_dir() {
                    return Err(err(
                        io::ErrorKind::InvalidInput,
                        format!("{} is not a directory", self.dir.display()),
                    ));
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Move `path` into quarantine as action `id`.
    pub fn put(&self, id: i64, path: &Path) -> io::Result<Record> {
        let path_str = path
            .to_str()
            .ok_or_else(|| err(io::ErrorKind::InvalidInput, "path is not UTF-8"))?
            .to_owned();
        let src = open_nofollow(path)?;
        let meta = src.metadata()?;
        if !meta.is_file() {
            return Err(err(
                io::ErrorKind::InvalidInput,
                format!("{path_str} is not a regular file"),
            ));
        }
        self.ensure_dir()?;
        let stored = format!("{id}.bin");
        let dst_path = self.dir.join(&stored);
        let mut dst = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o000)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&dst_path)?;
        let undo_copy = |e: io::Error| {
            let _ = fs::remove_file(&dst_path);
            e
        };
        let (sha256, size) = copy_hashing(&src, &mut dst).map_err(undo_copy)?;

        // the name must still point at the inode that was copied (not swapped for something else meanwhile)
        let now = fs::symlink_metadata(path).map_err(undo_copy)?;
        if now.dev() != meta.dev() || now.ino() != meta.ino() {
            return Err(undo_copy(err(
                io::ErrorKind::Other,
                format!("{path_str} was replaced while it was being quarantined"),
            )));
        }
        fs::remove_file(path).map_err(undo_copy)?;

        let rec = Record {
            path: path_str,
            stored,
            sha256,
            size,
            mode: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            mtime_ns: u64::try_from(meta.mtime()).unwrap_or(0) * 1_000_000_000
                + u64::try_from(meta.mtime_nsec()).unwrap_or(0),
            nlink: meta.nlink(),
        };
        // best effort: the database holds the same record
        if let Ok(json) = serde_json::to_vec_pretty(&rec) {
            let _ = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.dir.join(format!("{id}.json")))
                .and_then(|mut f| f.write_all(&json));
        }
        Ok(rec)
    }

    /// Put a quarantined file back where it was. Refuses when anything exists at the path now, when the copy's
    /// SHA-256 changed, or when the folder is gone.
    pub fn restore(&self, rec: &Record) -> io::Result<()> {
        let path = Path::new(&rec.path);
        if !path.is_absolute() || rec.stored.contains('/') {
            return Err(err(io::ErrorKind::InvalidInput, "bad quarantine record"));
        }
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(err(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists again; move it away first", rec.path),
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let stored = self.dir.join(&rec.stored);
        if sha256_file(&stored)? != rec.sha256 {
            return Err(err(
                io::ErrorKind::InvalidData,
                "the quarantined copy changed; not restoring it",
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| err(io::ErrorKind::InvalidInput, "no parent folder"))?;
        let name = path
            .file_name()
            .ok_or_else(|| err(io::ErrorKind::InvalidInput, "no file name"))?;
        let tmp = parent.join(format!(
            ".synapse-restore-{}-{}",
            rec.stored,
            name.to_string_lossy()
        ));
        let src = File::open(&stored)?;
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        let finish = (|| {
            copy_hashing(&src, &mut out)?;
            // owner first: chown clears setuid/setgid bits, the mode then sets them again
            if let Err(e) = std::os::unix::fs::fchown(&out, Some(rec.uid), Some(rec.gid)) {
                // an unprivileged restore (tests) keeps the caller as owner
                if e.kind() != io::ErrorKind::PermissionDenied {
                    return Err(e);
                }
            }
            out.set_permissions(fs::Permissions::from_mode(rec.mode & 0o7777))?;
            out.set_modified(UNIX_EPOCH + Duration::from_nanos(rec.mtime_ns))?;
            out.sync_all()?;
            // link, not rename: fails instead of replacing a file that appeared meanwhile
            fs::hard_link(&tmp, path)
        })();
        let _ = fs::remove_file(&tmp);
        finish?;
        let _ = fs::remove_file(&stored);
        let _ = fs::remove_file(
            self.dir
                .join(format!("{}.json", rec.stored.trim_end_matches(".bin"))),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_and_restore_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let q = Quarantine::new(dir.path().join("q"));
        let victim = dir.path().join("eicar.com");
        fs::write(&victim, b"X5O!P%@AP").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o751)).unwrap();
        let mtime = fs::metadata(&victim).unwrap().modified().unwrap();

        let rec = q.put(9, &victim).unwrap();
        assert!(!victim.exists());
        let stored = dir.path().join("q/9.bin");
        assert_eq!(fs::metadata(&stored).unwrap().mode() & 0o777, 0);
        assert_eq!(
            fs::metadata(dir.path().join("q")).unwrap().mode() & 0o777,
            0o700
        );
        assert!(dir.path().join("q/9.json").exists());
        assert_eq!(rec.size, 9);
        assert_eq!(rec.mode & 0o777, 0o751);

        // something new at the path blocks the restore
        fs::write(&victim, b"new").unwrap();
        assert_eq!(
            q.restore(&rec).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        fs::remove_file(&victim).unwrap();

        // stored copy is unreadable to its owner (mode 000) in an unprivileged test: make it readable to continue
        fs::set_permissions(&stored, fs::Permissions::from_mode(0o400)).unwrap();
        q.restore(&rec).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"X5O!P%@AP");
        let m = fs::metadata(&victim).unwrap();
        assert_eq!(m.mode() & 0o777, 0o751);
        assert_eq!(m.modified().unwrap(), mtime);
        assert!(!stored.exists());
        assert!(!dir.path().join("q/9.json").exists());
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            2,
            "no temp file left"
        );
    }

    #[test]
    fn refuses_symlinks_dirs_and_tampered_copies() {
        let dir = tempfile::tempdir().unwrap();
        let q = Quarantine::new(dir.path().join("q"));
        let target = dir.path().join("t");
        fs::write(&target, b"t").unwrap();
        let link = dir.path().join("l");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(q.put(1, &link).is_err(), "symlink not followed");
        assert!(target.exists() && link.exists());
        assert!(q.put(2, dir.path()).is_err(), "directory");

        let rec = q.put(3, &target).unwrap();
        let stored = dir.path().join("q/3.bin");
        fs::set_permissions(&stored, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&stored, b"tampered").unwrap();
        assert_eq!(
            q.restore(&rec).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!target.exists());
        assert!(q.put(3, &dir.path().join("missing")).is_err());
    }
}
