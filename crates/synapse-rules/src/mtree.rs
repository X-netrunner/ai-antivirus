//! Layer L0: what pacman says a package's files should be.
//!
//! pacman keeps, per installed package, `/var/lib/pacman/local/<name>-<version>/desc` (with `%NAME%`) and `mtree` (gzip,
//! BSD mtree format) with each file's size, modification time and SHA-256. Reading these files directly gives the same data
//! as libalpm without linking against it: the `alpm` crate must match the installed libalpm version exactly, and a rolling
//! pacman upgrade would then break Synapse at the worst moment (spec 7: a file whose hash matches its package is trusted).

use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use synapse_common::event::Sha256;

use crate::{Error, Result};

pub const PACMAN_LOCAL: &str = "/var/lib/pacman/local";
pub const PACMAN_LOCK: &str = "/var/lib/pacman/db.lck";

/// Most files accepted from one package's mtree (the largest Arch packages have well under this).
const MAX_ENTRIES_PER_PACKAGE: usize = 500_000;

/// One regular file of a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtreeEntry {
    pub path: PathBuf,
    pub size: u64,
    /// Whole seconds (mtree has fractions; file systems compare on seconds here).
    pub mtime_s: i64,
    pub sha256: Sha256,
    /// Permission bits as pacman installed them (octal in the file; 0o644 when the entry says nothing).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

/// An installed package's name and its database directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPackage {
    pub name: String,
    pub dir: PathBuf,
    /// `%BACKUP%` files: configuration the package expects you to edit (`/etc/pacman.conf`). They are not trust material.
    pub backup: Vec<PathBuf>,
}

/// The first line of section `%NAME%` and the paths of section `%BACKUP%` in a pacman database file (`desc` has the name,
/// `files` the backup list).
fn parse_sections(desc: &str) -> (Option<String>, Vec<PathBuf>) {
    let (mut name, mut backup, mut section) = (None, Vec::new(), "");
    for line in desc.lines() {
        if line.starts_with('%') && line.ends_with('%') {
            section = line;
            continue;
        }
        if line.is_empty() {
            section = "";
            continue;
        }
        match section {
            "%NAME%" if name.is_none() => name = Some(line.to_owned()),
            // `etc/pacman.conf\t<md5>`
            "%BACKUP%" => {
                if let Some(p) = line.split('\t').next().filter(|p| !p.is_empty()) {
                    backup.push(Path::new("/").join(p));
                }
            }
            _ => {}
        }
    }
    (name, backup)
}

/// Every installed package (sorted by name).
pub fn local_packages(local: &Path) -> Result<Vec<LocalPackage>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(local).map_err(|e| Error::io(local, e))? {
        let entry = entry.map_err(|e| Error::io(local, e))?;
        let dir = entry.path();
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Ok(desc) = fs::read_to_string(dir.join("desc")) else {
            continue;
        };
        let (name, _) = parse_sections(&desc);
        let backup = fs::read_to_string(dir.join("files"))
            .map(|f| parse_sections(&f).1)
            .unwrap_or_default();
        if let Some(name) = name.filter(|n| !n.is_empty()) {
            out.push(LocalPackage { name, dir, backup });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// mtree escapes bytes as `\ooo` (three octal digits); `\\` is a backslash.
fn unescape(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            if b.get(i + 1) == Some(&b'\\') {
                out.push(b'\\');
                i += 2;
                continue;
            }
            let oct = b.get(i + 1..i + 4)?;
            if !oct.iter().all(|c| (b'0'..=b'7').contains(c)) {
                return None;
            }
            let v = oct
                .iter()
                .fold(0u32, |acc, c| acc * 8 + u32::from(c - b'0'));
            out.push(u8::try_from(v).ok()?);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

/// Parse the (already decompressed) text of an mtree file. Only regular files with a SHA-256 are returned; pacman's own
/// metadata entries (`./.PKGINFO`, `./.BUILDINFO`, `./.INSTALL`, `./.MTREE`, `./.CHANGELOG`) are skipped.
pub fn parse_mtree<R: BufRead>(reader: R) -> Result<Vec<MtreeEntry>> {
    let mut defaults_type = String::new();
    let (mut def_mode, mut def_uid, mut def_gid) = (0o644u32, 0u32, 0u32);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|e| Error::Mtree(e.to_string()))?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        let Some(first) = fields.next() else { continue };
        if first == "/set" {
            for kv in fields {
                if let Some(t) = kv.strip_prefix("type=") {
                    defaults_type = t.to_owned();
                } else if let Some(v) = kv.strip_prefix("mode=") {
                    def_mode = u32::from_str_radix(v, 8).unwrap_or(def_mode);
                } else if let Some(v) = kv.strip_prefix("uid=") {
                    def_uid = v.parse().unwrap_or(def_uid);
                } else if let Some(v) = kv.strip_prefix("gid=") {
                    def_gid = v.parse().unwrap_or(def_gid);
                }
            }
            continue;
        }
        if first.starts_with('/') {
            continue; // /unset and other directives
        }
        let Some(rel) = first.strip_prefix("./") else {
            continue;
        };
        if rel.starts_with('.') && !rel.contains('/') {
            continue;
        }
        let (mut kind, mut size, mut time, mut sha) = (defaults_type.clone(), None, None, None);
        let (mut mode, mut uid, mut gid) = (def_mode, def_uid, def_gid);
        for kv in fields {
            let Some((k, v)) = kv.split_once('=') else {
                continue;
            };
            match k {
                "type" => kind = v.to_owned(),
                "size" => size = v.parse::<u64>().ok(),
                "time" => time = v.split('.').next().and_then(|s| s.parse::<i64>().ok()),
                "sha256digest" => sha = v.parse::<Sha256>().ok(),
                "mode" => mode = u32::from_str_radix(v, 8).unwrap_or(mode),
                "uid" => uid = v.parse().unwrap_or(uid),
                "gid" => gid = v.parse().unwrap_or(gid),
                _ => {}
            }
        }
        if kind != "file" {
            continue;
        }
        let (Some(size), Some(mtime_s), Some(sha256)) = (size, time, sha) else {
            continue;
        };
        let Some(bytes) = unescape(rel) else { continue };
        let mut path = b"/".to_vec();
        path.extend_from_slice(&bytes);
        out.push(MtreeEntry {
            path: PathBuf::from(std::ffi::OsString::from_vec(path)),
            size,
            mtime_s,
            sha256,
            mode,
            uid,
            gid,
        });
        if out.len() > MAX_ENTRIES_PER_PACKAGE {
            return Err(Error::Mtree(format!(
                "more than {MAX_ENTRIES_PER_PACKAGE} entries"
            )));
        }
    }
    Ok(out)
}

/// The file entries of one installed package, without its `%BACKUP%` (editable configuration) files.
pub fn package_files(pkg: &LocalPackage) -> Result<Vec<MtreeEntry>> {
    let p = pkg.dir.join("mtree");
    let f = File::open(&p).map_err(|e| Error::io(&p, e))?;
    let mut entries = parse_mtree(BufReader::new(GzDecoder::new(f))).map_err(|e| match e {
        Error::Mtree(m) => Error::Mtree(format!("{}: {m}", p.display())),
        other => other,
    })?;
    entries.retain(|e| !pkg.backup.contains(&e.path));
    Ok(entries)
}

/// A pacman transaction is running (its lock file exists).
pub fn pacman_active() -> bool {
    Path::new(PACMAN_LOCK).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use std::io::Write;

    const SAMPLE: &str = "#mtree
/set type=file uid=0 gid=0 mode=644
./.BUILDINFO time=1700000000.0 size=5000 sha256digest=0000000000000000000000000000000000000000000000000000000000000000
./.PKGINFO time=1700000000.0 size=500 sha256digest=0000000000000000000000000000000000000000000000000000000000000000
./usr time=1700000000.0 mode=755 type=dir
./usr/bin/bash time=1700000123.5 mode=755 size=1112880 md5digest=x sha256digest=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
./usr/bin/sh time=1700000123.0 mode=777 type=link link=bash
./usr/share/doc/a\\040file time=1700000000.0 size=3 sha256digest=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
./usr/share/x time=1700000000.0 size=3
";

    #[test]
    fn files_with_digests_are_read_and_the_rest_skipped() {
        let e = parse_mtree(SAMPLE.as_bytes()).unwrap();
        assert_eq!(e.len(), 2, "{e:?}");
        assert_eq!(e[0].path, PathBuf::from("/usr/bin/bash"));
        assert_eq!(e[0].size, 1_112_880);
        assert_eq!(e[0].mtime_s, 1_700_000_123);
        assert_eq!((e[0].mode, e[0].uid, e[0].gid), (0o755, 0, 0));
        assert_eq!(e[1].mode, 0o644, "the /set default applies");
        assert_eq!(e[1].path, PathBuf::from("/usr/share/doc/a file"));
    }

    #[test]
    fn escapes() {
        assert_eq!(unescape("a\\040b").unwrap(), b"a b");
        assert_eq!(unescape("a\\\\b").unwrap(), b"a\\b");
        assert!(unescape("a\\9xx").is_none());
        assert!(unescape("a\\04").is_none());
    }

    #[test]
    fn a_fake_local_database_reads_like_pacman_s() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("bash-5.3-1");
        fs::create_dir(&pkg).unwrap();
        fs::write(pkg.join("desc"), "%NAME%\nbash\n\n%VERSION%\n5.3-1\n").unwrap();
        fs::write(
            pkg.join("files"),
            "%FILES%\nusr/\nusr/bin/bash\n\n%BACKUP%\nusr/share/doc/a file\tabc\n\n",
        )
        .unwrap();
        let mut gz = GzEncoder::new(
            File::create(pkg.join("mtree")).unwrap(),
            flate2::Compression::default(),
        );
        gz.write_all(SAMPLE.as_bytes()).unwrap();
        gz.finish().unwrap();
        fs::create_dir(dir.path().join("broken-1-1")).unwrap(); // no desc: ignored
        let pkgs = local_packages(dir.path()).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "bash");
        assert_eq!(pkgs[0].backup, vec![PathBuf::from("/usr/share/doc/a file")]);
        // the backup (editable) file is left out
        let files = package_files(&pkgs[0]).unwrap();
        assert_eq!(
            files.iter().map(|f| f.path.clone()).collect::<Vec<_>>(),
            vec![PathBuf::from("/usr/bin/bash")]
        );
    }
}
