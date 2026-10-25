//! cgroup v2 containment (spec 8, levels 2 and 3). A suspect process tree is moved into
//! `<cgroup_root>/ai_antivirus.slice/suspect-<action id>` and that cgroup is frozen (`cgroup.freeze`): cleaner than SIGSTOP,
//! because children forked later land in the same cgroup and are frozen too. Kill is `cgroup.kill` (kernel 5.14+) on
//! the same cgroup, which kills every member at once and cannot hit a reused PID.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub const SLICE: &str = "ai_antivirus.slice";

/// One process moved into a suspect cgroup, and where it came from (for undo).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub pid: u32,
    pub start_ns: u64,
    /// cgroup v2 path it was in, e.g. `/user.slice/user-1000.slice/session-2.scope`.
    pub from: String,
}

#[derive(Debug, Clone)]
pub struct Cgroups {
    root: PathBuf,
    /// Tests only: a plain directory stands in for cgroupfs, so control files are created and `cgroup.events` is
    /// written by hand.
    emulate: bool,
}

impl Cgroups {
    pub fn new(root: impl Into<PathBuf>) -> Cgroups {
        Cgroups {
            root: root.into(),
            emulate: false,
        }
    }

    /// For tests: treat a plain directory as the cgroup root.
    #[doc(hidden)]
    pub fn emulated(root: impl Into<PathBuf>) -> Cgroups {
        Cgroups {
            root: root.into(),
            emulate: true,
        }
    }

    /// Is a cgroup v2 hierarchy mounted at the root?
    pub fn available(&self) -> bool {
        self.emulate || self.root.join("cgroup.controllers").is_file()
    }

    /// The cgroup-relative name of the suspect cgroup for `id`.
    pub fn suspect_name(id: i64) -> String {
        format!("/{SLICE}/suspect-{id}")
    }

    /// Filesystem path of a cgroup v2 path such as `/user.slice/x.scope`. `None` for anything that is not a plain
    /// absolute path (the value comes from `/proc/<pid>/cgroup` or the database and is checked like input).
    pub fn path_of(&self, cgroup: &str) -> Option<PathBuf> {
        let p = Path::new(cgroup);
        let clean = p.is_absolute()
            && p.components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_)));
        clean.then(|| self.root.join(cgroup.trim_start_matches('/')))
    }

    fn write(&self, file: &Path, value: &str) -> io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create(self.emulate)
            .truncate(self.emulate)
            .open(file)?;
        f.write_all(value.as_bytes())
    }

    /// Create `ai_antivirus.slice/suspect-<id>` and return its path.
    pub fn create(&self, id: i64) -> io::Result<PathBuf> {
        let slice = self.root.join(SLICE);
        match fs::create_dir(&slice) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        let dir = slice.join(format!("suspect-{id}"));
        fs::create_dir(&dir)?;
        if self.emulate {
            fs::write(dir.join("cgroup.procs"), "")?;
            fs::write(dir.join("cgroup.events"), "populated 0\nfrozen 0\n")?;
        }
        Ok(dir)
    }

    /// Move the whole thread group of `pid` into `cg`.
    pub fn move_pid(&self, cg: &Path, pid: u32) -> io::Result<()> {
        if self.emulate {
            let mut f = OpenOptions::new()
                .append(true)
                .create(true)
                .open(cg.join("cgroup.procs"))?;
            return writeln!(f, "{pid}");
        }
        self.write(&cg.join("cgroup.procs"), &pid.to_string())
    }

    pub fn set_frozen(&self, cg: &Path, frozen: bool) -> io::Result<()> {
        let v = if frozen { "1" } else { "0" };
        self.write(&cg.join("cgroup.freeze"), v)?;
        if self.emulate {
            fs::write(
                cg.join("cgroup.events"),
                format!("populated 1\nfrozen {v}\n"),
            )?;
        }
        Ok(())
    }

    /// Wait until the kernel reports the cgroup frozen (a process in uninterruptible sleep can delay it).
    pub fn wait_frozen(&self, cg: &Path, timeout: Duration) -> bool {
        let until = Instant::now() + timeout;
        loop {
            let frozen = fs::read_to_string(cg.join("cgroup.events"))
                .is_ok_and(|t| t.lines().any(|l| l.trim() == "frozen 1"));
            if frozen || Instant::now() >= until {
                return frozen;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Kill every process in `cg` (`cgroup.kill`).
    pub fn kill(&self, cg: &Path) -> io::Result<()> {
        self.write(&cg.join("cgroup.kill"), "1")
    }

    /// PIDs currently in `cg`.
    pub fn procs(&self, cg: &Path) -> io::Result<Vec<u32>> {
        Ok(fs::read_to_string(cg.join("cgroup.procs"))?
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect())
    }

    /// Remove an empty suspect cgroup. A cgroup that still has members cannot be removed (`EBUSY`).
    pub fn remove(&self, cg: &Path) -> io::Result<()> {
        if self.emulate {
            return fs::remove_dir_all(cg);
        }
        fs::remove_dir(cg)
    }

    /// Suspect cgroups that exist now (for the sweep that removes emptied ones).
    pub fn suspects(&self) -> Vec<(i64, PathBuf)> {
        let Ok(rd) = fs::read_dir(self.root.join(SLICE)) else {
            return Vec::new();
        };
        rd.filter_map(|e| {
            let e = e.ok()?;
            let id = e
                .file_name()
                .to_str()?
                .strip_prefix("suspect-")?
                .parse()
                .ok()?;
            Some((id, e.path()))
        })
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emulated_freeze_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let cg = Cgroups::emulated(dir.path());
        assert!(cg.available());
        let s = cg.create(7).unwrap();
        assert_eq!(s, dir.path().join("ai_antivirus.slice/suspect-7"));
        assert!(cg.create(7).is_err(), "an id is used once");
        cg.move_pid(&s, 100).unwrap();
        cg.move_pid(&s, 101).unwrap();
        assert_eq!(cg.procs(&s).unwrap(), [100, 101]);
        assert!(!cg.wait_frozen(&s, Duration::from_millis(30)));
        cg.set_frozen(&s, true).unwrap();
        assert!(cg.wait_frozen(&s, Duration::from_millis(30)));
        assert_eq!(cg.suspects(), [(7, s.clone())]);
        cg.remove(&s).unwrap();
        assert!(cg.suspects().is_empty());
    }

    #[test]
    fn cgroup_paths_are_checked() {
        let cg = Cgroups::new("/sys/fs/cgroup");
        assert_eq!(
            cg.path_of("/user.slice/a.scope"),
            Some(PathBuf::from("/sys/fs/cgroup/user.slice/a.scope"))
        );
        assert_eq!(cg.path_of("/"), Some(PathBuf::from("/sys/fs/cgroup/")));
        for bad in ["", "user.slice", "/../etc", "/a/../b"] {
            assert_eq!(cg.path_of(bad), None, "{bad}");
        }
        assert_eq!(Cgroups::suspect_name(3), "/ai_antivirus.slice/suspect-3");
    }
}
