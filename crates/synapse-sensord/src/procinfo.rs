//! Reading process facts from `/proc` (or a fake root in tests).
//!
//! Everything read here is attacker-influenced (command lines, paths,
//! `comm`), so it is parsed defensively and never trusted to be UTF-8.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use synapse_common::event::{BootId, ProcKey};
use synapse_common::{Error, Result};

/// `USER_HZ`: `/proc/<pid>/stat` times are in clock ticks of this frequency.
/// It is 100 on every Linux architecture Arch supports; a constant avoids
/// calling `sysconf` (which would need `unsafe`).
pub const USER_HZ: u64 = 100;
const NS_PER_TICK: u64 = 1_000_000_000 / USER_HZ;
/// Command lines are cut at this size so one process cannot bloat the log.
const MAX_CMDLINE_BYTES: u64 = 64 * 1024;
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// The fields of `/proc/<pid>/stat` Synapse uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatInfo {
    pub ppid: u32,
    /// Process start time in clock ticks since boot.
    pub start_ticks: u64,
}

/// Parse one `stat` line. `comm` (field 2) is in parentheses and may itself
/// contain spaces and parentheses, so the split happens after the *last* `)`.
pub fn parse_stat(text: &str) -> Option<StatInfo> {
    let close = text.rfind(')')?;
    let mut fields = text.get(close + 1..)?.split_whitespace();
    let _state = fields.next()?; // field 3
    let ppid = fields.next()?.parse().ok()?; // field 4
    let start_ticks = fields.nth(17)?.parse().ok()?; // fields 5..=21 skipped, then 22
    Some(StatInfo { ppid, start_ticks })
}

/// Convert start ticks to nanoseconds since boot (the `ProcKey::start_ns` unit).
pub fn start_ns(start_ticks: u64) -> u64 {
    start_ticks.saturating_mul(NS_PER_TICK)
}

/// Split a `cmdline` blob into arguments.
pub fn parse_cmdline(bytes: &[u8]) -> Vec<OsString> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let body = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    body.split(|b| *b == 0)
        .map(|arg| OsString::from_vec(arg.to_vec()))
        .collect()
}

/// Extract the cgroup v2 path from `/proc/<pid>/cgroup` (the `0::` line).
pub fn parse_cgroup(text: &str) -> String {
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap_or("")
        .to_owned()
}

/// Read the kernel boot id.
pub fn read_boot_id() -> Result<BootId> {
    let path = Path::new(BOOT_ID_PATH);
    let text = fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    BootId::parse(&text).ok_or_else(|| {
        Error::io(
            path,
            io::Error::new(io::ErrorKind::InvalidData, "malformed boot id"),
        )
    })
}

fn pid_dir(root: &Path, pid: u32) -> PathBuf {
    root.join(pid.to_string())
}

/// Read and parse `<root>/<pid>/stat`. `None` if the process is gone or the
/// file is unreadable or malformed.
pub fn read_stat(root: &Path, pid: u32) -> Option<StatInfo> {
    let bytes = fs::read(pid_dir(root, pid).join("stat")).ok()?;
    parse_stat(&String::from_utf8_lossy(&bytes))
}

/// Everything the poller reports about a new process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub key: ProcKey,
    pub ppid: u32,
    pub uid: u32,
    pub exe: PathBuf,
    pub argv: Vec<OsString>,
    pub cwd: PathBuf,
    pub cgroup: String,
    pub stdio: Vec<OsString>,
}

/// Result of inspecting one PID.
#[derive(Debug, PartialEq, Eq)]
pub enum Probe {
    Process(Box<ProcInfo>),
    /// A kernel thread (or a zombie with nothing to report): tracked, never reported.
    KernelThread,
    /// Vanished, or the PID was reused while we were reading it.
    Gone,
}

fn read_cmdline(dir: &Path) -> Vec<OsString> {
    use std::io::Read;
    let Ok(file) = fs::File::open(dir.join("cmdline")) else {
        return Vec::new();
    };
    let mut bytes = Vec::new();
    match file.take(MAX_CMDLINE_BYTES).read_to_end(&mut bytes) {
        Ok(_) => parse_cmdline(&bytes),
        Err(_) => Vec::new(),
    }
}

/// Where fds 0, 1 and 2 of the process in `dir` point (empty entries for fds that are closed or unreadable).
pub fn read_stdio(dir: &Path) -> Vec<OsString> {
    (0..3)
        .map(|fd| {
            fs::read_link(dir.join("fd").join(fd.to_string()))
                .map(PathBuf::into_os_string)
                .unwrap_or_default()
        })
        .collect()
}

/// Collect the facts for `pid`, whose `stat` was just read as `stat`.
pub fn probe(root: &Path, pid: u32, stat: &StatInfo) -> Probe {
    // Kernel threads: PID 2 (kthreadd) and its children.
    if pid == 2 || stat.ppid == 2 {
        return Probe::KernelThread;
    }
    let dir = pid_dir(root, pid);
    let Ok(meta) = fs::metadata(&dir) else {
        return Probe::Gone;
    };
    let argv = read_cmdline(&dir);
    let exe = match fs::read_link(dir.join("exe")) {
        Ok(path) => path,
        // No exe link and no arguments: a kernel thread or a zombie.
        Err(e) if e.kind() == io::ErrorKind::NotFound && argv.is_empty() => {
            return Probe::KernelThread;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Probe::Gone,
        // Not permitted to read it (not root): report the process anyway.
        Err(_) => PathBuf::new(),
    };
    let cwd = fs::read_link(dir.join("cwd")).unwrap_or_default();
    let stdio = read_stdio(&dir);
    let cgroup = fs::read(dir.join("cgroup"))
        .map(|b| parse_cgroup(&String::from_utf8_lossy(&b)))
        .unwrap_or_default();

    // Guard against PID reuse during the reads above.
    match read_stat(root, pid) {
        Some(again) if again.start_ticks == stat.start_ticks => {}
        _ => return Probe::Gone,
    }

    Probe::Process(Box::new(ProcInfo {
        key: ProcKey {
            pid,
            start_ns: start_ns(stat.start_ticks),
        },
        ppid: stat.ppid,
        uid: meta.uid(),
        exe,
        argv,
        cwd,
        cgroup,
        stdio,
    }))
}

#[cfg(test)]
pub(crate) mod testing {
    /// A syntactically valid `/proc/<pid>/stat` line.
    pub fn stat_line(pid: u32, comm: &str, ppid: u32, start_ticks: u64) -> String {
        format!(
            "{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 \
             {start_ticks} 0 0 18446744073709551615\n"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::testing::stat_line;
    use super::*;

    #[test]
    fn parses_a_plain_stat_line() {
        let info = parse_stat(&stat_line(1234, "bash", 1, 987_654)).unwrap();
        assert_eq!(
            info,
            StatInfo {
                ppid: 1,
                start_ticks: 987_654
            }
        );
    }

    #[test]
    fn comm_with_spaces_and_parentheses_does_not_confuse_the_parser() {
        let line = stat_line(77, "my (weird) prog) x", 5, 42);
        assert_eq!(
            parse_stat(&line),
            Some(StatInfo {
                ppid: 5,
                start_ticks: 42
            })
        );
    }

    #[test]
    fn malformed_stat_lines_are_rejected() {
        assert_eq!(parse_stat(""), None);
        assert_eq!(parse_stat("1 (x) S"), None);
        assert_eq!(parse_stat("1 (x) S notanumber 1 1 0"), None);
        assert_eq!(parse_stat("no parentheses at all"), None);
    }

    #[test]
    fn start_ticks_convert_to_nanoseconds() {
        assert_eq!(start_ns(1), 10_000_000);
        assert_eq!(start_ns(u64::MAX), u64::MAX);
    }

    #[test]
    fn cmdline_splits_on_nul_and_keeps_empty_arguments() {
        assert!(parse_cmdline(b"").is_empty());
        assert_eq!(
            parse_cmdline(b"sh\0-c\0echo hi\0"),
            vec![
                OsString::from("sh"),
                OsString::from("-c"),
                OsString::from("echo hi")
            ]
        );
        assert_eq!(
            parse_cmdline(b"a\0\0b\0"),
            vec![OsString::from("a"), OsString::new(), OsString::from("b")]
        );
        // Programs that rewrite their title may leave no trailing NUL.
        assert_eq!(
            parse_cmdline(b"nginx: master"),
            vec![OsString::from("nginx: master")]
        );
    }

    #[test]
    fn cmdline_keeps_non_utf8_bytes() {
        let args = parse_cmdline(b"x\0\xff\xfe\0");
        assert_eq!(args.len(), 2);
        assert_eq!(args[1].as_encoded_bytes(), b"\xff\xfe");
    }

    #[test]
    fn cgroup_v2_path_is_extracted() {
        assert_eq!(
            parse_cgroup("0::/user.slice/user-1000.slice/session-2.scope\n"),
            "/user.slice/user-1000.slice/session-2.scope"
        );
        assert_eq!(parse_cgroup("12:cpu:/foo\n0::/bar\n"), "/bar");
        assert_eq!(parse_cgroup("12:cpu:/foo\n"), "");
        assert_eq!(parse_cgroup(""), "");
    }

    #[test]
    fn boot_id_of_this_machine_parses() {
        // Linux-only, like the rest of Synapse.
        assert!(read_boot_id().is_ok());
    }
}
