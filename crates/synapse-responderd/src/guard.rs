//! The allowlist (hard rule 3, spec 8), checked by the responder on its own, at the moment of acting, whatever the
//! engine decided: PID 1 and kernel threads, systemd, Synapse itself, login session leaders, `engine.allow_exe`, and
//! anything at all while a pacman transaction runs. Files and addresses have their own lists of things never touched.

use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

use crate::procfs::LiveProc;

/// Why something is left alone. Shown to the user and stored as the action's `error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn no(msg: impl Into<String>) -> Result<(), Refusal> {
    Err(Refusal(msg.into()))
}

/// What the guard needs to know about the system right now.
pub struct Context<'a> {
    pub allow_exe: &'a [PathBuf],
    pub pacman_active: bool,
    pub self_pid: u32,
}

const SYNAPSE_DIRS: &[&str] = &[
    "/usr/lib/synapse/",
    "/etc/synapse/",
    "/var/lib/synapse/",
    "/var/lib/synapse-ai/",
    "/var/lib/synapse-private/",
];
const SYSTEMD_PREFIXES: &[&str] = &["/usr/lib/systemd/", "/usr/bin/systemd", "/usr/bin/udevadm"];
/// Files under these are never quarantined: the system would not boot or Synapse would lose itself.
const FILE_NEVER: &[&str] = &[
    "/boot/",
    "/efi/",
    "/proc/",
    "/sys/",
    "/usr/lib/systemd/",
    "/usr/lib/modules/",
    "/usr/lib/synapse/",
    "/etc/synapse/",
    "/var/lib/synapse/",
    "/var/lib/synapse-ai/",
    "/var/lib/synapse-private/",
    "/var/lib/pacman/",
];

fn is_synapse_exe(exe: &Path) -> bool {
    let s = exe.to_string_lossy();
    SYNAPSE_DIRS.iter().any(|d| s.starts_with(d))
        || exe.parent() == Some(Path::new("/usr/bin"))
            && exe
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("synapse"))
}

/// May the responder freeze or kill this live process?
pub fn check_process(p: &LiveProc, ancestors: &[PathBuf], cx: &Context<'_>) -> Result<(), Refusal> {
    if p.pid <= 1 {
        return no("PID 1 is never touched");
    }
    if p.kernel_thread {
        return no("kernel threads are never touched");
    }
    if p.pid == cx.self_pid {
        return no("the responder never acts on itself");
    }
    if cx.pacman_active {
        return no("a pacman transaction is running (/var/lib/pacman/db.lck); no destructive action until it ends");
    }
    if p.sid == p.pid {
        return no("login session leaders are never touched");
    }
    if p.cgroup.contains("/synapse-") && p.cgroup.ends_with(".service") {
        return no("Synapse's own services are never touched");
    }
    let Some(exe) = &p.exe else {
        return no(
            "the executable cannot be read; the process cannot be checked against the allowlist",
        );
    };
    if is_synapse_exe(exe) {
        return no("Synapse itself is never touched");
    }
    let s = exe.to_string_lossy();
    if SYSTEMD_PREFIXES.iter().any(|d| s.starts_with(d)) {
        return no(format!("systemd components are never touched ({s})"));
    }
    if cx.allow_exe.iter().any(|a| a == exe) {
        return no(format!("{s} is in engine.allow_exe"));
    }
    if let Some(a) = ancestors
        .iter()
        .find(|a| a.as_path() == Path::new("/usr/bin/pacman"))
    {
        // pacman's hooks outlive the lock in rare cases (a hook that forks into the background)
        return no(format!("runs under {}", a.display()));
    }
    Ok(())
}

/// Lexically clean absolute path (no `.`/`..`, no NUL).
fn clean_abs(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && !path.to_string_lossy().contains('\0')
}

/// May the responder quarantine this file? `pacman_owned` comes from the trust cache.
pub fn check_file(
    path: &Path,
    pacman_owned: Option<&str>,
    cx: &Context<'_>,
) -> Result<(), Refusal> {
    if !clean_abs(path) {
        return no(format!("{} is not a clean absolute path", path.display()));
    }
    if cx.pacman_active {
        return no("a pacman transaction is running (/var/lib/pacman/db.lck); no destructive action until it ends");
    }
    let s = path.to_string_lossy();
    if let Some(d) = FILE_NEVER.iter().find(|d| s.starts_with(*d)) {
        return no(format!("files under {d} are never quarantined"));
    }
    if s.starts_with("/dev/") && !s.starts_with("/dev/shm/") {
        return no("device files are never quarantined");
    }
    if is_synapse_exe(path) || cx.allow_exe.iter().any(|a| a == path) {
        return no(format!("{s} is Synapse or in engine.allow_exe"));
    }
    if let Some(pkg) = pacman_owned {
        return no(format!(
            "{s} belongs to package {pkg}; reinstall it (pacman -S {pkg}) instead of quarantining it"
        ));
    }
    Ok(())
}

/// May the responder restore this file from its package? Restoring puts back bytes that match pacman's own record, so
/// it is allowed where quarantining is not (Synapse's own files, systemd units); it never touches pacman's database or
/// device files, and never runs during a pacman transaction.
pub fn check_restore(path: &Path, cx: &Context<'_>) -> Result<(), Refusal> {
    if !clean_abs(path) {
        return no(format!("{} is not a clean absolute path", path.display()));
    }
    if cx.pacman_active {
        return no("a pacman transaction is running (/var/lib/pacman/db.lck); no destructive action until it ends");
    }
    let s = path.to_string_lossy();
    for d in ["/proc/", "/sys/", "/var/lib/pacman/", "/dev/"] {
        if s.starts_with(d) {
            return no(format!("files under {d} are never restored"));
        }
    }
    Ok(())
}

/// May the responder block this address?
pub fn check_ip(ip: IpAddr) -> Result<(), Refusal> {
    let bad = match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return check_ip(IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    };
    if bad {
        return no(format!(
            "{ip} is a loopback, link-local, multicast or unspecified address"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, sid: u32, exe: &str, cgroup: &str) -> LiveProc {
        LiveProc {
            pid,
            ppid: 1,
            sid,
            start_ns: 1,
            kernel_thread: false,
            exe: Some(PathBuf::from(exe)),
            cgroup: cgroup.to_owned(),
        }
    }

    fn cx(pacman: bool) -> Context<'static> {
        static ALLOW: std::sync::OnceLock<Vec<PathBuf>> = std::sync::OnceLock::new();
        Context {
            allow_exe: ALLOW.get_or_init(|| vec![PathBuf::from("/usr/bin/makepkg")]),
            pacman_active: pacman,
            self_pid: 4242,
        }
    }

    #[test]
    fn process_allowlist() {
        let ok = proc(500, 400, "/tmp/evil", "/user.slice/x.scope");
        assert!(check_process(&ok, &[], &cx(false)).is_ok());
        let refused =
            |p: &LiveProc, anc: &[PathBuf], c: &Context<'_>| check_process(p, anc, c).is_err();
        assert!(refused(&ok, &[], &cx(true)), "pacman running");
        assert!(refused(
            &proc(1, 1, "/usr/lib/systemd/systemd", "/init.scope"),
            &[],
            &cx(false)
        ));
        assert!(
            refused(&proc(500, 500, "/usr/bin/bash", ""), &[], &cx(false)),
            "session leader"
        );
        assert!(refused(
            &proc(4242, 1, "/usr/bin/synapse-responderd", ""),
            &[],
            &cx(false)
        ));
        assert!(refused(
            &proc(501, 1, "/usr/bin/synapse-engined", ""),
            &[],
            &cx(false)
        ));
        assert!(refused(
            &proc(502, 1, "/tmp/x", "/system.slice/synapse-engined.service"),
            &[],
            &cx(false)
        ));
        assert!(refused(
            &proc(503, 1, "/usr/lib/systemd/systemd-journald", ""),
            &[],
            &cx(false)
        ));
        assert!(
            refused(&proc(504, 1, "/usr/bin/makepkg", ""), &[], &cx(false)),
            "allow_exe"
        );
        assert!(
            refused(&ok, &[PathBuf::from("/usr/bin/pacman")], &cx(false)),
            "under pacman"
        );
        let mut k = ok.clone();
        k.kernel_thread = true;
        assert!(refused(&k, &[], &cx(false)));
        let mut unknown = ok.clone();
        unknown.exe = None;
        assert!(
            refused(&unknown, &[], &cx(false)),
            "unknown exe fails closed"
        );
        // a program merely named like Synapse elsewhere is not protected
        assert!(check_process(&proc(505, 1, "/tmp/synapse-engined", ""), &[], &cx(false)).is_ok());
    }

    #[test]
    fn file_allowlist() {
        let c = cx(false);
        assert!(check_file(Path::new("/tmp/eicar.com"), None, &c).is_ok());
        assert!(check_file(Path::new("/home/u/Downloads/x.bin"), None, &c).is_ok());
        assert!(check_file(Path::new("/dev/shm/x"), None, &c).is_ok());
        for bad in [
            "relative",
            "/tmp/../etc/passwd",
            "/boot/vmlinuz-linux",
            "/usr/lib/systemd/systemd",
            "/var/lib/synapse/synapse.db",
            "/dev/sda",
            "/usr/bin/synapsectl",
            "/usr/bin/makepkg",
        ] {
            assert!(check_file(Path::new(bad), None, &c).is_err(), "{bad}");
        }
        let e = check_file(Path::new("/usr/bin/ls"), Some("coreutils"), &c).unwrap_err();
        assert!(e.0.contains("pacman -S coreutils"));
        assert!(check_file(Path::new("/tmp/x"), None, &cx(true)).is_err());
    }

    #[test]
    fn ip_allowlist() {
        for ok in ["1.2.3.4", "2001:db8::1", "192.168.1.20"] {
            assert!(check_ip(ok.parse().unwrap()).is_ok(), "{ok}");
        }
        for bad in [
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "169.254.1.1",
            "::1",
            "::",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(check_ip(bad.parse().unwrap()).is_err(), "{bad}");
        }
    }
}
