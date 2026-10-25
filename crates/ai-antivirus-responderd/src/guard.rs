//! The allowlist (hard rule 3, spec 8), checked by the responder on its own, at the moment of acting, whatever the
//! engine decided: PID 1 and kernel threads, systemd, AI Antivirus itself, login session leaders, `engine.allow_exe`, and
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

const AI_ANTIVIRUS_DIRS: &[&str] = &[
    "/usr/lib/ai-antivirus/",
    "/etc/ai-antivirus/",
    "/var/lib/ai-antivirus/",
    "/var/lib/ai-antivirus-analyzer/",
    "/var/lib/ai-antivirus-private/",
];
const SYSTEMD_PREFIXES: &[&str] = &["/usr/lib/systemd/", "/usr/bin/systemd", "/usr/bin/udevadm"];
/// Files under these are never quarantined: the system would not boot or AI Antivirus would lose itself.
const FILE_NEVER: &[&str] = &[
    "/boot/",
    "/efi/",
    "/proc/",
    "/sys/",
    "/usr/lib/systemd/",
    "/usr/lib/modules/",
    "/usr/lib/ai-antivirus/",
    "/etc/ai-antivirus/",
    "/var/lib/ai-antivirus/",
    "/var/lib/ai-antivirus-analyzer/",
    "/var/lib/ai-antivirus-private/",
    "/var/lib/pacman/",
];

fn is_ai_antivirus_exe(exe: &Path) -> bool {
    let s = exe.to_string_lossy();
    AI_ANTIVIRUS_DIRS.iter().any(|d| s.starts_with(d))
        || exe.parent() == Some(Path::new("/usr/bin"))
            && exe
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("ai-antivirus"))
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
    if p.cgroup.contains("/ai-antivirus-") && p.cgroup.ends_with(".service") {
        return no("AI Antivirus's own services are never touched");
    }
    let Some(exe) = &p.exe else {
        return no(
            "the executable cannot be read; the process cannot be checked against the allowlist",
        );
    };
    if is_ai_antivirus_exe(exe) {
        return no("AI Antivirus itself is never touched");
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
    if is_ai_antivirus_exe(path) || cx.allow_exe.iter().any(|a| a == path) {
        return no(format!("{s} is AI Antivirus or in engine.allow_exe"));
    }
    if let Some(pkg) = pacman_owned {
        return no(format!(
            "{s} belongs to package {pkg}; reinstall it (pacman -S {pkg}) instead of quarantining it"
        ));
    }
    Ok(())
}

/// May the responder restore this file from its package? Restoring puts back bytes that match pacman's own record, so
/// it is allowed where quarantining is not (AI Antivirus's own files, systemd units); it never touches pacman's database or
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

/// `::ffff:a.b.c.d` as plain IPv4: real IPv4 traffic only ever matches the IPv4 set.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Addresses this machine needs to stay online: blocking one cuts every program off.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetFacts {
    pub gateways: Vec<IpAddr>,
    pub resolvers: Vec<IpAddr>,
}

/// Where [`NetFacts`] come from; tests point these at fixture files.
pub struct NetSources<'a> {
    pub route: &'a str,
    pub route6: &'a str,
    pub resolv: &'a [&'a str],
}

impl NetSources<'static> {
    pub const SYSTEM: NetSources<'static> = NetSources {
        route: "/proc/net/route",
        route6: "/proc/net/ipv6_route",
        resolv: &["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"],
    };
}

impl NetFacts {
    pub fn read(src: &NetSources<'_>) -> Self {
        let text = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
        let mut gateways = parse_route(&text(src.route));
        gateways.extend(parse_route6(&text(src.route6)));
        let mut resolvers: Vec<IpAddr> = src
            .resolv
            .iter()
            .flat_map(|p| parse_resolv(&text(p)))
            .collect();
        gateways.sort();
        gateways.dedup();
        resolvers.sort();
        resolvers.dedup();
        Self {
            gateways,
            resolvers,
        }
    }
}

/// Default-route gateways from /proc/net/route (addresses are little-endian hex).
fn parse_route(text: &str) -> Vec<IpAddr> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.get(1) != Some(&"00000000") {
                return None;
            }
            let gw = u32::from_str_radix(f.get(2)?, 16).ok()?;
            (gw != 0).then(|| IpAddr::V4(std::net::Ipv4Addr::from(gw.swap_bytes())))
        })
        .collect()
}

/// Default-route next hops from /proc/net/ipv6_route (dest ::/0 with a non-zero next hop).
fn parse_route6(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 5 || f[0] != "0".repeat(32) || f[1] != "00" {
                return None;
            }
            let hop = u128::from_str_radix(f[4], 16).ok()?;
            (hop != 0).then(|| IpAddr::V6(std::net::Ipv6Addr::from(hop)))
        })
        .collect()
}

/// `nameserver` lines of a resolv.conf.
fn parse_resolv(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            (w.next()? == "nameserver").then_some(())?;
            // a zone id (fe80::1%eth0) is not part of the address
            w.next()?.split('%').next()?.parse().ok()
        })
        .map(canonical_ip)
        .collect()
}

/// May the responder block this address? Reads the gateways and resolvers of this machine now.
pub fn check_ip(ip: IpAddr) -> Result<(), Refusal> {
    check_ip_with(ip, &NetFacts::read(&NetSources::SYSTEM))
}

/// [`check_ip`] with the network facts given (for tests and dry runs).
pub fn check_ip_with(ip: IpAddr, net: &NetFacts) -> Result<(), Refusal> {
    let ip = canonical_ip(ip);
    check_ip_kind(ip)?;
    if net.gateways.contains(&ip) {
        return no(format!(
            "{ip} is a default gateway of this machine; blocking it would cut the network"
        ));
    }
    if net.resolvers.contains(&ip) {
        return no(format!(
            "{ip} is a DNS resolver of this machine; blocking it would cut name lookups"
        ));
    }
    Ok(())
}

fn check_ip_kind(ip: IpAddr) -> Result<(), Refusal> {
    let bad = match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
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

    #[test]
    fn gateways_and_resolvers_are_never_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let w = |name: &str, body: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, body).unwrap();
            p.to_string_lossy().into_owned()
        };
        let route = w(
            "route",
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
             wlp3s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n\
             wlp3s0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\n",
        );
        let route6 = w(
            "route6",
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 wlp3s0\n\
             20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 wlp3s0\n",
        );
        let resolv = w(
            "resolv",
            "# comment\nnameserver 9.9.9.9\nnameserver 2620:fe::fe\nsearch lan\n",
        );
        let stub = w("stub", "nameserver 127.0.0.53\n");
        let srcs = [resolv.as_str(), stub.as_str()];
        let net = NetFacts::read(&NetSources {
            route: &route,
            route6: &route6,
            resolv: &srcs,
        });
        assert_eq!(
            net.gateways,
            vec![
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "fe80::1".parse().unwrap(),
            ]
        );
        assert!(net.resolvers.contains(&"9.9.9.9".parse().unwrap()));
        assert!(net.resolvers.contains(&"2620:fe::fe".parse().unwrap()));

        let msg = check_ip_with("192.168.1.1".parse().unwrap(), &net)
            .unwrap_err()
            .0;
        assert!(msg.contains("default gateway"), "{msg}");
        let msg = check_ip_with("9.9.9.9".parse().unwrap(), &net)
            .unwrap_err()
            .0;
        assert!(msg.contains("DNS resolver"), "{msg}");
        // the mapped form of a resolver is the resolver
        assert!(check_ip_with("::ffff:9.9.9.9".parse().unwrap(), &net).is_err());
        assert!(check_ip_with("203.0.113.9".parse().unwrap(), &net).is_ok());
        // missing files mean no extra protection, not an error
        let none = NetFacts::read(&NetSources {
            route: "/nonexistent/route",
            route6: "/nonexistent/route6",
            resolv: &[],
        });
        assert_eq!(none, NetFacts::default());
    }

    #[test]
    fn mapped_ipv6_becomes_ipv4() {
        let m: IpAddr = "::ffff:203.0.113.5".parse().unwrap();
        assert_eq!(canonical_ip(m), "203.0.113.5".parse::<IpAddr>().unwrap());
        let v6: IpAddr = "2001:db8::5".parse().unwrap();
        assert_eq!(canonical_ip(v6), v6);
        // loopback in mapped form is still loopback
        assert!(check_ip_with("::ffff:127.0.0.1".parse().unwrap(), &NetFacts::default()).is_err());
    }

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
            &proc(4242, 1, "/usr/bin/ai-antivirus-responderd", ""),
            &[],
            &cx(false)
        ));
        assert!(refused(
            &proc(501, 1, "/usr/bin/ai-antivirus-engined", ""),
            &[],
            &cx(false)
        ));
        assert!(refused(
            &proc(
                502,
                1,
                "/tmp/x",
                "/system.slice/ai-antivirus-engined.service"
            ),
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
        // a program merely named like AI Antivirus elsewhere is not protected
        assert!(check_process(
            &proc(505, 1, "/tmp/ai-antivirus-engined", ""),
            &[],
            &cx(false)
        )
        .is_ok());
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
            "/var/lib/ai-antivirus/ai-antivirus.db",
            "/dev/sda",
            "/usr/bin/ai-antivirus",
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
