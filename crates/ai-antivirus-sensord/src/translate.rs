//! Turns decoded eBPF records into schema `Event`s.
//!
//! This is the only place that mixes kernel facts with `/proc` facts, and it is
//! plain Rust over a [`ProcFs`], so it is tested without a kernel.
//!
//! What comes from where for `Exec`:
//!
//! | field | source | if unavailable |
//! | --- | --- | --- |
//! | `proc`, `parent` | process table (fork edges + `/proc` start time) | `start_ns = 0` |
//! | `uid` | kernel, real uid | n/a |
//! | `argv` | kernel, captured before the exec | `/proc/<pid>/cmdline`, else empty |
//! | `exe` | `/proc/<pid>/exe` | the path as given to `execve` |
//! | `cwd`, `cgroup` | `/proc/<pid>/...` | empty |
//!
//! `/proc` data is only used while the live process is still the one that
//! exec'd (same start time before and after reading), so a PID that exited and
//! was reused never contributes facts about the wrong process.

use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use ai_antivirus_common::event::{Event, Proto};
use ai_antivirus_ebpf_common::{
    DecodeError, ExecView, Record, AF_INET, AF_INET6, EXIT_FLAG_HAS_CODE, PROTO_TCP, PROTO_UDP,
};

use crate::poller::UNKNOWN_EXIT_CODE;
use crate::procinfo;
use crate::proctree::{lock, ProcFs, SharedTable};
use crate::sink::Sink;

/// A live `/proc` entry counts as "the same process" within this start-time gap.
const LIVE_TOLERANCE_NS: u64 = 50_000_000;
/// How many ancestors an `exec` event carries.
const LINEAGE_MAX: usize = 24;

pub struct Translator {
    table: SharedTable,
    fs: Box<dyn ProcFs>,
}

impl Translator {
    pub fn new(table: SharedTable, fs: Box<dyn ProcFs>) -> Translator {
        Translator { table, fs }
    }

    /// Decode and handle one ring-buffer record, sending any resulting event.
    pub fn handle(&self, bytes: &[u8], sink: &Sink) -> Result<(), DecodeError> {
        match Record::decode(bytes)? {
            Record::Fork(fork) => {
                lock(&self.table).on_fork(fork.parent_tgid, fork.child_pid, fork.ts_boot_ns);
            }
            Record::Exec(view) => sink.send(self.exec_event(&view)),
            Record::Exit(exit) => {
                let key = lock(&self.table).on_exit(exit.tgid, exit.tid);
                if let Some(proc) = key {
                    let code = if exit.flags & EXIT_FLAG_HAS_CODE != 0 {
                        exit.code
                    } else {
                        UNKNOWN_EXIT_CODE
                    };
                    sink.send(Event::Exit { proc, code });
                }
            }
            Record::Connect(conn) => {
                let ip = match conn.family {
                    AF_INET => {
                        let [a, b, c, d, ..] = conn.addr;
                        Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
                    }
                    AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(conn.addr))),
                    _ => None,
                };
                let proto = match conn.proto {
                    PROTO_TCP => Some(Proto::Tcp),
                    PROTO_UDP => Some(Proto::Udp),
                    _ => None,
                };
                if let (Some(ip), Some(proto)) = (ip, proto) {
                    let proc = lock(&self.table).resolve(conn.tgid, Some(conn.ts_boot_ns));
                    sink.send(Event::Connect {
                        proc,
                        dst: SocketAddr::new(ip, conn.port),
                        proto,
                    });
                }
            }
        }
        Ok(())
    }

    /// Forget vanished processes (see `ProcTable::sweep`).
    pub fn sweep(&self) -> usize {
        lock(&self.table).sweep()
    }

    fn is_live(&self, pid: u32, start_ns: u64) -> bool {
        self.fs.stat(pid).is_some_and(|stat| {
            procinfo::start_ns(stat.start_ticks).abs_diff(start_ns) <= LIVE_TOLERANCE_NS
        })
    }

    fn exec_event(&self, view: &ExecView<'_>) -> Event {
        let pid = view.tgid;
        let (proc, parent, lineage) = {
            let mut table = lock(&self.table);
            let (proc, parent) = table.on_exec(pid, view.ts_boot_ns);
            (proc, parent, table.ancestry(pid, LINEAGE_MAX))
        };

        let mut exe = None;
        let mut cwd = None;
        let mut cgroup = String::new();
        let mut proc_argv = Vec::new();
        let mut stdio = Vec::new();
        // A key with start_ns 0 means "unknown": nothing to compare against, so
        // `/proc` is not trusted for it.
        if proc.start_ns != 0 && self.is_live(pid, proc.start_ns) {
            exe = self.fs.exe(pid);
            cwd = self.fs.cwd(pid);
            cgroup = self.fs.cgroup(pid);
            stdio = self.fs.stdio(pid);
            if view.argv.is_empty() {
                proc_argv = self.fs.cmdline(pid);
            }
            if !self.is_live(pid, proc.start_ns) {
                // The process went away while we were reading.
                exe = None;
                cwd = None;
                cgroup.clear();
                proc_argv.clear();
                stdio.clear();
            }
        }

        let argv = if view.argv.is_empty() {
            proc_argv
        } else {
            procinfo::parse_cmdline(view.argv)
        };
        Event::Exec {
            proc,
            parent,
            uid: view.uid,
            exe: exe.unwrap_or_else(|| PathBuf::from(OsStr::from_bytes(view.filename))),
            argv,
            cwd: cwd.unwrap_or_default(),
            cgroup,
            stdio,
            lineage,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proctree::testing::FakeFs;
    use crate::proctree::ProcTable;
    use ai_antivirus_common::event::ProcKey;
    use ai_antivirus_ebpf_common::{
        ConnectRecord, ExecRecord, ExitRecord, ForkRecord, EXEC_FLAG_ARGV, KIND_CONNECT, KIND_EXEC,
        KIND_EXIT, KIND_FORK,
    };
    use core::mem::{offset_of, size_of};
    use std::ffi::OsString;
    use std::sync::{Arc, Mutex};

    const T5: u64 = 5_000_000_000;

    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_ne_bytes());
    }
    fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_ne_bytes());
    }

    fn fork(parent: u32, child: u32, ts: u64) -> Vec<u8> {
        let mut b = vec![0u8; size_of::<ForkRecord>()];
        put32(&mut b, 0, KIND_FORK);
        put32(&mut b, offset_of!(ForkRecord, parent_tid), parent);
        put32(&mut b, offset_of!(ForkRecord, parent_tgid), parent);
        put32(&mut b, offset_of!(ForkRecord, child_pid), child);
        put64(&mut b, offset_of!(ForkRecord, ts_boot_ns), ts);
        b
    }

    fn exec(tgid: u32, ts: u64, name: &[u8], argv: &[u8], argc: u32) -> Vec<u8> {
        let mut b = vec![0u8; size_of::<ExecRecord>()];
        put32(&mut b, 0, KIND_EXEC);
        put32(&mut b, offset_of!(ExecRecord, tgid), tgid);
        put32(&mut b, offset_of!(ExecRecord, old_tid), tgid);
        put32(&mut b, offset_of!(ExecRecord, uid), 1000);
        put64(&mut b, offset_of!(ExecRecord, ts_boot_ns), ts);
        let flags = if argv.is_empty() { 0 } else { EXEC_FLAG_ARGV };
        put32(&mut b, offset_of!(ExecRecord, flags), flags);
        put32(&mut b, offset_of!(ExecRecord, argc), argc);
        put32(
            &mut b,
            offset_of!(ExecRecord, filename_len),
            (name.len() + 1) as u32,
        );
        put32(&mut b, offset_of!(ExecRecord, argv_len), argv.len() as u32);
        let n = offset_of!(ExecRecord, filename);
        b[n..n + name.len()].copy_from_slice(name);
        let a = offset_of!(ExecRecord, argv);
        b[a..a + argv.len()].copy_from_slice(argv);
        b
    }

    fn exit(tgid: u32, tid: u32, code: Option<i32>) -> Vec<u8> {
        let mut b = vec![0u8; size_of::<ExitRecord>()];
        put32(&mut b, 0, KIND_EXIT);
        put32(&mut b, offset_of!(ExitRecord, tgid), tgid);
        put32(&mut b, offset_of!(ExitRecord, tid), tid);
        put32(
            &mut b,
            offset_of!(ExitRecord, flags),
            u32::from(code.is_some()),
        );
        put32(
            &mut b,
            offset_of!(ExitRecord, code),
            code.unwrap_or(0) as u32,
        );
        b
    }

    fn connect(tgid: u32, family: u16, proto: u8, port: u16, addr: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; size_of::<ConnectRecord>()];
        put32(&mut b, 0, KIND_CONNECT);
        put32(&mut b, offset_of!(ConnectRecord, tgid), tgid);
        put64(
            &mut b,
            offset_of!(ConnectRecord, ts_boot_ns),
            T5 + 1_000_000,
        );
        b[offset_of!(ConnectRecord, family)..][..2].copy_from_slice(&family.to_ne_bytes());
        b[offset_of!(ConnectRecord, proto)] = proto;
        b[offset_of!(ConnectRecord, port)..][..2].copy_from_slice(&port.to_ne_bytes());
        b[offset_of!(ConnectRecord, addr)..][..addr.len()].copy_from_slice(addr);
        b
    }

    struct Rig {
        tr: Translator,
        fake: FakeFs,
        sink: Sink,
        rx: std::sync::mpsc::Receiver<crate::sink::Stamped>,
    }

    impl Rig {
        fn new() -> Rig {
            let fake = FakeFs::default();
            let table: SharedTable = Arc::new(Mutex::new(ProcTable::new(Box::new(fake.clone()))));
            let (sink, rx) = Sink::channel(64);
            Rig {
                tr: Translator::new(table, Box::new(fake.clone())),
                fake,
                sink,
                rx,
            }
        }

        fn feed(&self, bytes: &[u8]) {
            self.tr.handle(bytes, &self.sink).unwrap();
        }

        fn events(&self) -> Vec<Event> {
            self.rx.try_iter().map(|(_, e)| e).collect()
        }
    }

    #[test]
    fn fork_then_exec_builds_an_exec_chain_from_kernel_and_proc_facts() {
        let rig = Rig::new();
        rig.fake.set(10, 1, 400);
        rig.tr.table.lock().unwrap().baseline().unwrap();
        rig.fake.set(20, 10, 500);
        rig.fake.details(
            20,
            "/usr/bin/curl",
            "/home/u",
            "/user.slice/x.scope",
            &["stale"],
        );

        rig.feed(&fork(10, 20, T5 + 2_000_000));
        assert!(rig.events().is_empty(), "forks are internal");
        rig.feed(&exec(
            20,
            T5 + 3_000_000,
            b"curl",
            b"curl\0-s\0http://x\0",
            3,
        ));

        let events = rig.events();
        let [Event::Exec {
            proc,
            parent,
            uid,
            exe,
            argv,
            cwd,
            cgroup,
            ..
        }] = events.as_slice()
        else {
            panic!("expected one Exec, got {events:?}");
        };
        assert_eq!(
            *proc,
            ProcKey {
                pid: 20,
                start_ns: T5
            }
        );
        assert_eq!(
            *parent,
            ProcKey {
                pid: 10,
                start_ns: 4_000_000_000
            }
        );
        assert_eq!(*uid, 1000);
        assert_eq!(
            exe,
            &PathBuf::from("/usr/bin/curl"),
            "resolved path from /proc"
        );
        assert_eq!(
            argv,
            &vec![
                OsString::from("curl"),
                OsString::from("-s"),
                OsString::from("http://x")
            ],
            "kernel argv wins over /proc"
        );
        assert_eq!(cwd, &PathBuf::from("/home/u"));
        assert_eq!(cgroup, "/user.slice/x.scope");
    }

    #[test]
    fn a_short_lived_process_still_gets_a_full_exec_and_exit() {
        let rig = Rig::new();
        rig.fake.set(10, 1, 400);
        rig.tr.table.lock().unwrap().baseline().unwrap();
        // pid 30 is already gone from /proc when the record is handled.
        rig.feed(&fork(10, 30, T5 + 7_000_000));
        rig.feed(&exec(30, T5 + 8_000_000, b"/bin/true", b"true\0", 1));
        rig.feed(&exit(30, 30, Some(0)));

        let events = rig.events();
        assert_eq!(events.len(), 2, "{events:?}");
        let Event::Exec {
            proc,
            exe,
            argv,
            cwd,
            ..
        } = &events[0]
        else {
            panic!("expected Exec");
        };
        assert_eq!(
            *proc,
            ProcKey {
                pid: 30,
                start_ns: T5
            }
        );
        assert_eq!(
            exe,
            &PathBuf::from("/bin/true"),
            "falls back to the execve path"
        );
        assert_eq!(argv, &vec![OsString::from("true")]);
        assert_eq!(cwd, &PathBuf::new());
        assert_eq!(
            events[1],
            Event::Exit {
                proc: *proc,
                code: 0
            }
        );
    }

    #[test]
    fn argv_falls_back_to_proc_when_the_kernel_sent_none() {
        let rig = Rig::new();
        rig.fake.set(40, 1, 500);
        rig.fake
            .details(40, "/usr/bin/x", "/", "", &["x", "--flag"]);
        rig.feed(&exec(40, T5 + 1_000_000, b"x", b"", 0));
        let events = rig.events();
        let [Event::Exec { argv, .. }] = events.as_slice() else {
            panic!("expected one Exec");
        };
        assert_eq!(argv, &vec![OsString::from("x"), OsString::from("--flag")]);
    }

    #[test]
    fn proc_facts_of_a_reused_pid_are_never_used() {
        let rig = Rig::new();
        rig.fake.set(50, 1, 900); // a different, newer process owns pid 50 now
        rig.fake
            .details(50, "/usr/bin/other", "/other", "/other.scope", &["other"]);
        rig.feed(&fork(10, 50, T5));
        rig.feed(&exec(50, T5 + 1_000_000, b"/bin/real", b"real\0", 1));
        let events = rig.events();
        let [Event::Exec {
            proc,
            exe,
            cwd,
            cgroup,
            argv,
            ..
        }] = events.as_slice()
        else {
            panic!("expected one Exec");
        };
        assert_eq!(
            proc.start_ns, T5,
            "key comes from the fork, not the reused pid"
        );
        assert_eq!(exe, &PathBuf::from("/bin/real"));
        assert_eq!(cwd, &PathBuf::new());
        assert!(cgroup.is_empty());
        assert_eq!(argv, &vec![OsString::from("real")]);
    }

    #[test]
    fn exit_codes_known_unknown_and_threads() {
        let rig = Rig::new();
        rig.fake.set(60, 1, 500);
        rig.feed(&exec(60, T5, b"a", b"a\0", 1));
        rig.feed(&exit(60, 60, None));
        rig.fake.set(61, 1, 500);
        rig.feed(&exec(61, T5, b"b", b"b\0", 1));
        rig.feed(&exit(61, 99, Some(1))); // a thread: ignored
        rig.feed(&exit(61, 61, Some(7)));

        let exits: Vec<Event> = rig
            .events()
            .into_iter()
            .filter(|e| matches!(e, Event::Exit { .. }))
            .collect();
        let key = ProcKey {
            pid: 60,
            start_ns: T5,
        };
        assert_eq!(
            exits[0],
            Event::Exit {
                proc: key,
                code: UNKNOWN_EXIT_CODE
            }
        );
        assert!(matches!(exits[1], Event::Exit { code: 7, .. }));
        assert_eq!(exits.len(), 2);
    }

    #[test]
    fn connect_decodes_v4_v6_and_both_protocols() {
        let rig = Rig::new();
        rig.fake.set(70, 1, 500);
        rig.feed(&connect(70, AF_INET, PROTO_TCP, 443, &[93, 184, 216, 34]));
        let mut v6 = [0u8; 16];
        v6[15] = 1;
        rig.feed(&connect(70, AF_INET6, PROTO_UDP, 53, &v6));
        rig.feed(&connect(70, 1, PROTO_TCP, 1, &[0])); // AF_UNIX: not reported
        rig.feed(&connect(70, AF_INET, 9, 1, &[1, 1, 1, 1])); // unknown protocol

        let events = rig.events();
        assert_eq!(events.len(), 2, "{events:?}");
        let key = ProcKey {
            pid: 70,
            start_ns: T5,
        };
        assert_eq!(
            events[0],
            Event::Connect {
                proc: key,
                dst: "93.184.216.34:443".parse().unwrap(),
                proto: Proto::Tcp
            }
        );
        assert_eq!(
            events[1],
            Event::Connect {
                proc: key,
                dst: "[::1]:53".parse().unwrap(),
                proto: Proto::Udp
            }
        );
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        let rig = Rig::new();
        assert!(rig.tr.handle(&[], &rig.sink).is_err());
        assert!(rig.tr.handle(&[0xff; 64], &rig.sink).is_err());
        assert!(rig.events().is_empty());
    }
}
