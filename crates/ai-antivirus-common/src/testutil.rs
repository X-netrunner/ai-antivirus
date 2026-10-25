//! Shared fixtures for unit tests.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::event::{BootId, Envelope, Event, ProcKey, Proto, Sha256, TamperKind};

pub fn pk(pid: u32) -> ProcKey {
    ProcKey {
        pid,
        start_ns: u64::from(pid) * 1_000,
    }
}

/// One instance of every `Event` variant (and every `TamperKind`-bearing one).
pub fn all_event_variants() -> Vec<Event> {
    let addr = "192.0.2.10:4444".parse().unwrap();
    let addr6 = "[::1]:8080".parse().unwrap();
    vec![
        Event::Exec {
            proc: pk(100),
            parent: pk(1),
            uid: 1000,
            exe: PathBuf::from("/usr/bin/bash"),
            argv: vec![
                OsString::from("bash"),
                OsString::from("-c"),
                OsString::from("id"),
            ],
            cwd: PathBuf::from("/home/nex"),
            cgroup: "/user.slice/user-1000.slice".to_owned(),
            stdio: vec![
                OsString::from("socket:[4242]"),
                OsString::from("socket:[4242]"),
                OsString::from("/dev/pts/1"),
            ],
            lineage: vec![pk(1)],
        },
        Event::Exit {
            proc: pk(100),
            code: -9,
        },
        Event::Connect {
            proc: pk(100),
            dst: addr,
            proto: Proto::Tcp,
        },
        Event::Listen {
            proc: pk(101),
            addr: addr6,
        },
        Event::FileWrite {
            proc: pk(102),
            path: PathBuf::from("/etc/ld.so.preload"),
            size: 4096,
            sha256: Some(Sha256([0xab; 32])),
            head_entropy: Some(7950),
        },
        Event::FileCreate {
            proc: pk(102),
            path: PathBuf::from("/tmp/x"),
        },
        Event::FileRename {
            proc: pk(102),
            from: PathBuf::from("/tmp/x"),
            to: PathBuf::from("/tmp/y"),
        },
        Event::FileUnlink {
            proc: pk(102),
            path: PathBuf::from("/tmp/y"),
        },
        Event::ModuleLoad {
            proc: pk(103),
            name: OsString::from("evil"),
        },
        Event::Ptrace {
            proc: pk(104),
            target: pk(105),
        },
        Event::Tamper {
            what: TamperKind::SignalReceived {
                from: pk(106),
                signal: 9,
            },
        },
        Event::SensorHealth {
            dropped: 3,
            degraded: false,
        },
    ]
}

pub fn sample_envelope(seq: u64, ts_ns: u64) -> Envelope {
    Envelope {
        seq,
        ts_ns,
        boot_id: BootId(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff),
        event: Event::Exec {
            proc: pk(200 + u32::try_from(seq % 1000).unwrap()),
            parent: pk(1),
            uid: 1000,
            exe: PathBuf::from("/usr/bin/curl"),
            argv: vec![
                OsString::from("curl"),
                OsString::from("https://example.invalid"),
            ],
            cwd: PathBuf::from("/tmp"),
            cgroup: "/user.slice".to_owned(),
            stdio: Vec::new(),
            lineage: Vec::new(),
        },
    }
}
