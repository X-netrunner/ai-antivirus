//! Event schema shared by every AI Antivirus process (spec section 6).
//!
//! Conventions:
//! * `Envelope::ts_ns` is wall-clock nanoseconds since the Unix epoch.
//! * `ProcKey::start_ns` is the process start time in nanoseconds since boot.
//!   It is only unique within one `BootId`, which the `Envelope` carries.
//! * Linux paths and arguments are arbitrary bytes. They serialize as a plain
//!   JSON string when valid UTF-8 and as `{"hex": "..."}` otherwise, so the
//!   round trip is lossless and the common case stays readable.

use std::ffi::OsString;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Current wall-clock time as nanoseconds since the Unix epoch.
/// Returns 0 if the clock is before the epoch and saturates far in the future.
pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// hex helpers
// ---------------------------------------------------------------------------

pub(crate) mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(char::from(DIGITS[usize::from(b >> 4)]));
            out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
        }
        out
    }

    pub fn decode(s: &str) -> Option<Vec<u8>> {
        let bytes = s.as_bytes();
        if bytes.len() % 2 != 0 {
            return None;
        }
        let mut out = Vec::with_capacity(bytes.len() / 2);
        for pair in bytes.chunks_exact(2) {
            let hi = nibble(*pair.first()?)?;
            let lo = nibble(*pair.get(1)?)?;
            out.push((hi << 4) | lo);
        }
        Some(out)
    }

    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// identifiers
// ---------------------------------------------------------------------------

/// A process identity that survives PID reuse: PID plus start time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProcKey {
    pub pid: u32,
    pub start_ns: u64,
}

impl fmt::Display for ProcKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.pid, self.start_ns)
    }
}

/// The kernel boot id (`/proc/sys/kernel/random/boot_id`), as a 128-bit value.
/// Serialized as 32 lowercase hex digits because JSON numbers cannot hold it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BootId(pub u128);

impl BootId {
    /// Parse the kernel's UUID text form (dashes optional).
    pub fn parse(s: &str) -> Option<BootId> {
        let hex: String = s.trim().chars().filter(|c| *c != '-').collect();
        if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        u128::from_str_radix(&hex, 16).ok().map(BootId)
    }
}

impl fmt::Display for BootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

impl fmt::Debug for BootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BootId({self})")
    }
}

impl FromStr for BootId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BootId::parse(s).ok_or_else(|| format!("invalid boot id {s:?}"))
    }
}

impl Serialize for BootId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for BootId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(D::Error::custom)
    }
}

/// A SHA-256 digest, serialized as 64 lowercase hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256(pub [u8; 32]);

impl Sha256 {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Sha256> {
        <[u8; 32]>::try_from(bytes).ok().map(Sha256)
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256({self})")
    }
}

impl FromStr for Sha256 {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).ok_or_else(|| "sha256 must be hex".to_owned())?;
        Sha256::from_slice(&bytes).ok_or_else(|| "sha256 must be 64 hex digits".to_owned())
    }
}

impl Serialize for Sha256 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Sha256 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(D::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// lossless OS-string serialization
// ---------------------------------------------------------------------------

mod os_serde {
    use super::hex;
    use serde::ser::SerializeStruct;
    use serde::{Deserialize, Deserializer, Serializer};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Text(String),
        Bytes { hex: String },
    }

    impl Raw {
        fn into_bytes<E: serde::de::Error>(self) -> Result<Vec<u8>, E> {
            match self {
                Raw::Text(s) => Ok(s.into_bytes()),
                Raw::Bytes { hex } => {
                    hex::decode(&hex).ok_or_else(|| E::custom("invalid hex in byte string"))
                }
            }
        }
    }

    fn ser_bytes<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        match std::str::from_utf8(bytes) {
            Ok(text) => s.serialize_str(text),
            Err(_) => {
                let mut st = s.serialize_struct("RawBytes", 1)?;
                st.serialize_field("hex", &hex::encode(bytes))?;
                st.end()
            }
        }
    }

    pub mod path {
        use super::*;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        use std::path::{Path, PathBuf};

        pub fn serialize<S: Serializer>(p: &Path, s: S) -> Result<S::Ok, S::Error> {
            ser_bytes(p.as_os_str().as_bytes(), s)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PathBuf, D::Error> {
            let bytes = Raw::deserialize(d)?.into_bytes()?;
            Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
        }
    }

    pub mod string {
        use super::*;
        use std::ffi::{OsStr, OsString};
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        pub fn serialize<S: Serializer>(v: &OsStr, s: S) -> Result<S::Ok, S::Error> {
            ser_bytes(v.as_bytes(), s)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<OsString, D::Error> {
            let bytes = Raw::deserialize(d)?.into_bytes()?;
            Ok(OsString::from_vec(bytes))
        }
    }

    pub mod string_vec {
        use super::*;
        use serde::Serialize;
        use std::ffi::{OsStr, OsString};
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        struct One<'a>(&'a OsStr);

        impl Serialize for One<'_> {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                ser_bytes(self.0.as_bytes(), s)
            }
        }

        pub fn serialize<S: Serializer>(v: &[OsString], s: S) -> Result<S::Ok, S::Error> {
            s.collect_seq(v.iter().map(|x| One(x)))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<OsString>, D::Error> {
            Vec::<Raw>::deserialize(d)?
                .into_iter()
                .map(|r| r.into_bytes().map(OsString::from_vec))
                .collect()
        }
    }
}

// ---------------------------------------------------------------------------
// events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    Tcp,
    Udp,
}

/// What kind of tampering with AI Antivirus itself was observed (spec section 10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TamperKind {
    BinaryModified {
        #[serde(with = "os_serde::path")]
        path: PathBuf,
    },
    ConfigModified {
        #[serde(with = "os_serde::path")]
        path: PathBuf,
    },
    RuleBundleInvalid,
    ProbeDetached,
    SensorSilent,
    SignalReceived {
        from: ProcKey,
        signal: i32,
    },
    PtraceAttach {
        from: ProcKey,
    },
}

/// One observation. Variants follow spec section 6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Exec {
        proc: ProcKey,
        parent: ProcKey,
        uid: u32,
        #[serde(with = "os_serde::path")]
        exe: PathBuf,
        #[serde(with = "os_serde::string_vec")]
        argv: Vec<OsString>,
        #[serde(with = "os_serde::path")]
        cwd: PathBuf,
        cgroup: String,
        /// Where fds 0, 1 and 2 pointed at exec time, as `readlink /proc/<pid>/fd/N` shows them (`socket:[123]`, `pipe:[456]`,
        /// `/dev/pts/1`); empty entries for unreadable fds, an empty list when not collected. Added in M3; older logs omit it.
        #[serde(
            default,
            skip_serializing_if = "Vec::is_empty",
            with = "os_serde::string_vec"
        )]
        stdio: Vec<OsString>,
        /// The process's ancestors as the sensor's process table knows them, nearest first (parent, grandparent ...), up to
        /// 24. Includes processes that only forked and never exec'd (the subshells of a script), which no `exec` event
        /// describes, so the engine can still follow the chain to the program that started them. Added in M8; older logs
        /// omit it.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        lineage: Vec<ProcKey>,
    },
    Exit {
        proc: ProcKey,
        code: i32,
    },
    Connect {
        proc: ProcKey,
        dst: SocketAddr,
        proto: Proto,
    },
    Listen {
        proc: ProcKey,
        addr: SocketAddr,
    },
    FileWrite {
        proc: ProcKey,
        #[serde(with = "os_serde::path")]
        path: PathBuf,
        size: u64,
        sha256: Option<Sha256>,
        /// Entropy of the file's first 4 KiB in milli-bits per byte (0..=8000), see `entropy::shannon_milli`; None when the
        /// file is too small or was not readable. Added in M3; older logs omit it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        head_entropy: Option<u16>,
    },
    FileCreate {
        proc: ProcKey,
        #[serde(with = "os_serde::path")]
        path: PathBuf,
    },
    FileRename {
        proc: ProcKey,
        #[serde(with = "os_serde::path")]
        from: PathBuf,
        #[serde(with = "os_serde::path")]
        to: PathBuf,
    },
    FileUnlink {
        proc: ProcKey,
        #[serde(with = "os_serde::path")]
        path: PathBuf,
    },
    ModuleLoad {
        proc: ProcKey,
        #[serde(with = "os_serde::string")]
        name: OsString,
    },
    Ptrace {
        proc: ProcKey,
        target: ProcKey,
    },
    Tamper {
        what: TamperKind,
    },
    SensorHealth {
        dropped: u64,
        degraded: bool,
    },
}

impl Event {
    /// Stable snake_case name; identical to the serialized `type` tag.
    pub fn kind(&self) -> &'static str {
        match self {
            Event::Exec { .. } => "exec",
            Event::Exit { .. } => "exit",
            Event::Connect { .. } => "connect",
            Event::Listen { .. } => "listen",
            Event::FileWrite { .. } => "file_write",
            Event::FileCreate { .. } => "file_create",
            Event::FileRename { .. } => "file_rename",
            Event::FileUnlink { .. } => "file_unlink",
            Event::ModuleLoad { .. } => "module_load",
            Event::Ptrace { .. } => "ptrace",
            Event::Tamper { .. } => "tamper",
            Event::SensorHealth { .. } => "sensor_health",
        }
    }

    /// The acting process, for events that have one.
    pub fn proc_key(&self) -> Option<ProcKey> {
        match self {
            Event::Exec { proc, .. }
            | Event::Exit { proc, .. }
            | Event::Connect { proc, .. }
            | Event::Listen { proc, .. }
            | Event::FileWrite { proc, .. }
            | Event::FileCreate { proc, .. }
            | Event::FileRename { proc, .. }
            | Event::FileUnlink { proc, .. }
            | Event::ModuleLoad { proc, .. }
            | Event::Ptrace { proc, .. } => Some(*proc),
            Event::Tamper { .. } | Event::SensorHealth { .. } => None,
        }
    }
}

/// An event plus the metadata every consumer needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Monotonic per sensor run. Not unique across sensor restarts.
    pub seq: u64,
    /// Wall-clock nanoseconds since the Unix epoch.
    pub ts_ns: u64,
    pub boot_id: BootId,
    pub event: Event,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{all_event_variants, sample_envelope};
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn every_variant_round_trips_and_tag_matches_kind() {
        for event in all_event_variants() {
            let json = serde_json::to_string(&event).unwrap();
            let back: Event = serde_json::from_str(&json).unwrap();
            assert_eq!(back, event, "round trip failed for {json}");

            let value = serde_json::to_value(&event).unwrap();
            assert_eq!(value["type"], event.kind());
        }
    }

    #[test]
    fn variant_list_is_exhaustive_by_kind() {
        let mut kinds: Vec<_> = all_event_variants().iter().map(Event::kind).collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), 12);
    }

    #[test]
    fn envelope_round_trips() {
        let env = sample_envelope(7, 1_700_000_000_000_000_000);
        let json = serde_json::to_string(&env).unwrap();
        assert_eq!(serde_json::from_str::<Envelope>(&json).unwrap(), env);
        assert!(json.contains("\"boot_id\":\"00112233445566778899aabbccddeeff\""));
    }

    /// Mutated event-log lines never panic the parser, and any that still parse survive a round trip.
    #[test]
    fn mutated_event_log_lines_never_panic() {
        let mut state: u64 = 0x5EED_1234_ABCD_9876;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut parsed = 0u32;
        for (n, event) in crate::testutil::all_event_variants()
            .into_iter()
            .enumerate()
        {
            let env = Envelope {
                seq: n as u64,
                ts_ns: 1,
                boot_id: BootId(7),
                event,
            };
            let line = serde_json::to_vec(&env).unwrap();
            for _ in 0..3_000 {
                let mut b = line.clone();
                for _ in 0..1 + (next() % 3) as usize {
                    let at = (next() % b.len().max(1) as u64) as usize;
                    match next() % 4 {
                        0 => b[at] ^= 1 << (next() % 8),
                        1 => {
                            b.remove(at);
                        }
                        2 => b.insert(at, (next() & 0xff) as u8),
                        _ => b.truncate(at),
                    }
                    if b.is_empty() {
                        b.push(b'{');
                    }
                }
                if let Ok(back) = serde_json::from_slice::<Envelope>(&b) {
                    parsed += 1;
                    let again = serde_json::to_vec(&back).unwrap();
                    assert_eq!(serde_json::from_slice::<Envelope>(&again).unwrap(), back);
                }
            }
        }
        assert!(parsed > 0);
    }

    #[test]
    fn exec_without_stdio_from_an_m2_log_still_parses() {
        let line = r#"{"type":"exec","proc":{"pid":5,"start_ns":9},"parent":{"pid":1,"start_ns":1},"uid":0,"exe":"/usr/bin/sh","argv":["sh"],"cwd":"/","cgroup":""}"#;
        let event: Event = serde_json::from_str(line).unwrap();
        assert!(matches!(event, Event::Exec { ref stdio, .. } if stdio.is_empty()));
        // and an empty list is not written out
        assert!(!serde_json::to_string(&event).unwrap().contains("stdio"));
    }

    #[test]
    fn non_utf8_paths_and_args_survive() {
        let raw = vec![b'/', b't', b'm', b'p', b'/', 0xff, 0xfe];
        let event = Event::Exec {
            proc: ProcKey {
                pid: 1,
                start_ns: 2,
            },
            parent: ProcKey {
                pid: 0,
                start_ns: 0,
            },
            uid: 1000,
            exe: PathBuf::from(OsString::from_vec(raw.clone())),
            argv: vec![OsString::from("ok"), OsString::from_vec(vec![0x80])],
            cwd: PathBuf::from("/"),
            cgroup: String::new(),
            stdio: Vec::new(),
            lineage: Vec::new(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#"{"hex":"2f746d702ffffe"}"#));
        assert!(json.contains(r#""ok""#), "valid UTF-8 stays readable");
        assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), event);
    }

    #[test]
    fn malformed_byte_strings_are_rejected() {
        let bad = r#"{"type":"file_create","proc":{"pid":1,"start_ns":1},"path":{"hex":"zz"}}"#;
        assert!(serde_json::from_str::<Event>(bad).is_err());
        let odd = r#"{"type":"file_create","proc":{"pid":1,"start_ns":1},"path":{"hex":"abc"}}"#;
        assert!(serde_json::from_str::<Event>(odd).is_err());
    }

    #[test]
    fn unknown_event_type_is_rejected() {
        assert!(serde_json::from_str::<Event>(r#"{"type":"bogus"}"#).is_err());
    }

    #[test]
    fn boot_id_parsing() {
        let id = BootId::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        assert_eq!(id.to_string(), "00112233445566778899aabbccddeeff");
        assert_eq!(BootId::parse(&id.to_string()), Some(id));
        assert!(BootId::parse("").is_none());
        assert!(BootId::parse("+0112233445566778899aabbccddeeff").is_none());
        assert!(BootId::parse("0011223344556677889").is_none());
    }

    #[test]
    fn sha256_parsing() {
        let hexstr = "ab".repeat(32);
        let digest: Sha256 = hexstr.parse().unwrap();
        assert_eq!(digest.to_string(), hexstr);
        assert!("ab".repeat(31).parse::<Sha256>().is_err());
        assert!("zz".repeat(32).parse::<Sha256>().is_err());
    }

    #[test]
    fn proc_key_helpers() {
        let key = ProcKey {
            pid: 42,
            start_ns: 99,
        };
        assert_eq!(key.to_string(), "42:99");
        let with_proc = all_event_variants()
            .into_iter()
            .filter(|e| e.proc_key().is_some())
            .count();
        assert_eq!(with_proc, 10);
    }

    #[test]
    fn now_ns_is_plausible() {
        // After 2020-01-01.
        assert!(now_ns() > 1_577_836_800_000_000_000);
    }
}
