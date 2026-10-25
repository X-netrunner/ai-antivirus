//! Human-readable rendering of events for `synapsectl tail`.
//!
//! Event fields come from attacker-controlled data (file names, command
//! lines). Everything printed to a terminal goes through [`sanitize`] so a
//! hostile name cannot smuggle in escape sequences.

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::path::Path;

use synapse_common::event::{Envelope, Event};

/// Every `Event::kind()` value, for validating `--kind`.
pub const EVENT_KINDS: [&str; 12] = [
    "exec",
    "exit",
    "connect",
    "listen",
    "file_write",
    "file_create",
    "file_rename",
    "file_unlink",
    "module_load",
    "ptrace",
    "tamper",
    "sensor_health",
];

/// Longest command line shown in the one-line view.
const MAX_ARGV_CHARS: usize = 200;

/// Replace control characters (including ESC) with visible escapes.
pub fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

fn path(p: &Path) -> String {
    sanitize(&p.to_string_lossy())
}

fn os(s: &OsStr) -> String {
    sanitize(&s.to_string_lossy())
}

/// `2023-11-14T22:13:20.123Z` for a Unix-epoch nanosecond timestamp.
pub fn format_ts(ts_ns: u64) -> String {
    let secs = ts_ns / 1_000_000_000;
    let millis = (ts_ns / 1_000_000) % 1000;
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian
/// (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = u32::try_from(day_of_year - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn command_line(argv: &[std::ffi::OsString]) -> String {
    let mut line = String::new();
    for (i, arg) in argv.iter().enumerate() {
        if i > 0 {
            line.push(' ');
        }
        line.push_str(&os(arg));
        if line.chars().count() > MAX_ARGV_CHARS {
            let cut: String = line.chars().take(MAX_ARGV_CHARS).collect();
            return format!("{cut}...");
        }
    }
    line
}

/// One line describing the event (no timestamp).
/// ` stdin=socket:[123]` when stdin is a socket or a pipe (what the reverse-shell and download-and-run rules look at), else nothing.
fn stdin_note(stdio: &[OsString]) -> String {
    match stdio.first().map(|s| s.to_string_lossy()) {
        Some(s) if s.starts_with("socket:") || s.starts_with("pipe:") => {
            format!(" stdin={}", sanitize(&s))
        }
        _ => String::new(),
    }
}

pub fn describe(event: &Event) -> String {
    match event {
        Event::Exec {
            proc,
            parent,
            uid,
            exe,
            argv,
            cwd,
            cgroup,
            stdio,
        } => format!(
            "exec          {proc} ppid={} uid={uid} exe={} cwd={} cgroup={}{} cmd={}",
            parent.pid,
            path(exe),
            path(cwd),
            sanitize(cgroup),
            stdin_note(stdio),
            command_line(argv)
        ),
        Event::Exit { proc, code } => format!("exit          {proc} code={code}"),
        Event::Connect { proc, dst, proto } => {
            let proto = format!("{proto:?}").to_lowercase();
            format!("connect       {proc} {dst} {proto}")
        }
        Event::Listen { proc, addr } => format!("listen        {proc} {addr}"),
        Event::FileWrite {
            proc,
            path: file,
            size,
            sha256,
            head_entropy,
        } => {
            let mut line = format!("file_write    {proc} {} size={size}", path(file));
            if let Some(hash) = sha256 {
                let _ = write!(line, " sha256={hash}");
            }
            if let Some(e) = head_entropy {
                let _ = write!(line, " entropy={}.{:03}", e / 1000, e % 1000);
            }
            line
        }
        Event::FileCreate { proc, path: file } => format!("file_create   {proc} {}", path(file)),
        Event::FileRename { proc, from, to } => {
            format!("file_rename   {proc} {} -> {}", path(from), path(to))
        }
        Event::FileUnlink { proc, path: file } => format!("file_unlink   {proc} {}", path(file)),
        Event::ModuleLoad { proc, name } => format!("module_load   {proc} {}", os(name)),
        Event::Ptrace { proc, target } => format!("ptrace        {proc} -> {target}"),
        Event::Tamper { what } => format!("tamper        {what:?}"),
        Event::SensorHealth { dropped, degraded } => {
            format!("sensor_health dropped={dropped} degraded={degraded}")
        }
    }
}

/// `timestamp  #seq  description`
pub fn format_envelope(env: &Envelope) -> String {
    format!(
        "{} #{:<6} {}",
        format_ts(env.ts_ns),
        env.seq,
        describe(&env.event)
    )
}

/// clap value parser for `--kind`: accept only known event kinds.
pub fn parse_kind(kind: &str) -> Result<String, String> {
    if EVENT_KINDS.contains(&kind) {
        Ok(kind.to_owned())
    } else {
        Err(format!(
            "unknown event kind {kind:?}; valid kinds: {}",
            EVENT_KINDS.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use synapse_common::event::{BootId, ProcKey};

    fn pk(pid: u32) -> ProcKey {
        ProcKey {
            pid,
            start_ns: u64::from(pid) * 10,
        }
    }

    #[test]
    fn timestamps_format_in_utc() {
        assert_eq!(format_ts(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            format_ts(1_700_000_000_123_000_000),
            "2023-11-14T22:13:20.123Z"
        );
        // A leap day.
        assert_eq!(
            format_ts(951_782_400_000_000_000),
            "2000-02-29T00:00:00.000Z"
        );
        assert_eq!(
            format_ts(951_868_800_000_000_000),
            "2000-03-01T00:00:00.000Z"
        );
        // The end of a year.
        assert_eq!(
            format_ts(1_767_225_599_000_000_000),
            "2025-12-31T23:59:59.000Z"
        );
    }

    #[test]
    fn control_characters_are_made_visible() {
        assert_eq!(sanitize("a\x1b[31mred\x07\n"), "a\\u{1b}[31mred\\u{7}\\n");
        assert_eq!(sanitize("plain ünïcode"), "plain ünïcode");
    }

    #[test]
    fn exec_lines_are_sanitized_and_long_command_lines_cut() {
        let event = Event::Exec {
            proc: pk(5),
            parent: pk(1),
            uid: 1000,
            exe: PathBuf::from("/tmp/evil\x1b[2J"),
            argv: vec![OsString::from("x"), OsString::from("y".repeat(500))],
            cwd: PathBuf::from("/tmp"),
            cgroup: "/a.slice".to_owned(),
            stdio: vec![OsString::from("socket:[7]")],
        };
        let line = describe(&event);
        assert!(!line.contains('\x1b'));
        assert!(line.contains("exe=/tmp/evil\\u{1b}[2J"));
        assert!(line.contains(" stdin=socket:[7] cmd="));
        assert!(line.ends_with("..."));
        assert!(line.len() < 450, "command line was not truncated");
    }

    #[test]
    fn descriptions_start_with_the_kind_name() {
        // Guards EVENT_KINDS against drifting from the schema.
        let kinds_in_schema = [
            describe(&Event::Exit {
                proc: pk(1),
                code: 0,
            }),
            describe(&Event::SensorHealth {
                dropped: 1,
                degraded: false,
            }),
            describe(&Event::FileWrite {
                proc: pk(1),
                path: PathBuf::from("/x"),
                size: 3,
                sha256: None,
                head_entropy: None,
            }),
        ];
        for (line, kind) in kinds_in_schema
            .iter()
            .zip(["exit", "sensor_health", "file_write"])
        {
            assert!(line.starts_with(kind), "{line}");
            assert!(EVENT_KINDS.contains(&kind));
        }
    }

    #[test]
    fn envelope_line_has_time_sequence_and_description() {
        let env = Envelope {
            seq: 42,
            ts_ns: 1_700_000_000_000_000_000,
            boot_id: BootId(1),
            event: Event::Exit {
                proc: pk(9),
                code: 0,
            },
        };
        let line = format_envelope(&env);
        assert!(line.starts_with("2023-11-14T22:13:20.000Z #42"), "{line}");
        assert!(line.contains("exit"));
        assert!(line.contains("9:90"));
    }

    #[test]
    fn kind_parser_names_the_valid_choices() {
        assert_eq!(parse_kind("exec").unwrap(), "exec");
        let err = parse_kind("execc").unwrap_err();
        assert!(err.contains("execc") && err.contains("file_write"));
    }
}
