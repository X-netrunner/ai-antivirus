//! The input bundle for one alert (spec 9): the execution chain, the file's hash, extracted strings, domains and
//! addresses, capped at about 32 KiB. The contents of credential files (SSH and GPG keys, shadow files, browser
//! profiles, password stores, cloud credentials) are never read into a bundle.
//!
//! The spec also names a tree-sitter feature summary. This milestone leaves it out: the model reads the extracted
//! strings itself, and fixed pattern lists would only duplicate what the YARA and behavior rules already do.

use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use ai_antivirus_common::store::AlertRow;
use serde::{Deserialize, Serialize};

/// Largest serialized bundle.
pub const MAX_BUNDLE_BYTES: usize = 32 * 1024;
/// How much of a file is looked at.
pub const MAX_SAMPLE_BYTES: u64 = 256 * 1024;
const MAX_STRINGS: usize = 48;
const MAX_STRING_LEN: usize = 160;
const MIN_STRING_LEN: usize = 6;
const MAX_NAMES: usize = 24;

/// Paths whose contents never leave the file system through the analyzer. `~/` = in any home directory.
const CREDENTIAL_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/ssh/ssh_host_",
    "~/.ssh/",
    "~/.gnupg/",
    "~/.password-store/",
    "~/.local/share/keyrings/",
    "~/.mozilla/",
    "~/.config/chromium/",
    "~/.config/google-chrome/",
    "~/.config/BraveSoftware/",
    "~/.config/vivaldi/",
    "~/.netrc",
    "~/.aws/",
    "~/.kube/",
    "~/.docker/config.json",
    "~/.git-credentials",
];

pub fn is_credential_path(path: &str) -> bool {
    CREDENTIAL_PATHS.iter().any(|p| match p.strip_prefix("~/") {
        Some(rest) => {
            path.strip_prefix("/root/")
                .is_some_and(|t| t.starts_with(rest))
                || path
                    .strip_prefix("/home/")
                    .and_then(|t| t.split_once('/'))
                    .is_some_and(|(_, t)| t.starts_with(rest))
        }
        None => path.starts_with(p),
    })
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub exe: Option<String>,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    /// false when the file was not read (credential path, unreadable, not a regular file).
    pub content_included: bool,
    pub why_not: Option<String>,
    pub size: Option<u64>,
    pub is_text: Option<bool>,
    pub strings: Vec<String>,
    pub domains: Vec<String>,
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bundle {
    pub alert_id: i64,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub process: ProcessInfo,
    pub file: Option<FileInfo>,
    /// The event's own facts (destination, path, window counts ...), as the engine stored them.
    pub evidence: serde_json::Value,
}

/// Runs of printable ASCII of at least `MIN_STRING_LEN` characters, like `strings(1)`, longest 160 characters each.
pub fn extract_strings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let flush = |cur: &mut Vec<u8>, out: &mut Vec<String>| {
        if cur.len() >= MIN_STRING_LEN {
            out.push(String::from_utf8_lossy(&cur[..cur.len().min(MAX_STRING_LEN)]).into_owned());
        }
        cur.clear();
    };
    for &b in data {
        if (0x20..0x7f).contains(&b) || b == b'\t' {
            cur.push(b);
        } else {
            flush(&mut cur, &mut out);
        }
    }
    flush(&mut cur, &mut out);
    // keep the longest, most informative ones, in file order
    if out.len() > MAX_STRINGS {
        let mut idx: Vec<usize> = (0..out.len()).collect();
        idx.sort_by_key(|&i| std::cmp::Reverse(out[i].len()));
        idx.truncate(MAX_STRINGS);
        idx.sort_unstable();
        out = idx.into_iter().map(|i| out[i].clone()).collect();
    }
    out
}

/// Host names and IP addresses mentioned in `text`.
pub fn extract_names(text: &str) -> (Vec<String>, Vec<String>) {
    let mut domains: Vec<String> = Vec::new();
    let mut ips: Vec<String> = Vec::new();
    for tok in
        text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':'))
    {
        let t = tok.trim_matches(|c| c == '.' || c == ':' || c == '-');
        if t.len() < 4 {
            continue;
        }
        // "1.2.3.4:80" -> the address part
        let host = t
            .rsplit_once(':')
            .filter(|(_, p)| p.bytes().all(|c| c.is_ascii_digit()))
            .map_or(t, |(h, _)| h);
        if host.parse::<IpAddr>().is_ok() {
            if !ips.iter().any(|i| i == host) && ips.len() < MAX_NAMES {
                ips.push(host.to_owned());
            }
        } else if host.contains('.')
            && host
                .rsplit('.')
                .next()
                .is_some_and(|tld| tld.len() >= 2 && tld.bytes().all(|c| c.is_ascii_alphabetic()))
            && !domains.iter().any(|d| d == host)
            && domains.len() < MAX_NAMES
        {
            domains.push(host.to_owned());
        }
    }
    (domains, ips)
}

/// Look at a file for the bundle: never a credential path, never anything that is not a regular file.
pub fn inspect_file(path: &str) -> FileInfo {
    let mut info = FileInfo {
        path: path.to_owned(),
        ..FileInfo::default()
    };
    if is_credential_path(path) {
        info.why_not = Some("credential file: contents are never sent to the analyzer".into());
        return info;
    }
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc_flags())
        .open(Path::new(path));
    let file: File = match opened {
        Ok(f) => f,
        Err(e) => {
            info.why_not = Some(format!("cannot open: {e}"));
            return info;
        }
    };
    let Ok(meta) = file.metadata() else {
        info.why_not = Some("cannot stat".into());
        return info;
    };
    if !meta.is_file() {
        info.why_not = Some("not a regular file".into());
        return info;
    }
    info.size = Some(meta.len());
    let mut data = Vec::new();
    if file.take(MAX_SAMPLE_BYTES).read_to_end(&mut data).is_err() {
        info.why_not = Some("read error".into());
        return info;
    }
    info.is_text = Some(!data.contains(&0));
    info.strings = extract_strings(&data);
    let joined = info.strings.join("\n");
    let (domains, ips) = extract_names(&joined);
    info.domains = domains;
    info.ips = ips;
    info.content_included = true;
    info
}

/// `O_NOFOLLOW | O_NONBLOCK`: a symlink swapped in later is not followed and a FIFO cannot hang the read.
fn libc_flags() -> i32 {
    libc::O_NOFOLLOW | libc::O_NONBLOCK
}

impl Bundle {
    pub fn from_alert(alert: &AlertRow, with_file: bool) -> Bundle {
        let d = &alert.detail;
        let s = |k: &str| d.get(k).and_then(|v| v.as_str()).map(str::to_owned);
        let argv: Vec<String> = d
            .get("argv")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        // a file alert names its file; an exec alert (it carries argv) names the program that ran
        let subject = s("path").or_else(|| d.get("argv").and_then(|_| s("exe")));
        let file = if with_file {
            subject
                .filter(|p| p.starts_with('/'))
                .map(|p| inspect_file(&p))
        } else {
            None
        };
        Bundle {
            alert_id: alert.id,
            rule_id: alert.rule_id.clone(),
            title: alert.title.clone(),
            severity: alert.severity.as_str().to_owned(),
            process: ProcessInfo {
                exe: s("exe"),
                argv,
            },
            file,
            evidence: d.clone(),
        }
    }

    /// Serialize, shrinking the strings and the evidence until the result fits in `MAX_BUNDLE_BYTES`.
    pub fn to_json_capped(&self) -> String {
        let mut b = self.clone();
        loop {
            let text = serde_json::to_string(&b).unwrap_or_default();
            if text.len() <= MAX_BUNDLE_BYTES {
                return text;
            }
            if let Some(f) = b.file.as_mut().filter(|f| f.strings.len() > 4) {
                let keep = f.strings.len() / 2;
                f.strings.truncate(keep);
            } else if b.process.argv.len() > 4 {
                let keep = b.process.argv.len() / 2;
                b.process.argv.truncate(keep);
            } else {
                b.evidence = serde_json::json!({"note": "evidence cut to fit the size limit"});
                b.process.argv.clear();
                if let Some(f) = b.file.as_mut() {
                    f.strings.clear();
                }
                return serde_json::to_string(&b).unwrap_or_default();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_antivirus_common::event::ProcKey;
    use ai_antivirus_common::model::Severity;

    #[test]
    fn credential_paths_are_recognized() {
        assert!(is_credential_path("/home/nex/.ssh/id_ed25519"));
        assert!(is_credential_path("/root/.gnupg/secring.gpg"));
        assert!(is_credential_path(
            "/home/nex/.mozilla/firefox/x.default/logins.json"
        ));
        assert!(is_credential_path("/etc/shadow"));
        assert!(!is_credential_path("/home/nex/.sshfs/x"));
        assert!(!is_credential_path("/home/nex/Downloads/a.sh"));
        assert!(!is_credential_path("/tmp/.ssh/x"));
    }

    #[test]
    fn credential_files_are_not_read_even_when_they_exist() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir(&ssh).unwrap();
        // a path under a real home would be refused by name; here a plain file is read, a credential name is not
        let plain = dir.path().join("note.txt");
        std::fs::write(
            &plain,
            "see http://updates.example.invalid/x and 198.51.100.7:8080 for details",
        )
        .unwrap();
        let i = inspect_file(plain.to_str().unwrap());
        assert!(i.content_included);
        assert_eq!(i.domains, ["updates.example.invalid"]);
        assert_eq!(i.ips, ["198.51.100.7"]);
        let cred = inspect_file("/etc/shadow");
        assert!(!cred.content_included && cred.strings.is_empty());
        assert!(inspect_file("/nonexistent/x")
            .why_not
            .unwrap()
            .contains("cannot open"));
        assert_eq!(
            inspect_file(dir.path().to_str().unwrap())
                .why_not
                .as_deref(),
            Some("not a regular file")
        );
    }

    #[test]
    fn symlinks_are_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::write(&real, "hello world strings").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(!inspect_file(link.to_str().unwrap()).content_included);
    }

    #[test]
    fn strings_keep_the_longest_runs_in_order() {
        let mut data = Vec::new();
        for i in 0..200 {
            data.extend_from_slice(format!("short{i}").as_bytes());
            data.push(0);
        }
        data.extend_from_slice(b"this is a rather long readable run of text");
        data.push(0);
        let s = extract_strings(&data);
        assert_eq!(s.len(), MAX_STRINGS);
        assert!(s.iter().any(|x| x.starts_with("this is a rather long")));
        assert!(extract_strings(b"ab\0cd").is_empty());
    }

    #[test]
    fn an_exec_alert_inspects_the_program_that_ran() {
        let dir = tempfile::tempdir().unwrap();
        let prog = dir.path().join("run.sh");
        std::fs::write(
            &prog,
            "#!/bin/sh\necho contacting update.example.invalid now\n",
        )
        .unwrap();
        let mk = |detail: serde_json::Value| AlertRow {
            id: 1,
            ts_ns: 1,
            rule_id: "AV-B-0013".into(),
            severity: Severity::Medium,
            confidence: 0.5,
            title: "t".into(),
            proc_key: None,
            detail,
            acknowledged: false,
        };
        let exec = Bundle::from_alert(
            &mk(serde_json::json!({"exe": prog, "argv": ["run.sh"]})),
            true,
        );
        assert_eq!(exec.file.unwrap().domains, ["update.example.invalid"]);
        // a non-exec alert (no argv) does not read the acting program
        let other = Bundle::from_alert(
            &mk(serde_json::json!({"exe": prog, "dst": "198.51.100.1:443"})),
            true,
        );
        assert!(other.file.is_none());
    }

    #[test]
    fn the_bundle_is_capped() {
        let alert = AlertRow {
            id: 3,
            ts_ns: 1,
            rule_id: "AV-B-0002".into(),
            severity: Severity::High,
            confidence: 0.7,
            title: "t".into(),
            proc_key: Some(ProcKey {
                pid: 5,
                start_ns: 6,
            }),
            detail: serde_json::json!({"exe": "/usr/bin/sh", "argv": vec!["x".repeat(900); 100], "blob": "y".repeat(60_000)}),
            acknowledged: false,
        };
        let b = Bundle::from_alert(&alert, false);
        let text = b.to_json_capped();
        assert!(text.len() <= MAX_BUNDLE_BYTES, "{}", text.len());
        assert!(text.contains("AV-B-0002"));
    }
}
