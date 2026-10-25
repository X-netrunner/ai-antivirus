//! `synapse-notify`: runs in your desktop session (a systemd user service), follows the responder's notification spool
//! (`<response.notify_dir>/notify.jsonl`) and shows each entry with `notify-send`. Everything in a notification comes
//! from what Synapse saw on the machine (program names, paths, rule titles), so it is treated as untrusted text: control
//! characters are removed, markup is escaped, lengths are capped, and `notify-send` gets it as plain arguments after
//! `--` (no shell). Your user must be in the `synapse-notify` group to read the spool.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use signal_hook::consts::{SIGINT, SIGTERM};
use synapse_common::config::{Config, DEFAULT_CONFIG_PATH};
use synapse_common::eventlog::Follower;
use synapse_responderd::notify::{Notification, SPOOL};

const POLL: Duration = Duration::from_millis(500);
/// At most this many popups per window; the rest are summed up in one.
const BURST: usize = 5;
const BURST_WINDOW: Duration = Duration::from_secs(30);
const MAX_TITLE: usize = 120;
const MAX_BODY: usize = 500;

#[derive(Parser)]
#[command(
    name = "synapse-notify",
    version,
    about = "Synapse EDR desktop notifier"
)]
struct Cli {
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
    /// Print notifications on stdout instead of showing them.
    #[arg(long)]
    print: bool,
    #[arg(long, default_value = "/usr/bin/notify-send")]
    notify_send: PathBuf,
}

/// Plain, single-paragraph text safe for a notification server that may interpret markup.
fn clean(text: &str, max: usize) -> String {
    let mut out = String::new();
    for c in text
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(max)
    {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
    out
}

fn urgency(severity: &str) -> &'static str {
    match severity {
        "high" | "critical" => "critical",
        "medium" => "normal",
        _ => "low",
    }
}

/// `notify-send` arguments for one notification.
fn args(n: &Notification) -> Vec<String> {
    let title = clean(&format!("Synapse: {}", n.title), MAX_TITLE);
    let mut body = format!("{} [{}]", n.rule_id, n.severity);
    if !n.summary.is_empty() {
        body.push('\n');
        body.push_str(&n.summary);
    }
    vec![
        "--app-name=Synapse".into(),
        format!("--urgency={}", urgency(&n.severity)),
        "--icon=security-high".into(),
        "--".into(),
        title,
        clean(&body, MAX_BODY),
    ]
}

/// Lets `BURST` notifications through per window and counts the rest.
struct Limiter {
    since: Instant,
    shown: usize,
    held: usize,
}

impl Limiter {
    fn new(now: Instant) -> Limiter {
        Limiter {
            since: now,
            shown: 0,
            held: 0,
        }
    }

    /// true: show it. When a window ends with held-back notifications, `flush` reports how many.
    fn admit(&mut self, now: Instant) -> bool {
        if now.duration_since(self.since) >= BURST_WINDOW {
            self.since = now;
            self.shown = 0;
        }
        if self.shown < BURST {
            self.shown += 1;
            true
        } else {
            self.held += 1;
            false
        }
    }

    fn flush(&mut self, now: Instant) -> Option<usize> {
        (self.held > 0 && now.duration_since(self.since) >= BURST_WINDOW)
            .then(|| std::mem::take(&mut self.held))
    }
}

fn show(cli: &Cli, a: &[String]) {
    if cli.print {
        println!("{}", a.get(4..).unwrap_or_default().join(" | "));
        return;
    }
    let r = Command::new(&cli.notify_send)
        .args(a)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status();
    if let Err(e) = r {
        eprintln!(
            "synapse-notify: cannot run {}: {e}",
            cli.notify_send.display()
        );
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let dir = match Config::load(&cli.config) {
        Ok(c) => c.response.notify_dir,
        Err(e) => {
            eprintln!("synapse-notify: {e}; using the default notification folder");
            Config::default().response.notify_dir
        }
    };
    let spool = dir.join(SPOOL);
    let mut follower = match Follower::from_end(&spool) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("synapse-notify: {e} (is your user in the synapse-notify group?)");
            return ExitCode::FAILURE;
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    for s in [SIGINT, SIGTERM] {
        if let Err(e) = signal_hook::flag::register(s, Arc::clone(&stop)) {
            eprintln!("synapse-notify: cannot install signal handler: {e}");
            return ExitCode::FAILURE;
        }
    }
    let mut limiter = Limiter::new(Instant::now());
    let mut warned = false;
    while !stop.load(Ordering::Relaxed) {
        match follower.poll() {
            Ok(lines) => {
                warned = false;
                for l in lines {
                    let Ok(n) = serde_json::from_slice::<Notification>(&l) else {
                        continue;
                    };
                    if limiter.admit(Instant::now()) {
                        show(&cli, &args(&n));
                    }
                }
            }
            Err(e) if !warned => {
                eprintln!("synapse-notify: {e}");
                warned = true;
            }
            Err(_) => {}
        }
        if let Some(n) = limiter.flush(Instant::now()) {
            let a = vec![
                "--app-name=Synapse".into(),
                "--urgency=normal".into(),
                "--".into(),
                "Synapse".into(),
                format!("{n} more notifications were held back. See: synapsectl actions"),
            ];
            show(&cli, &a);
        }
        std::thread::sleep(POLL);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_text_is_cleaned() {
        assert_eq!(
            clean("a\x1b[31mb<i>&</i>", 100),
            "a[31mb&lt;i&gt;&amp;&lt;/i&gt;"
        );
        assert_eq!(clean("abcdef", 3), "abc");
        let n = Notification {
            ts_ns: 0,
            alert_id: None,
            action_id: Some(3),
            rule_id: "SYN-B-0001".into(),
            severity: "high".into(),
            title: "--help".into(),
            summary: "Would freeze".into(),
        };
        let a = args(&n);
        assert_eq!(a[1], "--urgency=critical");
        assert_eq!(a[3], "--", "everything after is a plain argument");
        assert_eq!(a[4], "Synapse: --help");
        assert_eq!(a[5], "SYN-B-0001 [high]\nWould freeze");
    }

    #[test]
    fn bursts_are_held_back_and_counted() {
        let t = Instant::now();
        let mut l = Limiter::new(t);
        let shown = (0..8).filter(|_| l.admit(t)).count();
        assert_eq!(shown, BURST);
        assert_eq!(l.flush(t), None, "window not over");
        let later = t + BURST_WINDOW;
        assert_eq!(l.flush(later), Some(3));
        assert_eq!(l.flush(later), None);
        assert!(l.admit(later));
    }
}
