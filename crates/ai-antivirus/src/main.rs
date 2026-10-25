//! `ai-antivirus`: command line interface for AI Antivirus.
//!
//! Commands: `config-check`, `db-init`, `db-stats`, `db-cleanup` (M0),
//! `tail` (M1), `alerts`, `scan`, `rules`, `trust-baseline`, `integrity`,
//! `hash-add` (M3), and `actions`, `approve`, `reject`, `undo`, `breaker-reset`,
//! `responder-status` (M4).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod advice;
mod ask;
mod detect;
mod except;
mod pacman;
mod render;
mod respond;
mod sign;
mod status;
mod update;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use ai_antivirus_common::config::{
    Config, LogFormat, LogLevel, LoggingConfig, DEFAULT_CONFIG_PATH,
};
use ai_antivirus_common::event::{now_ns, Envelope};
use ai_antivirus_common::eventlog::{self, Follower};
use ai_antivirus_common::store::Store;
use ai_antivirus_common::{logging, Error};
use ai_antivirus_responderd::ipc::Request;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ai-antivirus", version, about = "AI Antivirus control tool")]
struct Cli {
    /// Path to the configuration file.
    #[arg(long, global = true, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate the configuration file and summarize it.
    ConfigCheck {
        /// Also print the effective configuration as TOML.
        #[arg(long)]
        print: bool,
    },
    /// Create the database and apply the schema (idempotent).
    DbInit {
        /// Database path; defaults to <state_dir>/ai-antivirus.db from the config.
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Show schema version, row counts and sizes.
    DbStats {
        /// Database path; defaults to <state_dir>/ai-antivirus.db from the config.
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Apply retention (age and size) to the event table.
    DbCleanup {
        /// Database path; defaults to <state_dir>/ai-antivirus.db from the config.
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Show recent events from the JSONL event log, optionally following it.
    Tail {
        /// Number of recent events to show first.
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
        /// Keep running and print new events as they arrive.
        #[arg(short, long)]
        follow: bool,
        /// Print the raw JSON lines instead of the readable form.
        #[arg(long)]
        json: bool,
        /// Only show these event kinds (comma separated), e.g. exec,file_write.
        #[arg(long, value_delimiter = ',', value_parser = render::parse_kind)]
        kind: Vec<String>,
        /// Read this file instead of <log_dir>/events.jsonl from the config.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Show the newest alerts from the database.
    Alerts {
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
        /// One JSON object per line.
        #[arg(long)]
        json: bool,
        /// Only alerts not acknowledged yet.
        #[arg(long)]
        unacked: bool,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Mark alerts as seen: by id, or every one with --all.
    Ack {
        ids: Vec<i64>,
        #[arg(long, conflicts_with = "ids")]
        all: bool,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Ask the local model about what AI Antivirus saw (advice only; the model is the one in [ai], loopback only).
    Ask {
        question: Vec<String>,
        /// JSON lines (model, done / error), for the Halcyon Security center.
        #[arg(long)]
        json: bool,
    },
    /// Services, sensor health, last event, alerts in the last 24 h, pending actions. Works without root.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Programs and folders left alone (AI coding tools by default). Lists them; `add`, `remove` and `reset` need root.
    Exceptions {
        #[command(subcommand)]
        action: Option<ExceptionCmd>,
        /// One JSON object (for the Halcyon Security center).
        #[arg(long)]
        json: bool,
    },
    /// Validate a new rules directory and install it in place of `engine.rules_dir` (the old set is kept as .prev).
    RulesUpdate {
        dir: PathBuf,
        /// Only validate and show what would change.
        #[arg(long)]
        dry_run: bool,
        /// Rules directory to replace instead of `engine.rules_dir`.
        #[arg(long)]
        target: Option<PathBuf>,
    },
    /// Put the previous rule set (.prev) back.
    RulesRollback {
        #[arg(long)]
        target: Option<PathBuf>,
    },
    /// Check files now (pacman trust, hash table, YARA). Directories are walked; symlinks are not followed.
    /// Exits with status 1 when anything was found.
    Scan {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Only print findings.
        #[arg(short, long)]
        quiet: bool,
        /// One JSON object per finding, then a summary object.
        #[arg(long, conflicts_with = "quiet")]
        json: bool,
        /// Scan threads (default: one per core, up to 8).
        #[arg(short, long)]
        jobs: Option<usize>,
        /// Rules directory instead of `engine.rules_dir`.
        #[arg(long)]
        rules: Option<PathBuf>,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Validate the behavior and YARA rules and list them.
    Rules {
        /// Rules directory instead of `engine.rules_dir`.
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Load what pacman installed (every package's mtree) into the trust cache.
    TrustBaseline {
        #[arg(long)]
        db: Option<PathBuf>,
        /// pacman's local database (default /var/lib/pacman/local).
        #[arg(long)]
        pacman_local: Option<PathBuf>,
    },
    /// Hash every package file in the trust cache and report the ones that differ from pacman's record.
    /// Exits with status 1 when a file differs.
    Integrity {
        /// Only this package.
        #[arg(long)]
        package: Option<String>,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Show what the responder did, would do, or waits for approval to do.
    Actions {
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
        /// Only actions waiting for approval.
        #[arg(long)]
        pending: bool,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Approve a pending action; the responder runs it now (root).
    Approve {
        id: i64,
        #[arg(long)]
        json: bool,
    },
    /// Reject a pending action (root).
    Reject {
        id: i64,
        #[arg(long)]
        json: bool,
    },
    /// Reverse an executed action: thaw, restore a quarantined file, lift a block (root).
    Undo {
        id: i64,
        #[arg(long)]
        json: bool,
    },
    /// Close the circuit breaker so automatic actions resume (root).
    BreakerReset {
        #[arg(long)]
        json: bool,
    },
    /// Mode, dry-run, circuit breaker and pending count, from the running responder (root).
    ResponderStatus {
        #[arg(long)]
        json: bool,
    },
    /// Add a file or SHA-256 to the hash table as bad (the default) or good.
    /// Show what the AI analyzer said about alerts (advice only).
    AiNotes {
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// List rule proposals (from the AI analyzer) and their state.
    Proposals {
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Show the exact rule that approving a proposal would install.
    ProposalShow {
        id: i64,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Approve a pending rule proposal: installs it as a LOCAL rule (run as root; the engine reloads it).
    ApproveRule {
        id: i64,
        #[arg(long)]
        db: Option<PathBuf>,
        /// Rules directory instead of `engine.rules_dir`.
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Signing key: the bundle is signed again after installing (needed when engine.require_signed_rules is on).
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Create the rule-signing key pair (rules-signing.key mode 0600, rules.pub) in DIR.
    Keygen {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Sign the rules directory (writes bundle.manifest and bundle.sig).
    RulesSign {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Check that the rules directory is exactly what was signed. Exit 2 when it is not.
    RulesVerify {
        #[arg(long)]
        pubkey: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// pacman PreTransaction hook: confirms AI Antivirus stays passive while pacman holds its lock.
    PacmanBegin,
    /// pacman PostTransaction hook: package names on stdin; refreshes the trust cache for them.
    PacmanEnd {
        #[arg(long)]
        db: Option<PathBuf>,
        /// pacman's local database (default /var/lib/pacman/local).
        #[arg(long)]
        pacman_local: Option<PathBuf>,
    },
    /// Look at a PKGBUILD directory (the PKGBUILD and its .install and patch files) before building it.
    /// Exits with status 1 when something was found.
    ScanPkgbuild {
        dir: PathBuf,
        /// Rules directory instead of `engine.rules_dir`.
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Reject a pending rule proposal.
    RejectRule {
        id: i64,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    HashAdd {
        /// A file, or a SHA-256 in hex.
        what: String,
        #[arg(long)]
        good: bool,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        db: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ExceptionCmd {
    /// Show the exceptions.
    List,
    /// Leave a program (a name such as `claude`, or a path) or a folder alone.
    Add {
        /// program or folder
        kind: ai_antivirus_common::exceptions::Kind,
        /// A program name (`claude`), a program path (`~/.local/bin/tool`, `/opt/app/*`) or a folder (`~/samples`).
        #[arg(value_name = "MATCH")]
        pattern: String,
        /// What it is ("Claude Code").
        #[arg(long)]
        name: Option<String>,
    },
    /// Remove an exception (by its match).
    Remove {
        #[arg(value_name = "MATCH")]
        pattern: String,
    },
    /// Go back to the built-in exceptions.
    Reset,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // Quiet by default for a CLI; RUST_LOG overrides.
    let _ = logging::init(&LoggingConfig {
        level: LogLevel::Warn,
        format: LogFormat::Text,
    });

    // M3 commands report plain messages and may exit 1 for "found something"
    let found = match &cli.command {
        Command::Alerts {
            lines,
            json,
            unacked,
            db,
        } => Some(
            detect::alerts(&cli.config, db.as_deref(), *lines, *json, *unacked).map(|()| false),
        ),
        Command::Ack { ids, all, db } => {
            Some(detect::ack(&cli.config, db.as_deref(), ids, *all).map(|()| false))
        }
        Command::Status { json } => Some(status::status(&cli.config, *json).map(|()| false)),
        Command::Exceptions { action, json } => Some(
            match action {
                None | Some(ExceptionCmd::List) => except::list(&cli.config, *json),
                Some(ExceptionCmd::Add {
                    kind,
                    pattern,
                    name,
                }) => except::add(&cli.config, *kind, pattern, name.as_deref()),
                Some(ExceptionCmd::Remove { pattern }) => except::remove(&cli.config, pattern),
                Some(ExceptionCmd::Reset) => except::reset(&cli.config),
            }
            .map(|()| false),
        ),
        Command::Ask { question, json } => {
            Some(ask::ask(&cli.config, &question.join(" "), *json).map(|()| false))
        }
        Command::RulesUpdate {
            dir,
            dry_run,
            target,
        } => Some(
            update::rules_update(&cli.config, dir, *dry_run, target.as_deref()).map(|()| false),
        ),
        Command::RulesRollback { target } => {
            Some(update::rules_rollback(&cli.config, target.as_deref()).map(|()| false))
        }
        Command::Scan {
            paths,
            quiet,
            json,
            jobs,
            rules,
            db,
        } => Some(detect::scan(
            &cli.config,
            db.as_deref(),
            rules.as_deref(),
            paths,
            if *json {
                detect::ScanOutput::Json
            } else if *quiet {
                detect::ScanOutput::Quiet
            } else {
                detect::ScanOutput::All
            },
            *jobs,
        )),
        Command::Rules { dir } => Some(detect::rules(&cli.config, dir.as_deref()).map(|()| false)),
        Command::TrustBaseline { db, pacman_local } => Some(
            detect::trust_baseline(&cli.config, db.as_deref(), pacman_local.as_deref())
                .map(|()| false),
        ),
        Command::Integrity { package, db } => Some(detect::integrity(
            &cli.config,
            db.as_deref(),
            package.as_deref(),
        )),
        Command::HashAdd {
            what,
            good,
            label,
            db,
        } => Some(
            detect::hash_add(&cli.config, db.as_deref(), what, *good, label.as_deref())
                .map(|()| false),
        ),
        Command::Actions {
            lines,
            pending,
            json,
            db,
        } => Some(
            respond::actions(&cli.config, db.as_deref(), *lines, *json, *pending).map(|()| false),
        ),
        Command::AiNotes { lines, json, db } => {
            Some(advice::ai_notes(&cli.config, db.as_deref(), *lines, *json).map(|()| false))
        }
        Command::Proposals { lines, json, db } => {
            Some(advice::proposals(&cli.config, db.as_deref(), *lines, *json).map(|()| false))
        }
        Command::ProposalShow { id, db } => {
            Some(advice::proposal_show(&cli.config, db.as_deref(), *id).map(|()| false))
        }
        Command::ApproveRule { id, db, rules, key } => Some(
            advice::approve_rule(
                &cli.config,
                db.as_deref(),
                *id,
                rules.as_deref(),
                key.as_deref(),
            )
            .map(|()| false),
        ),
        Command::PacmanBegin => Some(pacman::pacman_begin().map(|()| false)),
        Command::PacmanEnd { db, pacman_local } => {
            if pacman::stdin_is_terminal() {
                println!("ai-antivirus: pacman-end reads package names from stdin (the pacman hook passes them)");
                return ExitCode::SUCCESS;
            }
            Some(
                pacman::pacman_end(
                    &cli.config,
                    db.as_deref(),
                    pacman_local.as_deref(),
                    &mut std::io::stdin().lock(),
                )
                .map(|()| false),
            )
        }
        Command::ScanPkgbuild { dir, rules } => {
            Some(pacman::scan_pkgbuild(&cli.config, dir, rules.as_deref()))
        }
        Command::Keygen { dir } => Some(sign::keygen(dir).map(|()| false)),
        Command::RulesSign { key, dir } => {
            Some(sign::rules_sign(&cli.config, dir.as_deref(), key).map(|()| false))
        }
        Command::RulesVerify { pubkey, dir } => {
            Some(sign::rules_verify(&cli.config, dir.as_deref(), pubkey.as_deref()).map(|()| false))
        }
        Command::RejectRule { id, reason, db } => Some(
            advice::reject_rule(&cli.config, db.as_deref(), *id, reason.as_deref()).map(|()| false),
        ),
        Command::Approve { id, json } => control(&cli.config, &Request::Approve { id: *id }, *json),
        Command::Reject { id, json } => control(&cli.config, &Request::Reject { id: *id }, *json),
        Command::Undo { id, json } => control(&cli.config, &Request::Undo { id: *id }, *json),
        Command::BreakerReset { json } => control(&cli.config, &Request::BreakerReset, *json),
        Command::ResponderStatus { json } => control(&cli.config, &Request::Status, *json),
        _ => None,
    };
    if let Some(r) = found {
        return match r {
            Ok(false) => ExitCode::SUCCESS,
            Ok(true) => ExitCode::from(1),
            // `ai-antivirus alerts | head` closes the pipe; that is not an error either
            Err(e) if e.contains("Broken pipe") => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        };
    }

    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        // `ai-antivirus tail -f | head` closes the pipe; that is not an error.
        Err(Error::Io { source, .. }) if source.kind() == io::ErrorKind::BrokenPipe => {
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// A refused request exits with status 1, like "found something".
fn control(cfg: &Path, req: &Request, json: bool) -> Option<Result<bool, String>> {
    Some(respond::control(cfg, req, json).map(|ok| !ok))
}

fn run(cli: &Cli) -> Result<(), Error> {
    match &cli.command {
        Command::ConfigCheck { print } => config_check(&cli.config, *print),
        Command::DbInit { db } => {
            let path = db_path(&cli.config, db.as_deref())?;
            let store = Store::open(&path)?;
            println!(
                "database ready: {} (schema v{})",
                path.display(),
                store.schema_version()?
            );
            Ok(())
        }
        Command::DbStats { db } => {
            let path = db_path(&cli.config, db.as_deref())?;
            let s = Store::open(&path)?.stats()?;
            println!("database      {}", path.display());
            println!("schema        v{}", s.schema_version);
            println!(
                "size          {} bytes used, {} on disk",
                s.used_bytes, s.file_bytes
            );
            for (name, n) in [
                ("events", s.events),
                ("alerts", s.alerts),
                ("verdicts", s.verdicts),
                ("actions", s.actions),
                ("proposals", s.proposals),
                ("hashes", s.hashes),
                ("baselines", s.baselines),
                ("trust_cache", s.trust_cache),
            ] {
                println!("{name:<13} {n}");
            }
            Ok(())
        }
        Command::Tail {
            lines,
            follow,
            json,
            kind,
            file,
        } => tail(
            &cli.config,
            &TailOptions {
                lines: *lines,
                follow: *follow,
                json: *json,
                kinds: kind,
                file: file.as_deref(),
            },
        ),
        Command::Alerts { .. }
        | Command::Ack { .. }
        | Command::Status { .. }
        | Command::Exceptions { .. }
        | Command::Ask { .. }
        | Command::RulesUpdate { .. }
        | Command::RulesRollback { .. }
        | Command::Scan { .. }
        | Command::Rules { .. }
        | Command::TrustBaseline { .. }
        | Command::Integrity { .. }
        | Command::HashAdd { .. }
        | Command::Actions { .. }
        | Command::AiNotes { .. }
        | Command::Proposals { .. }
        | Command::ProposalShow { .. }
        | Command::ApproveRule { .. }
        | Command::RejectRule { .. }
        | Command::PacmanBegin
        | Command::PacmanEnd { .. }
        | Command::ScanPkgbuild { .. }
        | Command::Keygen { .. }
        | Command::RulesSign { .. }
        | Command::RulesVerify { .. }
        | Command::Approve { .. }
        | Command::Reject { .. }
        | Command::Undo { .. }
        | Command::BreakerReset { .. }
        | Command::ResponderStatus { .. } => Ok(()), // handled in main
        Command::DbCleanup { db } => {
            let cfg = Config::load(&cli.config)?;
            let path = db.clone().unwrap_or_else(|| cfg.db_path());
            let report = Store::open(&path)?.cleanup(
                cfg.general.retention_days,
                cfg.max_db_bytes(),
                now_ns(),
            )?;
            println!(
                "deleted {} events by age, {} by size; {} bytes in use",
                report.deleted_by_age, report.deleted_by_size, report.used_bytes_after
            );
            Ok(())
        }
    }
}

/// `--db` wins and needs no config; otherwise derive the path from the config.
fn db_path(config: &Path, explicit: Option<&Path>) -> Result<PathBuf, Error> {
    match explicit {
        Some(p) => Ok(p.to_path_buf()),
        None => Ok(Config::load(config)?.db_path()),
    }
}

fn config_check(path: &Path, print: bool) -> Result<(), Error> {
    let cfg = Config::load(path)?;
    println!("config OK: {}", path.display());
    println!("mode                 {}", cfg.general.mode.as_str());
    println!("max automatic level  {}", cfg.effective_max_auto_level());
    println!(
        "ai analyzer          {}",
        if cfg.ai.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!("database             {}", cfg.db_path().display());
    if print {
        let text = toml::to_string_pretty(&cfg)
            .map_err(|e| Error::ConfigInvalid(vec![format!("cannot render config: {e}")]))?;
        println!("\n{text}");
    }
    Ok(())
}

struct TailOptions<'a> {
    lines: usize,
    follow: bool,
    json: bool,
    kinds: &'a [String],
    file: Option<&'a Path>,
}

/// How often `tail -f` checks the log for new lines.
const FOLLOW_INTERVAL: Duration = Duration::from_millis(200);

fn tail(config: &Path, opts: &TailOptions<'_>) -> Result<(), Error> {
    let path = match opts.file {
        Some(p) => p.to_path_buf(),
        None => eventlog::log_path(&Config::load(config)?.paths.log_dir),
    };

    // Start following before reading the history so no event falls in the
    // gap; at worst one event near the boundary is shown twice.
    let mut follower = if opts.follow {
        Some(Follower::from_end(&path)?)
    } else {
        None
    };

    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in eventlog::last_lines(&path, opts.lines)? {
        print_line(&mut out, &line, opts)?;
    }
    out.flush().map_err(|e| Error::io("<stdout>", e))?;

    if let Some(follower) = follower.as_mut() {
        loop {
            for line in follower.poll()? {
                print_line(&mut out, &line, opts)?;
            }
            out.flush().map_err(|e| Error::io("<stdout>", e))?;
            std::thread::sleep(FOLLOW_INTERVAL);
        }
    }
    Ok(())
}

/// Parse one log line and print it if it passes the filters. Lines that are
/// not valid events are reported on stderr and skipped.
fn print_line(out: &mut impl Write, line: &[u8], opts: &TailOptions<'_>) -> Result<(), Error> {
    let envelope: Envelope = match serde_json::from_slice(line) {
        Ok(envelope) => envelope,
        Err(e) => {
            let shown = String::from_utf8_lossy(line.get(..80).unwrap_or(line));
            eprintln!(
                "warning: skipping unreadable log line ({e}): {}",
                render::sanitize(&shown)
            );
            return Ok(());
        }
    };
    if !opts.kinds.is_empty() && !opts.kinds.iter().any(|k| k == envelope.event.kind()) {
        return Ok(());
    }
    let text = if opts.json {
        // Re-serialize rather than echo the raw bytes, so the output is
        // always one well-formed event per line.
        serde_json::to_string(&envelope)?
    } else {
        render::format_envelope(&envelope)
    };
    writeln!(out, "{text}").map_err(|e| Error::io("<stdout>", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_antivirus_common::event::{BootId, Event, ProcKey};

    fn line(seq: u64, event: Event) -> Vec<u8> {
        serde_json::to_vec(&Envelope {
            seq,
            ts_ns: 1_700_000_000_000_000_000,
            boot_id: BootId(1),
            event,
        })
        .unwrap()
    }

    fn exit_event() -> Event {
        Event::Exit {
            proc: ProcKey {
                pid: 3,
                start_ns: 4,
            },
            code: 0,
        }
    }

    fn opts(kinds: &[String], json: bool) -> TailOptions<'_> {
        TailOptions {
            lines: 10,
            follow: false,
            json,
            kinds,
            file: None,
        }
    }

    #[test]
    fn prints_readable_lines_and_filters_by_kind() {
        let mut out = Vec::new();
        let exit = line(1, exit_event());
        let health = line(
            2,
            Event::SensorHealth {
                dropped: 0,
                degraded: false,
            },
        );

        let only_exit = vec!["exit".to_owned()];
        print_line(&mut out, &exit, &opts(&only_exit, false)).unwrap();
        print_line(&mut out, &health, &opts(&only_exit, false)).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.contains("exit") && text.contains("#1"));
    }

    #[test]
    fn json_mode_emits_one_valid_event_per_line() {
        let mut out = Vec::new();
        print_line(&mut out, &line(7, exit_event()), &opts(&[], true)).unwrap();
        let text = String::from_utf8(out).unwrap();
        let back: Envelope = serde_json::from_str(text.trim_end()).unwrap();
        assert_eq!(back.seq, 7);
    }

    #[test]
    fn garbage_lines_are_skipped_not_fatal() {
        let mut out = Vec::new();
        print_line(&mut out, b"not json at all", &opts(&[], false)).unwrap();
        print_line(&mut out, b"\x1b[2J{broken", &opts(&[], false)).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn last_lines_reads_a_real_file() {
        let dir = std::env::temp_dir().join(format!("ai-antivirus-tail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("events.jsonl");
        let mut content = Vec::new();
        for seq in 1..=5 {
            content.extend(line(seq, exit_event()));
            content.push(b'\n');
        }
        std::fs::write(&file, content).unwrap();

        let lines = eventlog::last_lines(&file, 2).unwrap();
        let seqs: Vec<u64> = lines
            .iter()
            .map(|l| serde_json::from_slice::<Envelope>(l).unwrap().seq)
            .collect();
        assert_eq!(seqs, vec![4, 5]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
