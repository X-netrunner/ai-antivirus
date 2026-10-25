//! `synapsectl`: command line interface for Synapse.
//!
//! Commands: `config-check`, `db-init`, `db-stats`, `db-cleanup` (M0),
//! `tail` (M1), and `alerts`, `scan`, `rules`, `trust-baseline`, `integrity`,
//! `hash-add` (M3).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod detect;
mod render;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use synapse_common::config::{Config, LogFormat, LogLevel, LoggingConfig, DEFAULT_CONFIG_PATH};
use synapse_common::event::{now_ns, Envelope};
use synapse_common::eventlog::{self, Follower};
use synapse_common::store::Store;
use synapse_common::{logging, Error};

#[derive(Parser)]
#[command(name = "synapsectl", version, about = "Synapse EDR control tool")]
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
        /// Database path; defaults to <state_dir>/synapse.db from the config.
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Show schema version, row counts and sizes.
    DbStats {
        /// Database path; defaults to <state_dir>/synapse.db from the config.
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Apply retention (age and size) to the event table.
    DbCleanup {
        /// Database path; defaults to <state_dir>/synapse.db from the config.
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
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Check files now (pacman trust, hash table, YARA). Directories are walked; symlinks are not followed.
    /// Exits with status 1 when anything was found.
    Scan {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Only print findings.
        #[arg(short, long)]
        quiet: bool,
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
    /// Add a file or SHA-256 to the hash table as bad (the default) or good.
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    // Quiet by default for a CLI; RUST_LOG overrides.
    let _ = logging::init(&LoggingConfig {
        level: LogLevel::Warn,
        format: LogFormat::Text,
    });

    // M3 commands report plain messages and may exit 1 for "found something"
    let found = match &cli.command {
        Command::Alerts { lines, json, db } => {
            Some(detect::alerts(&cli.config, db.as_deref(), *lines, *json).map(|()| false))
        }
        Command::Scan {
            paths,
            quiet,
            rules,
            db,
        } => Some(detect::scan(
            &cli.config,
            db.as_deref(),
            rules.as_deref(),
            paths,
            *quiet,
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
        _ => None,
    };
    if let Some(r) = found {
        return match r {
            Ok(false) => ExitCode::SUCCESS,
            Ok(true) => ExitCode::from(1),
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        };
    }

    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        // `synapsectl tail -f | head` closes the pipe; that is not an error.
        Err(Error::Io { source, .. }) if source.kind() == io::ErrorKind::BrokenPipe => {
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
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
        | Command::Scan { .. }
        | Command::Rules { .. }
        | Command::TrustBaseline { .. }
        | Command::Integrity { .. }
        | Command::HashAdd { .. } => Ok(()), // handled in main
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
    use synapse_common::event::{BootId, Event, ProcKey};

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
        let dir = std::env::temp_dir().join(format!("synapsectl-tail-{}", std::process::id()));
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
