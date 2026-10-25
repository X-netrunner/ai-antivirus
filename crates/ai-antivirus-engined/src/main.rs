//! `ai-antivirus-engined`: the AI Antivirus engine daemon (see the library docs).

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use ai_antivirus_common::config::{Config, DEFAULT_CONFIG_PATH};
use ai_antivirus_common::logging;
use ai_antivirus_common::store::Store;
use clap::Parser;
use signal_hook::consts::{SIGINT, SIGTERM};

#[derive(Parser)]
#[command(
    name = "ai-antivirus-engined",
    version,
    about = "AI Antivirus engine daemon"
)]
struct Cli {
    /// Path to the configuration file.
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
    /// Run a recorded event log (JSONL) through the engine and print the alerts as JSON lines, then exit.
    #[arg(long, value_name = "FILE")]
    replay: Option<PathBuf>,
    /// With --replay: use this rules directory instead of `engine.rules_dir`.
    #[arg(long, value_name = "DIR", requires = "replay")]
    rules: Option<PathBuf>,
    /// With --replay: use this database for trust and hashes (read and written) instead of an empty in-memory one.
    #[arg(long, value_name = "FILE", requires = "replay")]
    db: Option<PathBuf>,
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("ai-antivirus-engined: {msg}");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cfg = match Config::load(&cli.config) {
        Ok(cfg) => cfg,
        // a replay needs no installed config: the defaults are fine
        Err(_) if cli.replay.is_some() && !cli.config.exists() => Config::default(),
        Err(e) => return fail(e),
    };
    if let Err(e) = logging::init(&cfg.logging) {
        return fail(e);
    }

    if let Some(path) = &cli.replay {
        let rules = cli
            .rules
            .clone()
            .unwrap_or_else(|| cfg.engine.rules_dir.clone());
        let mut engine = match ai_antivirus_engined::build(&cfg, &rules) {
            Ok(e) => e,
            Err(e) => return fail(e),
        };
        let store = match &cli.db {
            Some(db) => Store::open(db),
            None => Store::open_in_memory(),
        };
        let mut store = match store {
            Ok(s) => s,
            Err(e) => return fail(e),
        };
        let input = match File::open(path) {
            Ok(f) => BufReader::new(f),
            Err(e) => return fail(format!("{}: {e}", path.display())),
        };
        let mut stdout = std::io::stdout().lock();
        return match ai_antivirus_engined::replay(&mut engine, &mut store, input, &mut stdout) {
            Ok(alerts) => {
                eprintln!(
                    "ai-antivirus-engined: {} events, {} alerts",
                    engine.stats.events,
                    alerts.len()
                );
                ExitCode::SUCCESS
            }
            Err(e) => fail(e),
        };
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    for signal in [SIGINT, SIGTERM] {
        if let Err(e) = signal_hook::flag::register(signal, Arc::clone(&shutdown)) {
            return fail(format!("cannot install signal handler: {e}"));
        }
    }
    match ai_antivirus_engined::run(&cfg, &shutdown) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}
