//! `ai-antivirus-analyzer`: the AI Antivirus AI analyzer daemon (advice only; see the library docs).

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use ai_antivirus_common::config::{Config, DEFAULT_CONFIG_PATH};
use ai_antivirus_common::logging;
use clap::Parser;
use signal_hook::consts::{SIGINT, SIGTERM};

#[derive(Parser)]
#[command(
    name = "ai-antivirus-analyzer",
    version,
    about = "AI Antivirus AI analyzer (advice only)"
)]
struct Cli {
    /// Path to the configuration file.
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("ai-antivirus-analyzer: {msg}");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cfg = match Config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    if let Err(e) = logging::init(&cfg.logging) {
        return fail(e);
    }
    let shutdown = Arc::new(AtomicBool::new(false));
    for sig in [SIGINT, SIGTERM] {
        if let Err(e) = signal_hook::flag::register(sig, Arc::clone(&shutdown)) {
            return fail(format!("cannot install signal handler: {e}"));
        }
    }
    match ai_antivirus_analyzer::daemon::run(&cfg, &shutdown) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}
