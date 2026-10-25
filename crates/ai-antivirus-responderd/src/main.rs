//! `ai-antivirus-responderd`: the AI Antivirus responder daemon (see the library docs).

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
    name = "ai-antivirus-responderd",
    version,
    about = "AI Antivirus responder daemon"
)]
struct Cli {
    /// Path to the configuration file.
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("ai-antivirus-responderd: {msg}");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cfg = match Config::load(&cli.config) {
        Ok(cfg) => cfg,
        Err(e) => return fail(e),
    };
    if let Err(e) = logging::init(&cfg.logging) {
        return fail(e);
    }
    let shutdown = Arc::new(AtomicBool::new(false));
    for signal in [SIGINT, SIGTERM] {
        if let Err(e) = signal_hook::flag::register(signal, Arc::clone(&shutdown)) {
            return fail(format!("cannot install signal handler: {e}"));
        }
    }
    match ai_antivirus_responderd::run(&cfg, &shutdown) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}
