//! `ai-antivirus-sensord`: the AI Antivirus sensor daemon.

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
    name = "ai-antivirus-sensord",
    version,
    about = "AI Antivirus sensor daemon"
)]
struct Cli {
    /// Path to the configuration file.
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cfg = match Config::load(&cli.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("ai-antivirus-sensord: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = logging::init(&cfg.logging) {
        eprintln!("ai-antivirus-sensord: {e}");
        return ExitCode::FAILURE;
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    for signal in [SIGINT, SIGTERM] {
        if let Err(e) = signal_hook::flag::register(signal, Arc::clone(&shutdown)) {
            eprintln!("ai-antivirus-sensord: cannot install signal handler: {e}");
            return ExitCode::FAILURE;
        }
    }

    match ai_antivirus_sensord::run(&cfg, &shutdown) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ai-antivirus-sensord: {e}");
            ExitCode::FAILURE
        }
    }
}
