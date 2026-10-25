//! `synapse-sensord`: the Synapse sensor daemon.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::Parser;
use signal_hook::consts::{SIGINT, SIGTERM};
use synapse_common::config::{Config, DEFAULT_CONFIG_PATH};
use synapse_common::logging;

#[derive(Parser)]
#[command(name = "synapse-sensord", version, about = "Synapse EDR sensor daemon")]
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
            eprintln!("synapse-sensord: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = logging::init(&cfg.logging) {
        eprintln!("synapse-sensord: {e}");
        return ExitCode::FAILURE;
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    for signal in [SIGINT, SIGTERM] {
        if let Err(e) = signal_hook::flag::register(signal, Arc::clone(&shutdown)) {
            eprintln!("synapse-sensord: cannot install signal handler: {e}");
            return ExitCode::FAILURE;
        }
    }

    match synapse_sensord::run(&cfg, &shutdown) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("synapse-sensord: {e}");
            ExitCode::FAILURE
        }
    }
}
