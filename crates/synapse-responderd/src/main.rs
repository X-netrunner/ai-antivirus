//! `synapse-responderd`: the Synapse responder daemon (see the library docs).

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::Parser;
use signal_hook::consts::{SIGINT, SIGTERM};
use synapse_common::config::{Config, DEFAULT_CONFIG_PATH};
use synapse_common::logging;

#[derive(Parser)]
#[command(
    name = "synapse-responderd",
    version,
    about = "Synapse EDR responder daemon"
)]
struct Cli {
    /// Path to the configuration file.
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("synapse-responderd: {msg}");
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
    match synapse_responderd::run(&cfg, &shutdown) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}
