//! Tracing setup shared by every binary. Logs go to stderr, which systemd
//! captures in the journal.

use std::io::IsTerminal;

use tracing_subscriber::EnvFilter;

use crate::config::{LogFormat, LoggingConfig};
use crate::error::{Error, Result};

/// Build the filter: `RUST_LOG` (if given and valid) wins over the configured level.
pub fn build_filter(config_level: &str, rust_log: Option<&str>) -> EnvFilter {
    rust_log
        .and_then(|s| EnvFilter::try_new(s).ok())
        .unwrap_or_else(|| EnvFilter::new(config_level))
}

/// Install the global subscriber. Fails if one is already installed.
pub fn init(cfg: &LoggingConfig) -> Result<()> {
    let env = std::env::var("RUST_LOG").ok();
    let filter = build_filter(cfg.level.as_str(), env.as_deref());
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true);
    let result = match cfg.format {
        LogFormat::Json => builder.json().try_init(),
        LogFormat::Text => builder
            .with_ansi(std::io::stderr().is_terminal())
            .try_init(),
    };
    result.map_err(|e| Error::Logging(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_level_is_the_default() {
        assert_eq!(build_filter("warn", None).to_string(), "warn");
    }

    #[test]
    fn rust_log_overrides_when_valid() {
        assert_eq!(build_filter("warn", Some("debug")).to_string(), "debug");
    }

    #[test]
    fn invalid_rust_log_falls_back() {
        assert_eq!(build_filter("info", Some("=[bad")).to_string(), "info");
    }
}
