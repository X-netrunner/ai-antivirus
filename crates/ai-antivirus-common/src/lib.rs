//! Shared foundation for the AI Antivirus: event schema, configuration,
//! logging and the SQLite store. Every AI Antivirus process depends on this crate.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod config;
pub mod entropy;
pub mod error;
pub mod event;
pub mod eventlog;
pub mod exceptions;
pub mod logging;
pub mod model;
pub mod notify;
pub mod store;

#[cfg(test)]
mod testutil;

pub use error::{Error, Result};
