//! Shared foundation for the Synapse EDR: event schema, configuration,
//! logging and the SQLite store. Every Synapse process depends on this crate.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod config;
pub mod error;
pub mod event;
pub mod eventlog;
pub mod logging;
pub mod model;
pub mod store;

#[cfg(test)]
mod testutil;

pub use error::{Error, Result};
