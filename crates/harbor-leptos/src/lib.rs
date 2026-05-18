//! Leptos integration helpers and components for Harbor.
//!
//! This crate will expose the Leptos-facing API while delegating auth logic to
//! `harbor-core`.

/// Version of the `harbor-leptos` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
