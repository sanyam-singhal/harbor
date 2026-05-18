//! Email delivery integrations for Harbor.
//!
//! Provider-specific implementations live here so the core authentication
//! model remains independent from Resend or any future mail provider.

/// Version of the `harbor-email` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
