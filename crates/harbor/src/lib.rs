//! Facade crate for Harbor auth.
//!
//! Applications should normally depend on this crate instead of importing
//! Harbor's internal crates directly. The lower-level crates remain separate
//! architecture boundaries; this facade is the stable integration surface for
//! Leptos applications.

/// Core auth domain, service, error, password, secret, and store contracts.
pub mod core {
    pub use harbor_core::*;
}

/// Email rendering and delivery integrations.
pub mod email {
    pub use harbor_email::*;
}

#[cfg(feature = "leptos")]
pub mod leptos;

/// SQLx-backed Harbor stores.
#[cfg(feature = "sqlite")]
pub mod sqlx {
    pub use harbor_sqlx::*;
}

pub mod prelude;

/// Version of the `harbor` facade crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
