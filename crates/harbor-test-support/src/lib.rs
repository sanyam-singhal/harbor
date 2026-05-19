//! Test support utilities for Harbor crates.
//!
//! Shared fixtures and contract-test helpers live here so implementation crates
//! can be tested consistently.
//!
//! This crate intentionally depends only on `harbor-core`. Provider or
//! integration fakes belong beside the traits they implement, such as
//! `harbor_email::RecordingMailer` for the email boundary.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use harbor_core::{RandomError, SecretGenerator, UnixTimestampMicros};

mod error;
mod fixtures;
mod ids;
mod service;
pub mod store_contracts;

pub use error::TestSupportError;
pub use fixtures::TempSqliteDatabase;
pub use ids::TestIdFactory;
pub use service::{DeterministicAuthService, TestAuthServiceBuilder};

/// Version of the `harbor-test-support` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Deterministic test clock.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock {
    now: UnixTimestampMicros,
}

impl FixedClock {
    /// Creates a deterministic clock fixed at `now`.
    #[must_use]
    pub const fn new(now: UnixTimestampMicros) -> Self {
        Self { now }
    }
}

impl harbor_core::Clock for FixedClock {
    fn now(&self) -> UnixTimestampMicros {
        self.now
    }
}

/// Deterministic byte generator for repeatable tests.
#[derive(Debug, Clone)]
pub struct DeterministicSecretGenerator {
    counter: Arc<AtomicU64>,
}

impl DeterministicSecretGenerator {
    /// Creates a deterministic generator starting at counter value zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            counter: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Default for DeterministicSecretGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretGenerator for DeterministicSecretGenerator {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        let increment = u64::try_from(dest.len()).map_err(|_error| RandomError::SystemRandom)?;
        let mut value = self.counter.fetch_add(increment, Ordering::Relaxed);
        for byte in dest {
            *byte = value.to_le_bytes()[0];
            value = value.wrapping_add(1);
        }
        Ok(())
    }
}
