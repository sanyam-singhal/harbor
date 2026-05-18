//! Test support utilities for Harbor crates.
//!
//! Shared fixtures and contract-test helpers live here so implementation crates
//! can be tested consistently.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use harbor_core::{RandomError, SecretGenerator, UnixTimestampMicros};

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
        let mut value = self.counter.fetch_add(1, Ordering::Relaxed);
        for byte in dest {
            *byte = value.to_le_bytes()[0];
            value = value.wrapping_add(1);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use harbor_core::{SecretGenerator, new_user_id};

    use super::DeterministicSecretGenerator;

    #[test]
    fn deterministic_generator_produces_repeatable_but_advancing_values() {
        let generator = DeterministicSecretGenerator::new();

        let first = new_user_id(&generator);
        let second = new_user_id(&generator);

        assert!(first.is_ok());
        assert!(second.is_ok());
        assert_ne!(
            first.map(|id| id.to_string()),
            second.map(|id| id.to_string())
        );
    }

    #[test]
    fn deterministic_generator_fills_bytes() {
        let generator = DeterministicSecretGenerator::new();
        let mut bytes = [0_u8; 4];

        assert!(generator.fill_bytes(&mut bytes).is_ok());
        assert_eq!(bytes, [0, 1, 2, 3]);
    }
}
