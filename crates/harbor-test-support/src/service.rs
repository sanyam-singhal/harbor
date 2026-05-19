//! Auth service test fixtures.

use harbor_core::{
    Argon2Params, Argon2PasswordHasher, AuthService, HmacSecretKey, PasswordPolicy,
    SecretGenerator, UnixTimestampMicros,
};

use crate::{DeterministicSecretGenerator, FixedClock, TestSupportError};

/// Deterministic auth service type used by store and workflow tests.
pub type DeterministicAuthService<S> = AuthService<S, FixedClock, DeterministicSecretGenerator>;

/// Builder for core auth services in tests.
#[derive(Debug, Clone)]
pub struct TestAuthServiceBuilder<S, G = DeterministicSecretGenerator> {
    store: S,
    now: UnixTimestampMicros,
    generator: G,
    hmac_key: Vec<u8>,
    password_min_bytes: usize,
    password_max_bytes: usize,
    argon2_memory_kib: u32,
    argon2_iterations: u32,
    argon2_parallelism: u32,
}

impl<S> TestAuthServiceBuilder<S, DeterministicSecretGenerator> {
    /// Creates a builder using deterministic test defaults.
    #[must_use]
    pub fn new(store: S) -> Self {
        Self {
            store,
            now: UnixTimestampMicros::EPOCH,
            generator: DeterministicSecretGenerator::new(),
            hmac_key: vec![9; 32],
            password_min_bytes: 8,
            password_max_bytes: 128,
            argon2_memory_kib: 32,
            argon2_iterations: 1,
            argon2_parallelism: 1,
        }
    }
}

impl<S, G> TestAuthServiceBuilder<S, G> {
    /// Sets the fixture clock timestamp.
    #[must_use]
    pub const fn with_now(mut self, now: UnixTimestampMicros) -> Self {
        self.now = now;
        self
    }

    /// Sets the HMAC key bytes.
    #[must_use]
    pub fn with_hmac_key(mut self, hmac_key: impl Into<Vec<u8>>) -> Self {
        self.hmac_key = hmac_key.into();
        self
    }

    /// Sets fast Argon2 parameters for tests.
    #[must_use]
    pub const fn with_argon2_params(
        mut self,
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Self {
        self.argon2_memory_kib = memory_kib;
        self.argon2_iterations = iterations;
        self.argon2_parallelism = parallelism;
        self
    }

    /// Sets the password policy used by the service.
    #[must_use]
    pub const fn with_password_policy(mut self, min_bytes: usize, max_bytes: usize) -> Self {
        self.password_min_bytes = min_bytes;
        self.password_max_bytes = max_bytes;
        self
    }

    /// Replaces the secret generator.
    #[must_use]
    pub fn with_generator<NextGenerator>(
        self,
        generator: NextGenerator,
    ) -> TestAuthServiceBuilder<S, NextGenerator> {
        TestAuthServiceBuilder {
            store: self.store,
            now: self.now,
            generator,
            hmac_key: self.hmac_key,
            password_min_bytes: self.password_min_bytes,
            password_max_bytes: self.password_max_bytes,
            argon2_memory_kib: self.argon2_memory_kib,
            argon2_iterations: self.argon2_iterations,
            argon2_parallelism: self.argon2_parallelism,
        }
    }

    /// Builds an [`AuthService`] with the configured test fixtures.
    ///
    /// # Errors
    ///
    /// Returns [`TestSupportError`] when the HMAC key, password policy, or
    /// Argon2 parameters are invalid.
    pub fn finish(self) -> Result<AuthService<S, FixedClock, G>, TestSupportError>
    where
        G: SecretGenerator,
    {
        let password_policy =
            PasswordPolicy::try_new(self.password_min_bytes, self.password_max_bytes)?;
        let argon2_params = Argon2Params::try_new(
            self.argon2_memory_kib,
            self.argon2_iterations,
            self.argon2_parallelism,
        )?;
        Ok(AuthService::new(
            self.store,
            FixedClock::new(self.now),
            self.generator,
            HmacSecretKey::try_new(self.hmac_key)?,
            Argon2PasswordHasher::new(password_policy, argon2_params),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::TestAuthServiceBuilder;

    #[test]
    fn builder_rejects_weak_hmac_key() {
        let result = TestAuthServiceBuilder::new("store")
            .with_hmac_key(vec![1; 8])
            .finish();

        assert!(result.is_err());
    }
}
