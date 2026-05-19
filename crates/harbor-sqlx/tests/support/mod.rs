#![allow(dead_code)]

use harbor_core::{
    AuthService, ChallengeId, HmacSecretKey, RandomError, SecretGenerator, SessionId, TokenHash,
    UnixTimestampMicros, UserEmailId, UserId,
};
use harbor_sqlx::{SqliteAuthStore, SqliteStoreOptions};
use harbor_test_support::{FixedClock, TestAuthServiceBuilder};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) const PHC: &str =
    "$argon2id$v=19$m=32,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$e9Q8Zc8mW2hS9UG+4XH15Q";
pub(crate) const ABSOLUTE_SESSION_MICROS: i64 = 30 * 24 * 60 * 60 * 1_000_000;

pub(crate) async fn migrated_store() -> Result<SqliteAuthStore, Box<dyn std::error::Error>> {
    Ok(
        SqliteAuthStore::connect_and_migrate("sqlite::memory:", SqliteStoreOptions::in_memory())
            .await?,
    )
}

pub(crate) fn test_service(
    store: SqliteAuthStore,
) -> Result<
    harbor_test_support::DeterministicAuthService<SqliteAuthStore>,
    Box<dyn std::error::Error>,
> {
    test_service_at(store, now())
}

pub(crate) fn test_service_at(
    store: SqliteAuthStore,
    now: UnixTimestampMicros,
) -> Result<
    harbor_test_support::DeterministicAuthService<SqliteAuthStore>,
    Box<dyn std::error::Error>,
> {
    Ok(TestAuthServiceBuilder::new(store).with_now(now).finish()?)
}

pub(crate) fn test_service_with_key_at(
    store: SqliteAuthStore,
    hmac_key: &HmacSecretKey,
    now: UnixTimestampMicros,
) -> Result<
    harbor_test_support::DeterministicAuthService<SqliteAuthStore>,
    Box<dyn std::error::Error>,
> {
    Ok(TestAuthServiceBuilder::new(store)
        .with_now(now)
        .with_hmac_key(hmac_key.expose_secret().to_vec())
        .finish()?)
}

pub(crate) fn test_service_with_generator<G>(
    store: SqliteAuthStore,
    generator: G,
) -> Result<AuthService<SqliteAuthStore, FixedClock, G>, Box<dyn std::error::Error>>
where
    G: SecretGenerator,
{
    Ok(TestAuthServiceBuilder::new(store)
        .with_generator(generator)
        .finish()?)
}

pub(crate) fn user_id() -> Result<UserId, harbor_core::DomainError> {
    UserId::try_new("user000000000001")
}

pub(crate) fn email_id() -> Result<UserEmailId, harbor_core::DomainError> {
    UserEmailId::try_new("email00000000001")
}

pub(crate) fn now() -> UnixTimestampMicros {
    UnixTimestampMicros::EPOCH
}

pub(crate) fn challenge_id() -> Result<ChallengeId, harbor_core::DomainError> {
    ChallengeId::try_new("challenge00000001")
}

pub(crate) fn token_hash() -> Result<TokenHash, harbor_core::DomainError> {
    TokenHash::try_new(vec![1; 32])
}

pub(crate) fn second_token_hash() -> Result<TokenHash, harbor_core::DomainError> {
    TokenHash::try_new(vec![5; 32])
}

pub(crate) fn session_id() -> Result<SessionId, harbor_core::DomainError> {
    SessionId::try_new("session000000001")
}

#[derive(Clone)]
pub(crate) struct FailingSecretGenerator;

impl SecretGenerator for FailingSecretGenerator {
    fn fill_bytes(&self, _dest: &mut [u8]) -> Result<(), RandomError> {
        Err(RandomError::SystemRandom)
    }
}

#[derive(Clone)]
pub(crate) struct FailAfterFirstSecretGenerator {
    calls: Arc<AtomicUsize>,
}

impl FailAfterFirstSecretGenerator {
    pub(crate) fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl SecretGenerator for FailAfterFirstSecretGenerator {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
            dest.fill(0xab);
            Ok(())
        } else {
            Err(RandomError::SystemRandom)
        }
    }
}
