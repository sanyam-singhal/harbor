//! Public API contract tests for `harbor-test-support`.

use harbor_core::{SecretGenerator, new_user_id};
use harbor_test_support::{
    DeterministicSecretGenerator, TempSqliteDatabase, TestAuthServiceBuilder, TestIdFactory,
};

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
fn deterministic_generator_fills_non_overlapping_byte_ranges() {
    let generator = DeterministicSecretGenerator::new();
    let mut first = [0_u8; 4];
    let mut second = [0_u8; 4];

    assert!(generator.fill_bytes(&mut first).is_ok());
    assert!(generator.fill_bytes(&mut second).is_ok());
    assert_eq!(first, [0, 1, 2, 3]);
    assert_eq!(second, [4, 5, 6, 7]);
}

#[test]
fn temp_sqlite_database_provides_unique_urls() -> Result<(), Box<dyn std::error::Error>> {
    let first = TempSqliteDatabase::new("fixture one")?;
    let second = TempSqliteDatabase::new("fixture one")?;

    assert_ne!(first.database_url(), second.database_url());
    assert!(first.root().exists());
    assert!(first.database_path().ends_with("harbor.sqlite"));
    assert!(first.database_url().starts_with("sqlite://"));
    assert!(first.database_url().ends_with("?mode=rwc"));
    Ok(())
}

#[test]
fn factory_produces_valid_unique_domain_values() -> Result<(), Box<dyn std::error::Error>> {
    let mut ids = TestIdFactory::new("Auth Flow");

    assert_ne!(ids.user_id()?, ids.user_id()?);
    assert_ne!(ids.user_email_id()?, ids.user_email_id()?);
    assert_ne!(ids.challenge_id()?, ids.challenge_id()?);
    assert_ne!(ids.session_id()?, ids.session_id()?);
    assert_ne!(ids.auth_event_id()?, ids.auth_event_id()?);
    assert_ne!(ids.email()?.canonical(), ids.email()?.canonical());
    assert!(ids.request_fingerprint().contains("client="));
    assert_ne!(ids.token_hash()?, ids.token_hash()?);
    Ok(())
}

#[test]
fn builder_rejects_weak_hmac_key() {
    let result = TestAuthServiceBuilder::new("store")
        .with_hmac_key(vec![1; 8])
        .finish();

    assert!(result.is_err());
}
