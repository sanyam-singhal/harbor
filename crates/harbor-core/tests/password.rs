//! Integration tests for Harbor password policy and hashing contracts.

use harbor_core::{
    Argon2Params, Argon2PasswordHasher, CommonPasswordBlocklist, PasswordError, PasswordHashError,
    PasswordHashString, PasswordPolicy, RandomError, SecretGenerator,
};

#[derive(Clone)]
struct FixedGenerator;

impl SecretGenerator for FixedGenerator {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        for (index, byte) in dest.iter_mut().enumerate() {
            *byte = index as u8;
        }
        Ok(())
    }
}

fn fast_hasher() -> Result<Argon2PasswordHasher, PasswordHashError> {
    Ok(Argon2PasswordHasher::new(
        PasswordPolicy::try_new(8, 128)?,
        Argon2Params::try_new(32, 1, 1)?,
    ))
}

#[test]
fn default_policy_matches_v0_1_security_decision() {
    let policy = PasswordPolicy::default();
    assert_eq!(policy.min_chars(), 15);
    assert_eq!(policy.max_bytes(), 1024);

    let params = Argon2Params::default();
    assert_eq!(params.memory_cost_kib(), 19_456);
    assert_eq!(params.iterations(), 2);
    assert_eq!(params.parallelism(), 1);
}

#[test]
fn password_policy_rejects_short_long_and_blocklisted_values() {
    let policy = PasswordPolicy::try_new(15, 32);
    assert!(policy.is_ok());
    let policy = match policy {
        Ok(policy) => policy,
        Err(error) => return assert_eq!(error, PasswordError::TooShort),
    };
    let blocklist = CommonPasswordBlocklist;

    assert_eq!(
        policy.validate("short", &blocklist),
        Err(PasswordError::TooShort)
    );
    assert_eq!(
        policy.validate("123456789012345678901234567890123", &blocklist),
        Err(PasswordError::TooLong)
    );
    assert_eq!(
        policy.validate("passwordpassword", &blocklist),
        Err(PasswordError::Blocklisted)
    );
    assert!(
        policy
            .validate("correct horse battery staple", &blocklist)
            .is_ok()
    );
    assert_eq!(PasswordPolicy::try_new(0, 32), Err(PasswordError::TooShort));
    assert_eq!(PasswordPolicy::try_new(15, 14), Err(PasswordError::TooLong));
    assert_eq!(PasswordError::TooShort.to_string(), "password is too short");
    assert_eq!(PasswordError::TooLong.to_string(), "password is too long");
    assert_eq!(
        PasswordError::Blocklisted.to_string(),
        "password is blocklisted"
    );
}

#[test]
fn password_hash_debug_is_redacted() -> Result<(), Box<dyn std::error::Error>> {
    let hasher = fast_hasher()?;
    let generator = FixedGenerator;
    let hash = hasher.hash_password(
        "correct horse battery staple",
        &CommonPasswordBlocklist,
        &generator,
    )?;

    assert_eq!(format!("{hash:?}"), "PasswordHashString([REDACTED])");
    assert!(hash.expose_phc().starts_with("$argon2id$"));
    Ok(())
}

#[test]
fn password_hash_verifies_and_rejects_wrong_password() -> Result<(), Box<dyn std::error::Error>> {
    let hasher = fast_hasher()?;
    let generator = FixedGenerator;
    let hash = hasher.hash_password(
        "correct horse battery staple",
        &CommonPasswordBlocklist,
        &generator,
    )?;

    let verified = hasher.verify_password("correct horse battery staple", &hash)?;
    let rejected = hasher.verify_password("wrong horse battery staple", &hash)?;

    assert!(verified.verified);
    assert!(!verified.needs_rehash);
    assert!(!rejected.verified);
    Ok(())
}

#[test]
fn verification_flags_rehash_for_old_parameters() -> Result<(), Box<dyn std::error::Error>> {
    let old_hasher = Argon2PasswordHasher::new(
        PasswordPolicy::try_new(8, 128)?,
        Argon2Params::try_new(32, 1, 1)?,
    );
    let new_hasher = Argon2PasswordHasher::new(
        PasswordPolicy::try_new(8, 128)?,
        Argon2Params::try_new(64, 1, 1)?,
    );
    let generator = FixedGenerator;
    let hash = old_hasher.hash_password(
        "correct horse battery staple",
        &CommonPasswordBlocklist,
        &generator,
    )?;

    let verified = new_hasher.verify_password("correct horse battery staple", &hash)?;

    assert!(verified.verified);
    assert!(verified.needs_rehash);
    Ok(())
}

#[test]
fn invalid_stored_hash_is_rejected() {
    assert!(PasswordHashString::try_new("not-a-phc-string").is_err());
}

#[test]
fn random_error_converts_to_hash_error_without_leaking_secret_context() {
    let error = PasswordHashError::from(RandomError::SystemRandom);
    assert_eq!(
        error.to_string(),
        "random generation failed: system random source failed"
    );
    assert_eq!(
        PasswordHashError::from(PasswordError::TooShort).to_string(),
        "password is too short"
    );
    assert_eq!(
        PasswordHashError::InvalidParameters.to_string(),
        "invalid Argon2 parameters"
    );
    assert_eq!(
        PasswordHashError::HashFailed.to_string(),
        "password hashing failed"
    );
    assert_eq!(
        PasswordHashError::InvalidStoredHash.to_string(),
        "stored password hash is invalid"
    );
}
