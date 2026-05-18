use super::{
    HmacSecretKey, SecretHashPurpose, constant_time_token_hash_eq, hash_secret, hash_secret_token,
};
use crate::{DomainError, SecretToken};

fn test_key() -> Result<HmacSecretKey, DomainError> {
    HmacSecretKey::try_new(vec![7; 32])
}

#[test]
fn hmac_secret_key_debug_is_redacted() -> Result<(), DomainError> {
    let key = test_key()?;

    assert_eq!(format!("{key:?}"), "HmacSecretKey([REDACTED])");
    assert_eq!(key.expose_secret().len(), 32);
    assert!(HmacSecretKey::try_new(vec![1; 31]).is_err());
    Ok(())
}

#[test]
fn hash_secret_is_stable_for_same_context() -> Result<(), DomainError> {
    let key = test_key()?;

    let first = hash_secret(&key, SecretHashPurpose::SessionToken, b"token")?;
    let second = hash_secret(&key, SecretHashPurpose::SessionToken, b"token")?;

    assert!(constant_time_token_hash_eq(&first, &second));
    assert_eq!(first.as_bytes().len(), 32);
    Ok(())
}

#[test]
fn hash_secret_is_domain_separated() -> Result<(), DomainError> {
    let key = test_key()?;

    let session = hash_secret(&key, SecretHashPurpose::SessionToken, b"same-token")?;
    let url = hash_secret(&key, SecretHashPurpose::UrlToken, b"same-token")?;

    assert!(!constant_time_token_hash_eq(&session, &url));
    Ok(())
}

#[test]
fn hash_secret_token_accepts_redacted_token_wrapper() -> Result<(), DomainError> {
    let key = test_key()?;
    let token = SecretToken::try_new("12345678")?;

    let hash = hash_secret_token(&key, SecretHashPurpose::OtpCode, &token)?;

    assert_eq!(format!("{hash:?}"), "TokenHash([REDACTED])");
    assert_eq!(hash.as_bytes().len(), 32);
    Ok(())
}
