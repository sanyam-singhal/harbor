//! Integration tests for Harbor domain value contracts.

use harbor_core::{
    AuthEventId, CanonicalEmail, ChallengeId, DomainError, EmailAddress, RedirectPath, RetryBudget,
    SecretToken, SessionId, TokenHash, UnixTimestampMicros, UserEmailId, UserId,
};

#[test]
fn opaque_ids_accept_expected_alphabet() {
    let id = "abcDEF0123456789_-";

    assert!(UserId::try_new(id).is_ok());
    assert!(SessionId::try_new(id).is_ok());
    assert!(ChallengeId::try_new(id).is_ok());
    assert!(UserEmailId::try_new(id).is_ok());
    assert!(AuthEventId::try_new(id).is_ok());
}

#[test]
fn opaque_ids_reject_invalid_space() {
    assert_eq!(UserId::try_new("").err(), Some(DomainError::Empty));
    assert_eq!(
        UserId::try_new("short").err(),
        Some(DomainError::OutOfRange)
    );
    assert_eq!(
        UserId::try_new("abcDEF0123456789!").err(),
        Some(DomainError::InvalidCharacters)
    );
}

#[test]
fn domain_errors_display_stable_messages() {
    assert_eq!(DomainError::Empty.to_string(), "value is empty");
    assert_eq!(DomainError::TooLong.to_string(), "value is too long");
    assert_eq!(
        DomainError::InvalidCharacters.to_string(),
        "value contains invalid characters"
    );
    assert_eq!(
        DomainError::InvalidFormat.to_string(),
        "value has an invalid format"
    );
    assert_eq!(
        DomainError::OutOfRange.to_string(),
        "value is outside the permitted range"
    );
}

#[test]
fn opaque_ids_display_and_convert_without_changing_value() -> Result<(), Box<dyn std::error::Error>>
{
    let user = UserId::try_new("user000000000001")?;
    let session = SessionId::try_new("session000000001")?;
    let challenge = ChallengeId::try_new("challenge00000001")?;
    let email = UserEmailId::try_new("email00000000001")?;
    let event = AuthEventId::try_new("event00000000001")?;

    assert_eq!(user.to_string(), "user000000000001");
    assert_eq!(
        CanonicalEmail::try_new("user@example.com")?.to_string(),
        "user@example.com"
    );
    assert_eq!(RedirectPath::try_new("/account")?.to_string(), "/account");
    assert_eq!(String::from(user), "user000000000001");
    assert_eq!(String::from(session), "session000000001");
    assert_eq!(String::from(challenge), "challenge00000001");
    assert_eq!(String::from(email), "email00000000001");
    assert_eq!(String::from(event), "event00000000001");
    Ok(())
}

#[test]
fn email_parse_preserves_original_and_builds_canonical_lookup() -> Result<(), DomainError> {
    let email = EmailAddress::parse("User.Name+Tag@Example.COM")?;

    assert_eq!(email.original(), "User.Name+Tag@Example.COM");
    assert_eq!(email.canonical().as_str(), "user.name+tag@example.com");

    let (original, canonical) = email.into_parts();
    assert_eq!(original, "User.Name+Tag@Example.COM");
    assert_eq!(canonical.as_str(), "user.name+tag@example.com");
    assert_eq!(
        EmailAddress::parse("Another.User@Example.COM")?
            .into_canonical()
            .as_str(),
        "another.user@example.com"
    );
    Ok(())
}

#[test]
fn email_parse_rejects_ambiguous_or_unbounded_values() {
    assert_eq!(EmailAddress::parse("").err(), Some(DomainError::Empty));
    assert_eq!(
        EmailAddress::parse(" user@example.com").err(),
        Some(DomainError::InvalidCharacters)
    );
    assert_eq!(
        EmailAddress::parse("user@@example.com").err(),
        Some(DomainError::InvalidFormat)
    );
    assert_eq!(
        EmailAddress::parse("user@example").err(),
        Some(DomainError::InvalidFormat)
    );
    assert_eq!(
        EmailAddress::parse(".user@example.com").err(),
        Some(DomainError::InvalidFormat)
    );
    assert_eq!(
        EmailAddress::parse("user@example..com").err(),
        Some(DomainError::InvalidFormat)
    );
    assert_eq!(
        EmailAddress::parse(format!("{}@example.com", "a".repeat(65))).err(),
        Some(DomainError::TooLong)
    );
    assert_eq!(
        EmailAddress::parse(format!("user@{}.com", "a".repeat(254))).err(),
        Some(DomainError::TooLong)
    );
    assert_eq!(
        EmailAddress::parse(format!("{}@example.com", "a".repeat(244))).err(),
        Some(DomainError::TooLong)
    );
    assert_eq!(
        EmailAddress::parse("user@.example.com").err(),
        Some(DomainError::InvalidFormat)
    );
    assert_eq!(
        EmailAddress::parse("user@example-.com").err(),
        Some(DomainError::InvalidFormat)
    );
    assert_eq!(
        EmailAddress::parse("user@example!.com").err(),
        Some(DomainError::InvalidCharacters)
    );
}

#[test]
fn canonical_email_must_already_be_canonical() {
    assert!(CanonicalEmail::try_new("user@example.com").is_ok());
    assert_eq!(
        CanonicalEmail::try_new("User@example.com").err(),
        Some(DomainError::InvalidFormat)
    );
}

#[test]
fn redirect_path_allows_only_same_origin_paths() {
    assert!(RedirectPath::try_new("/account?tab=sessions").is_ok());
    assert!(RedirectPath::try_new("https://example.com").is_err());
    assert!(RedirectPath::try_new("//example.com").is_err());
    assert!(RedirectPath::try_new("/account\\evil").is_err());
}

#[test]
fn timestamps_and_retry_budgets_enforce_bounds() {
    assert_eq!(
        UnixTimestampMicros::try_new(42).map(UnixTimestampMicros::as_i64),
        Ok(42)
    );
    assert!(UnixTimestampMicros::try_new(-1).is_err());
    assert_eq!(
        UnixTimestampMicros::EPOCH
            .checked_add_micros(5)
            .map(UnixTimestampMicros::as_i64),
        Some(5)
    );
    assert_eq!(UnixTimestampMicros::EPOCH.checked_add_micros(-1), None);
    assert!(RetryBudget::try_new(1).is_ok());
    assert!(RetryBudget::try_new(0).is_err());
    assert!(RetryBudget::try_new(RetryBudget::MAX + 1).is_err());
}

#[test]
fn secret_debug_output_is_redacted() -> Result<(), DomainError> {
    let token = SecretToken::try_new("secret-token")?;
    let hash = TokenHash::try_new(vec![1; 32])?;

    assert_eq!(format!("{token:?}"), "SecretToken([REDACTED])");
    assert_eq!(format!("{hash:?}"), "TokenHash([REDACTED])");
    assert_eq!(token.expose_secret(), "secret-token");
    assert_eq!(hash.as_bytes(), &[1; 32]);
    Ok(())
}
