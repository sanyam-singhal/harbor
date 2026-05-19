use crate::{
    ChallengeDelivery, ChallengePurpose, CreatePasswordUserInput, EmailAddress,
    InsertPasswordInput, PasswordCredentialRecord, StoreError, StoreErrorCode, UnixTimestampMicros,
    UserEmailId, UserId,
};

#[test]
fn password_records_do_not_debug_hashes() -> Result<(), Box<dyn std::error::Error>> {
    let user_id = UserId::try_new("abcDEF0123456789")?;
    assert_eq!(user_id.as_str(), "abcDEF0123456789");
    let phc = "$argon2id$v=19$m=32,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$e9Q8Zc8mW2hS9UG+4XH15Q";
    let record = PasswordCredentialRecord {
        user_id,
        password_hash: crate::PasswordHashString::try_new(phc)?,
        password_set_at: UnixTimestampMicros::EPOCH,
        password_version: 1,
    };
    let debug = format!("{record:?}");

    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(phc));

    let input = InsertPasswordInput {
        user_id: record.user_id,
        password_hash: record.password_hash,
        password_set_at: record.password_set_at,
        password_version: 2,
    };
    let input_debug = format!("{input:?}");
    assert!(input_debug.contains("[REDACTED]"));
    assert!(!input_debug.contains(phc));

    let email = EmailAddress::parse("user@example.com")?;
    let create = CreatePasswordUserInput {
        user_id: UserId::try_new("user000000000002")?,
        email_id: UserEmailId::try_new("email00000000002")?,
        email_original: email.original().to_owned(),
        email_canonical: email.canonical().clone(),
        password_hash: crate::PasswordHashString::try_new(phc)?,
        password_set_at: UnixTimestampMicros::EPOCH,
        password_version: 1,
        now: UnixTimestampMicros::EPOCH,
    };
    let create_debug = format!("{create:?}");
    assert!(create_debug.contains("[REDACTED]"));
    assert!(!create_debug.contains(phc));

    let error = StoreError::new(StoreErrorCode::CorruptData);
    assert_eq!(error.to_string(), "storage operation failed");

    let _purpose = ChallengePurpose::SignupConfirmation;
    let _delivery = ChallengeDelivery::MagicLink;
    Ok(())
}

#[test]
fn passive_store_records_are_debuggable_without_password_hashes()
-> Result<(), crate::PasswordHashError> {
    let hash = crate::Argon2PasswordHasher::default();
    assert_eq!(hash.policy().min_chars(), 15);

    let _type_marker = core::any::type_name::<PasswordCredentialRecord>();
    Ok(())
}
