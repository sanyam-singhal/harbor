//! Shared store contract tests.

use harbor_core::{
    AppendAuthEventInput, AuthEventKind, AuthStore, ChallengeDelivery, ChallengePurpose,
    CreateChallengeInput, CreateSessionInput, CreateUserEmailInput, CreateUserInput,
    DeleteExpiredSessionsInput, EmailAddress, FindEmailByCanonicalInput, GetChallengeInput,
    GetSessionInput, GetUserInput, IncrementChallengeAttemptsInput, IncrementRateLimitInput,
    InsertPasswordInput, PasswordHashString, RedirectPath, RetryBudget, RevokeSessionInput,
    RevokeUserSessionsInput, StoreErrorCode, TokenHash, UnixTimestampMicros,
    UpdateSessionLastSeenInput,
};

use crate::TestIdFactory;

const PHC: &str = "$argon2id$v=19$m=32,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$e9Q8Zc8mW2hS9UG+4XH15Q";

/// Runs the shared Harbor auth-store contract suite.
///
/// # Errors
///
/// Returns an error when any store operation violates the contract.
pub async fn run_auth_store_contracts<S>(store: S) -> Result<(), Box<dyn std::error::Error>>
where
    S: AuthStore,
{
    user_email_and_password_contract(store.clone()).await?;
    challenge_contract(store.clone()).await?;
    session_contract(store.clone()).await?;
    session_cleanup_boundary_contract(store.clone()).await?;
    rate_limit_and_event_contract(store).await?;
    Ok(())
}

async fn user_email_and_password_contract<S>(store: S) -> Result<(), Box<dyn std::error::Error>>
where
    S: AuthStore,
{
    let mut ids = TestIdFactory::with_start("contract-user", 1);
    let user_id = ids.user_id()?;
    let email = EmailAddress::parse("Contract@Example.com")?;

    store
        .create_user(CreateUserInput {
            id: user_id.clone(),
            now: now(),
        })
        .await?;
    let duplicate_user = store
        .create_user(CreateUserInput {
            id: user_id.clone(),
            now: now(),
        })
        .await;
    let duplicate_user = match duplicate_user {
        Ok(_) => return Err("duplicate user id should fail".into()),
        Err(error) => error,
    };
    assert_eq!(duplicate_user.code(), StoreErrorCode::Conflict);

    let fetched_user = store
        .get_user(GetUserInput {
            user_id: user_id.clone(),
        })
        .await?;
    assert!(fetched_user.is_some());

    store
        .create_user_email(CreateUserEmailInput {
            id: ids.user_email_id()?,
            user_id: user_id.clone(),
            email_original: email.original().to_owned(),
            email_canonical: email.canonical().clone(),
            is_primary: true,
            now: now(),
        })
        .await?;

    let duplicate = store
        .create_user_email(CreateUserEmailInput {
            id: ids.user_email_id()?,
            user_id: user_id.clone(),
            email_original: email.original().to_owned(),
            email_canonical: email.canonical().clone(),
            is_primary: false,
            now: now(),
        })
        .await;
    let duplicate = match duplicate {
        Ok(_) => return Err("duplicate canonical email should fail".into()),
        Err(error) => error,
    };
    assert_eq!(duplicate.code(), StoreErrorCode::Conflict);

    let verified_at = UnixTimestampMicros::try_new(10)?;
    let verified = store
        .mark_email_verified(harbor_core::MarkEmailVerifiedInput {
            email_canonical: email.canonical().clone(),
            verified_at,
        })
        .await?;
    let verified = match verified {
        Some(verified) => verified,
        None => return Err("verified email should exist".into()),
    };
    assert_eq!(verified.verified_at, Some(verified_at));

    store
        .upsert_password_credential(InsertPasswordInput {
            user_id: user_id.clone(),
            password_hash: PasswordHashString::try_new(PHC)?,
            password_set_at: verified_at,
            password_version: 1,
        })
        .await?;
    let fetched = store
        .get_password_credential(harbor_core::GetPasswordCredentialInput { user_id })
        .await?;
    assert!(fetched.is_some());

    let found = store
        .find_email_by_canonical(FindEmailByCanonicalInput {
            email_canonical: email.canonical().clone(),
        })
        .await?;
    assert!(found.is_some());
    Ok(())
}

async fn challenge_contract<S>(store: S) -> Result<(), Box<dyn std::error::Error>>
where
    S: AuthStore,
{
    let mut ids = TestIdFactory::with_start("contract-challenge", 1_000);
    let email = EmailAddress::parse("challenge@example.com")?;
    let challenge_id = ids.challenge_id()?;
    let consumed_at = UnixTimestampMicros::try_new(20)?;

    store
        .create_challenge(CreateChallengeInput {
            id: challenge_id.clone(),
            purpose: ChallengePurpose::EmailSignIn,
            user_id: None,
            email_canonical: email.canonical().clone(),
            secret_hash: token_hash(1)?,
            delivery: ChallengeDelivery::MagicLink,
            redirect_path: Some(RedirectPath::try_new("/account")?),
            expires_at: UnixTimestampMicros::try_new(1_000)?,
            max_attempts: RetryBudget::try_new(5)?,
            resend_after: now(),
            now: now(),
        })
        .await?;
    let duplicate = store
        .create_challenge(CreateChallengeInput {
            id: challenge_id.clone(),
            purpose: ChallengePurpose::EmailSignIn,
            user_id: None,
            email_canonical: email.canonical().clone(),
            secret_hash: ids.token_hash()?,
            delivery: ChallengeDelivery::MagicLink,
            redirect_path: None,
            expires_at: UnixTimestampMicros::try_new(1_000)?,
            max_attempts: RetryBudget::try_new(5)?,
            resend_after: now(),
            now: now(),
        })
        .await;
    let duplicate = match duplicate {
        Ok(_) => return Err("duplicate challenge id should fail".into()),
        Err(error) => error,
    };
    assert_eq!(duplicate.code(), StoreErrorCode::Conflict);

    let fetched = store
        .get_challenge(GetChallengeInput {
            challenge_id: challenge_id.clone(),
        })
        .await?;
    let fetched = match fetched {
        Some(challenge) => challenge,
        None => return Err("challenge should be fetchable".into()),
    };
    assert_eq!(fetched.resend_after, now());
    assert_eq!(fetched.last_sent_at, None);

    let incremented = store
        .increment_challenge_attempts(IncrementChallengeAttemptsInput {
            challenge_id: challenge_id.clone(),
        })
        .await?;
    let incremented = match incremented {
        Some(challenge) => challenge,
        None => return Err("challenge should exist after increment".into()),
    };
    assert_eq!(incremented.attempt_count, 1);

    let consumed = store
        .consume_challenge(
            GetChallengeInput {
                challenge_id: challenge_id.clone(),
            },
            consumed_at,
        )
        .await?;
    assert!(consumed.is_some());
    let second = store
        .consume_challenge(GetChallengeInput { challenge_id }, consumed_at)
        .await?;
    assert_eq!(second, None);

    let missing_increment = store
        .increment_challenge_attempts(IncrementChallengeAttemptsInput {
            challenge_id: ids.challenge_id()?,
        })
        .await?;
    assert_eq!(missing_increment, None);
    Ok(())
}

async fn session_contract<S>(store: S) -> Result<(), Box<dyn std::error::Error>>
where
    S: AuthStore,
{
    let mut ids = TestIdFactory::with_start("contract-session", 2_000);
    let user_id = ids.user_id()?;
    let session_id = ids.session_id()?;
    let session_token_hash = token_hash(2)?;

    store
        .create_user(CreateUserInput {
            id: user_id.clone(),
            now: now(),
        })
        .await?;
    store
        .create_session(CreateSessionInput {
            id: session_id.clone(),
            user_id: user_id.clone(),
            token_hash: session_token_hash.clone(),
            created_at: now(),
            idle_expires_at: UnixTimestampMicros::try_new(100)?,
            absolute_expires_at: UnixTimestampMicros::try_new(200)?,
            ip_hash: Some(token_hash(3)?),
            user_agent_hash: Some(token_hash(4)?),
        })
        .await?;
    let duplicate = store
        .create_session(CreateSessionInput {
            id: session_id.clone(),
            user_id: user_id.clone(),
            token_hash: ids.token_hash()?,
            created_at: now(),
            idle_expires_at: UnixTimestampMicros::try_new(100)?,
            absolute_expires_at: UnixTimestampMicros::try_new(200)?,
            ip_hash: None,
            user_agent_hash: None,
        })
        .await;
    let duplicate = match duplicate {
        Ok(_) => return Err("duplicate session id should fail".into()),
        Err(error) => error,
    };
    assert_eq!(duplicate.code(), StoreErrorCode::Conflict);

    let fetched = store
        .get_session_by_token_hash(GetSessionInput {
            token_hash: session_token_hash,
        })
        .await?;
    assert!(fetched.is_some());
    let updated = store
        .update_session_last_seen(UpdateSessionLastSeenInput {
            session_id: session_id.clone(),
            last_seen_at: UnixTimestampMicros::try_new(25)?,
        })
        .await?;
    let updated = match updated {
        Some(session) => session,
        None => return Err("session should update last_seen_at".into()),
    };
    assert_eq!(updated.last_seen_at, UnixTimestampMicros::try_new(25)?);

    let revoked = store
        .revoke_session(RevokeSessionInput {
            session_id,
            revoked_at: UnixTimestampMicros::try_new(50)?,
        })
        .await?;
    let revoked = match revoked {
        Some(session) => session,
        None => return Err("session should revoke".into()),
    };
    assert_eq!(revoked.revoked_at, Some(UnixTimestampMicros::try_new(50)?));

    store
        .create_session(CreateSessionInput {
            id: ids.session_id()?,
            user_id: user_id.clone(),
            token_hash: ids.token_hash()?,
            created_at: now(),
            idle_expires_at: UnixTimestampMicros::try_new(100)?,
            absolute_expires_at: UnixTimestampMicros::try_new(200)?,
            ip_hash: None,
            user_agent_hash: None,
        })
        .await?;
    let revoked = store
        .revoke_user_sessions(RevokeUserSessionsInput {
            user_id,
            revoked_at: UnixTimestampMicros::try_new(50)?,
        })
        .await?;
    assert_eq!(revoked, 1);
    let deleted = store
        .delete_expired_sessions(DeleteExpiredSessionsInput {
            now: UnixTimestampMicros::try_new(250)?,
        })
        .await?;
    assert_eq!(deleted, 2);
    Ok(())
}

async fn session_cleanup_boundary_contract<S>(store: S) -> Result<(), Box<dyn std::error::Error>>
where
    S: AuthStore,
{
    let mut ids = TestIdFactory::with_start("contract-cleanup", 3_000);
    let user_id = ids.user_id()?;
    let token_hash = ids.token_hash()?;

    store
        .create_user(CreateUserInput {
            id: user_id.clone(),
            now: now(),
        })
        .await?;
    store
        .create_session(CreateSessionInput {
            id: ids.session_id()?,
            user_id,
            token_hash: token_hash.clone(),
            created_at: now(),
            idle_expires_at: UnixTimestampMicros::try_new(100)?,
            absolute_expires_at: UnixTimestampMicros::try_new(200)?,
            ip_hash: None,
            user_agent_hash: None,
        })
        .await?;

    let before_boundary = store
        .delete_expired_sessions(DeleteExpiredSessionsInput {
            now: UnixTimestampMicros::try_new(99)?,
        })
        .await?;
    assert_eq!(before_boundary, 0);
    assert!(
        store
            .get_session_by_token_hash(GetSessionInput {
                token_hash: token_hash.clone(),
            })
            .await?
            .is_some()
    );

    let at_idle_boundary = store
        .delete_expired_sessions(DeleteExpiredSessionsInput {
            now: UnixTimestampMicros::try_new(100)?,
        })
        .await?;
    assert_eq!(at_idle_boundary, 1);
    assert_eq!(
        store
            .get_session_by_token_hash(GetSessionInput { token_hash })
            .await?,
        None
    );
    Ok(())
}

async fn rate_limit_and_event_contract<S>(store: S) -> Result<(), Box<dyn std::error::Error>>
where
    S: AuthStore,
{
    let mut ids = TestIdFactory::with_start("contract-events", 4_000);
    let key_hash = token_hash(5)?;
    let max_count = RetryBudget::try_new(1)?;
    let first = store
        .increment_rate_limit(IncrementRateLimitInput {
            scope: "contract".to_owned(),
            key_hash: key_hash.clone(),
            window_start: now(),
            max_count,
        })
        .await?;
    let second = store
        .increment_rate_limit(IncrementRateLimitInput {
            scope: "contract".to_owned(),
            key_hash: key_hash.clone(),
            window_start: now(),
            max_count,
        })
        .await?;
    assert!(first.allowed);
    assert!(!second.allowed);
    let new_window = store
        .increment_rate_limit(IncrementRateLimitInput {
            scope: "contract".to_owned(),
            key_hash: key_hash.clone(),
            window_start: UnixTimestampMicros::try_new(1)?,
            max_count,
        })
        .await?;
    assert_eq!(new_window.count, 1);
    assert!(new_window.allowed);

    let event = store
        .append_auth_event(AppendAuthEventInput {
            id: ids.auth_event_id()?,
            user_id: None,
            email_canonical: Some(
                EmailAddress::parse("event@example.com")?
                    .canonical()
                    .clone(),
            ),
            kind: AuthEventKind::SignInFailed,
            occurred_at: now(),
            ip_hash: Some(token_hash(6)?),
            user_agent_hash: Some(token_hash(7)?),
            detail_code: Some("contract".to_owned()),
        })
        .await?;
    assert_eq!(event.kind, AuthEventKind::SignInFailed);
    let next_event = store
        .append_auth_event(AppendAuthEventInput {
            id: ids.auth_event_id()?,
            user_id: None,
            email_canonical: None,
            kind: AuthEventKind::SessionRevoked,
            occurred_at: UnixTimestampMicros::try_new(1)?,
            ip_hash: None,
            user_agent_hash: None,
            detail_code: Some("ordered-after-first".to_owned()),
        })
        .await?;
    assert!(event.occurred_at < next_event.occurred_at);
    Ok(())
}

fn now() -> UnixTimestampMicros {
    UnixTimestampMicros::EPOCH
}

fn token_hash(byte: u8) -> Result<TokenHash, harbor_core::DomainError> {
    TokenHash::try_new(vec![byte; 4])
}
