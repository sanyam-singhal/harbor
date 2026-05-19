//! SQLite store integration tests.

mod support;

use harbor_core::{
    AppendAuthEventInput, AuthErrorCode, AuthEventId, AuthEventKind, AuthEventStore,
    ChallengeDelivery, ChallengeId, ChallengePurpose, ChallengeStore, CreateChallengeInput,
    CreateSessionInput, CreateUserEmailInput, CreateUserInput, DeleteExpiredSessionsInput,
    EmailAddress, FindEmailByCanonicalInput, GetChallengeInput, GetPasswordCredentialInput,
    GetSessionInput, GetUserInput, IncrementChallengeAttemptsInput, IncrementRateLimitInput,
    InsertPasswordInput, MarkEmailVerifiedInput, PasswordCredentialStore, PasswordHashString,
    RateLimitStore, RedirectPath, RetryBudget, RevokeSessionInput, RevokeUserSessionsInput,
    SessionId, SessionStore, StoreErrorCode, UnixTimestampMicros, UpdateSessionLastSeenInput,
    UserEmailId, UserEmailStore, UserStore,
};
use harbor_sqlx::{SqliteAuthStore, SqliteStoreOptions};
use harbor_test_support::TempSqliteDatabase;
use sqlx::Row;
use sqlx::sqlite::SqlitePoolOptions;
use std::time::Duration;
use support::{
    PHC, challenge_id, email_id, migrated_store, now, second_token_hash, session_id, test_service,
    token_hash, user_id,
};

#[tokio::test(flavor = "current_thread")]
async fn connects_migrates_and_checks_foreign_keys() -> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;

    store.verify_foreign_keys().await?;
    assert_eq!(format!("{store:?}"), "SqliteAuthStore { pool: [REDACTED] }");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn connects_to_temp_sqlite_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = TempSqliteDatabase::new("sqlx-store")?;
    let store =
        SqliteAuthStore::connect_and_migrate(fixture.database_url(), SqliteStoreOptions::default())
            .await?;

    store.verify_foreign_keys().await?;
    assert!(fixture.root().exists());
    assert!(fixture.database_path().exists());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn wraps_existing_pool() -> Result<(), Box<dyn std::error::Error>> {
    let store =
        SqliteAuthStore::connect("sqlite::memory:", SqliteStoreOptions::in_memory()).await?;

    sqlx::query("SELECT 1").execute(store.pool()).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn connection_and_pragma_errors_map_to_store_errors() -> Result<(), Box<dyn std::error::Error>>
{
    let failed_connect = SqliteAuthStore::connect(
        "sqlite:/root/harbor/.local/missing-directory/harbor.db",
        SqliteStoreOptions::new(1, Duration::from_millis(1), false, false),
    )
    .await;
    let failed_connect = match failed_connect {
        Ok(_) => return Err("missing sqlite parent directory should fail".into()),
        Err(error) => error,
    };
    assert_eq!(failed_connect.code(), StoreErrorCode::Unavailable);

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&pool)
        .await?;
    let store = SqliteAuthStore::new(pool);
    let disabled = store.verify_foreign_keys().await;
    let disabled = match disabled {
        Ok(_) => return Err("foreign keys should be disabled on a raw pool".into()),
        Err(error) => error,
    };
    assert_eq!(disabled.code(), StoreErrorCode::Unavailable);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn connection_options_cover_custom_and_default_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let defaults = SqliteStoreOptions::default();
    assert_eq!(defaults.max_connections(), 5);
    assert!(defaults.create_if_missing());
    assert!(defaults.use_wal());

    let custom = SqliteStoreOptions::new(1, Duration::from_millis(250), true, true);
    assert_eq!(custom.max_connections(), 1);
    assert_eq!(custom.busy_timeout(), Duration::from_millis(250));
    let store = SqliteAuthStore::connect("sqlite::memory:", custom).await?;
    sqlx::query("SELECT 1").execute(store.pool()).await?;

    let invalid = SqliteAuthStore::connect(
        "sqlite::memory:",
        SqliteStoreOptions::new(0, Duration::from_millis(250), true, false),
    )
    .await;
    let invalid = match invalid {
        Ok(_) => return Err("zero sqlite max_connections should fail".into()),
        Err(error) => error,
    };
    assert_eq!(invalid.code(), StoreErrorCode::Unavailable);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn corrupted_rows_map_to_corrupt_data() -> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let user_id = user_id()?;
    store
        .create_user(CreateUserInput {
            id: user_id.clone(),
            now: now(),
        })
        .await?;

    sqlx::query(
        "INSERT INTO harbor_password_credentials \
         (user_id, password_hash, password_set_at_unix_micros, password_version) \
         VALUES (?1, 'not-a-phc-string', 0, 1)",
    )
    .bind(user_id.as_str())
    .execute(store.pool())
    .await?;
    let password = store
        .get_password_credential(GetPasswordCredentialInput {
            user_id: user_id.clone(),
        })
        .await;
    let password = match password {
        Ok(_) => return Err("corrupt password hash should fail".into()),
        Err(error) => error,
    };
    assert_eq!(password.code(), StoreErrorCode::CorruptData);

    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(store.pool())
        .await?;

    let challenge_id = ChallengeId::try_new("challenge00000999")?;
    sqlx::query(
        "INSERT INTO harbor_challenges \
         (id, purpose, user_id, email_canonical, secret_hash, delivery, redirect_path, \
          expires_at_unix_micros, consumed_at_unix_micros, attempt_count, max_attempts, \
          resend_after_unix_micros, created_at_unix_micros, last_sent_at_unix_micros) \
         VALUES (?1, 'email_sign_in', NULL, 'corrupt@example.com', ?2, 'magic_link', NULL, \
          60000000, NULL, 0, -1, 0, 0, NULL)",
    )
    .bind(challenge_id.as_str())
    .bind(token_hash()?.as_bytes())
    .execute(store.pool())
    .await?;
    let challenge = store
        .get_challenge(GetChallengeInput {
            challenge_id: challenge_id.clone(),
        })
        .await;
    let challenge = match challenge {
        Ok(_) => return Err("negative max attempts should fail".into()),
        Err(error) => error,
    };
    assert_eq!(challenge.code(), StoreErrorCode::CorruptData);

    sqlx::query(
        "INSERT INTO harbor_rate_limits (scope, key_hash, window_start_unix_micros, count) \
         VALUES ('signin', ?1, 0, -2)",
    )
    .bind(second_token_hash()?.as_bytes())
    .execute(store.pool())
    .await?;
    let rate_limit = store
        .increment_rate_limit(IncrementRateLimitInput {
            scope: "signin".to_owned(),
            key_hash: second_token_hash()?,
            window_start: now(),
            max_count: RetryBudget::ONE,
        })
        .await;
    let rate_limit = match rate_limit {
        Ok(_) => return Err("negative rate limit count should fail".into()),
        Err(error) => error,
    };
    assert_eq!(rate_limit.code(), StoreErrorCode::CorruptData);

    sqlx::query("PRAGMA ignore_check_constraints = OFF")
        .execute(store.pool())
        .await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn creates_and_fetches_user_email() -> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let user_id = user_id()?;
    let email = EmailAddress::parse("User@Example.com")?;

    let user = store
        .create_user(CreateUserInput {
            id: user_id.clone(),
            now: now(),
        })
        .await?;
    let stored_user = store
        .get_user(GetUserInput {
            user_id: user_id.clone(),
        })
        .await?;

    assert_eq!(stored_user, Some(user));

    let inserted = store
        .create_user_email(CreateUserEmailInput {
            id: email_id()?,
            user_id: user_id.clone(),
            email_original: email.original().to_owned(),
            email_canonical: email.canonical().clone(),
            is_primary: true,
            now: now(),
        })
        .await?;
    let fetched = store
        .find_email_by_canonical(FindEmailByCanonicalInput {
            email_canonical: email.canonical().clone(),
        })
        .await?;

    assert_eq!(fetched, Some(inserted));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_canonical_email_is_conflict() -> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let user_id = user_id()?;
    let email = EmailAddress::parse("user@example.com")?;

    store
        .create_user(CreateUserInput {
            id: user_id.clone(),
            now: now(),
        })
        .await?;
    store
        .create_user_email(CreateUserEmailInput {
            id: email_id()?,
            user_id: user_id.clone(),
            email_original: email.original().to_owned(),
            email_canonical: email.canonical().clone(),
            is_primary: true,
            now: now(),
        })
        .await?;

    let duplicate = store
        .create_user_email(CreateUserEmailInput {
            id: UserEmailId::try_new("email00000000002")?,
            user_id,
            email_original: email.original().to_owned(),
            email_canonical: email.canonical().clone(),
            is_primary: false,
            now: now(),
        })
        .await;

    let error = match duplicate {
        Ok(_) => return Err("duplicate email should fail".into()),
        Err(error) => error,
    };
    assert_eq!(error.code(), StoreErrorCode::Conflict);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn marks_email_verified() -> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let user_id = user_id()?;
    let email = EmailAddress::parse("user@example.com")?;
    let verified_at = UnixTimestampMicros::try_new(10)?;

    store
        .create_user(CreateUserInput {
            id: user_id.clone(),
            now: now(),
        })
        .await?;
    store
        .create_user_email(CreateUserEmailInput {
            id: email_id()?,
            user_id,
            email_original: email.original().to_owned(),
            email_canonical: email.canonical().clone(),
            is_primary: true,
            now: now(),
        })
        .await?;

    let verified = store
        .mark_email_verified(MarkEmailVerifiedInput {
            email_canonical: email.canonical().clone(),
            verified_at,
        })
        .await?;

    let verified = match verified {
        Some(verified) => verified,
        None => return Err("verified email should exist".into()),
    };
    assert_eq!(verified.verified_at, Some(verified_at));
    assert_eq!(verified.updated_at, verified_at);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn upserts_and_fetches_password_credential() -> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let user_id = user_id()?;

    store
        .create_user(CreateUserInput {
            id: user_id.clone(),
            now: now(),
        })
        .await?;

    let first = store
        .upsert_password_credential(InsertPasswordInput {
            user_id: user_id.clone(),
            password_hash: PasswordHashString::try_new(PHC)?,
            password_set_at: now(),
            password_version: 1,
        })
        .await?;
    let second_time = UnixTimestampMicros::try_new(20)?;
    let second = store
        .upsert_password_credential(InsertPasswordInput {
            user_id: user_id.clone(),
            password_hash: PasswordHashString::try_new(PHC)?,
            password_set_at: second_time,
            password_version: 2,
        })
        .await?;
    let fetched = store
        .get_password_credential(GetPasswordCredentialInput { user_id })
        .await?;

    assert_eq!(first.password_version, 1);
    assert_eq!(second.password_version, 2);
    assert_eq!(fetched, Some(second));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn creates_increments_and_consumes_challenge() -> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let user_id = user_id()?;
    let email = EmailAddress::parse("user@example.com")?;
    let expires_at = UnixTimestampMicros::try_new(600_000_000)?;
    let consumed_at = UnixTimestampMicros::try_new(10)?;

    store
        .create_user(CreateUserInput {
            id: user_id.clone(),
            now: now(),
        })
        .await?;
    let created = store
        .create_challenge(CreateChallengeInput {
            id: challenge_id()?,
            purpose: ChallengePurpose::SignupConfirmation,
            user_id: Some(user_id),
            email_canonical: email.canonical().clone(),
            secret_hash: token_hash()?,
            delivery: ChallengeDelivery::MagicLink,
            redirect_path: Some(RedirectPath::try_new("/account")?),
            expires_at,
            max_attempts: RetryBudget::try_new(5)?,
            resend_after: now(),
            now: now(),
        })
        .await?;

    let fetched = store
        .get_challenge(GetChallengeInput {
            challenge_id: created.id.clone(),
        })
        .await?;
    assert_eq!(fetched, Some(created.clone()));

    let incremented = store
        .increment_challenge_attempts(IncrementChallengeAttemptsInput {
            challenge_id: created.id.clone(),
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
                challenge_id: created.id.clone(),
            },
            consumed_at,
        )
        .await?;
    let consumed = match consumed {
        Some(challenge) => challenge,
        None => return Err("challenge should be consumed once".into()),
    };
    assert_eq!(consumed.consumed_at, Some(consumed_at));

    let second_consume = store
        .consume_challenge(
            GetChallengeInput {
                challenge_id: created.id,
            },
            consumed_at,
        )
        .await?;
    assert_eq!(second_consume, None);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn creates_refreshes_revokes_and_deletes_sessions() -> Result<(), Box<dyn std::error::Error>>
{
    let store = migrated_store().await?;
    let user_id = user_id()?;
    let session_id = session_id()?;
    let token_hash = token_hash()?;
    let refreshed_at = UnixTimestampMicros::try_new(5)?;
    let idle_expires_at = UnixTimestampMicros::try_new(10)?;
    let absolute_expires_at = UnixTimestampMicros::try_new(20)?;
    let cleanup_at = UnixTimestampMicros::try_new(30)?;

    store
        .create_user(CreateUserInput {
            id: user_id.clone(),
            now: now(),
        })
        .await?;
    let created = store
        .create_session(CreateSessionInput {
            id: session_id.clone(),
            user_id: user_id.clone(),
            token_hash: token_hash.clone(),
            created_at: now(),
            idle_expires_at,
            absolute_expires_at,
            ip_hash: Some(second_token_hash()?),
            user_agent_hash: None,
        })
        .await?;
    let fetched = store
        .get_session_by_token_hash(GetSessionInput {
            token_hash: token_hash.clone(),
        })
        .await?;
    assert_eq!(fetched, Some(created));

    let refreshed = store
        .update_session_last_seen(UpdateSessionLastSeenInput {
            session_id: session_id.clone(),
            last_seen_at: refreshed_at,
        })
        .await?;
    let refreshed = match refreshed {
        Some(session) => session,
        None => return Err("session should refresh".into()),
    };
    assert_eq!(refreshed.last_seen_at, refreshed_at);

    let revoked = store
        .revoke_session(RevokeSessionInput {
            session_id: session_id.clone(),
            revoked_at: refreshed_at,
        })
        .await?;
    let revoked = match revoked {
        Some(session) => session,
        None => return Err("session should revoke".into()),
    };
    assert_eq!(revoked.revoked_at, Some(refreshed_at));

    let deleted = store
        .delete_expired_sessions(DeleteExpiredSessionsInput { now: cleanup_at })
        .await?;
    assert_eq!(deleted, 1);

    let missing = store
        .get_session_by_token_hash(GetSessionInput { token_hash })
        .await?;
    assert_eq!(missing, None);

    store
        .create_session(CreateSessionInput {
            id: SessionId::try_new("session000000002")?,
            user_id: user_id.clone(),
            token_hash: second_token_hash()?,
            created_at: now(),
            idle_expires_at,
            absolute_expires_at,
            ip_hash: None,
            user_agent_hash: None,
        })
        .await?;
    let revoked_count = store
        .revoke_user_sessions(RevokeUserSessionsInput {
            user_id,
            revoked_at: cleanup_at,
        })
        .await?;
    assert_eq!(revoked_count, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn increments_rate_limits_with_boundary_decision() -> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let key_hash = token_hash()?;
    let max_count = RetryBudget::try_new(2)?;

    let first = store
        .increment_rate_limit(IncrementRateLimitInput {
            scope: "signin".to_owned(),
            key_hash: key_hash.clone(),
            window_start: now(),
            max_count,
        })
        .await?;
    let second = store
        .increment_rate_limit(IncrementRateLimitInput {
            scope: "signin".to_owned(),
            key_hash: key_hash.clone(),
            window_start: now(),
            max_count,
        })
        .await?;
    let third = store
        .increment_rate_limit(IncrementRateLimitInput {
            scope: "signin".to_owned(),
            key_hash,
            window_start: now(),
            max_count,
        })
        .await?;

    assert_eq!(first.count, 1);
    assert!(first.allowed);
    assert_eq!(second.count, 2);
    assert!(second.allowed);
    assert_eq!(third.count, 3);
    assert!(!third.allowed);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn appends_auth_events_with_hashed_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let user_id = user_id()?;
    let email = EmailAddress::parse("user@example.com")?;
    let ip_hash = token_hash()?;
    let user_agent_hash = second_token_hash()?;

    store
        .create_user(CreateUserInput {
            id: user_id.clone(),
            now: now(),
        })
        .await?;
    let event = store
        .append_auth_event(AppendAuthEventInput {
            id: AuthEventId::try_new("event00000000001")?,
            user_id: Some(user_id),
            email_canonical: Some(email.canonical().clone()),
            kind: AuthEventKind::SignInSucceeded,
            occurred_at: now(),
            ip_hash: Some(ip_hash.clone()),
            user_agent_hash: Some(user_agent_hash.clone()),
            detail_code: Some("password".to_owned()),
        })
        .await?;

    let row = sqlx::query(
        "SELECT ip_hash, user_agent_hash, detail_code FROM harbor_auth_events WHERE id = ?1",
    )
    .bind(event.id.as_str())
    .fetch_one(store.pool())
    .await?;
    let stored_ip_hash: Vec<u8> = row.try_get("ip_hash")?;
    let stored_user_agent_hash: Vec<u8> = row.try_get("user_agent_hash")?;
    let detail_code: String = row.try_get("detail_code")?;

    assert_eq!(stored_ip_hash, ip_hash.as_bytes());
    assert_eq!(stored_user_agent_hash, user_agent_hash.as_bytes());
    assert_eq!(detail_code, "password");
    assert_eq!(event.kind, AuthEventKind::SignInSucceeded);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn sqlite_store_satisfies_shared_auth_store_contracts()
-> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;

    harbor_test_support::store_contracts::run_auth_store_contracts(store).await
}

#[tokio::test(flavor = "current_thread")]
async fn password_service_signup_signin_current_session_and_signout()
-> Result<(), Box<dyn std::error::Error>> {
    let store = migrated_store().await?;
    let service = test_service(store.clone())?;

    let signup = service
        .sign_up_with_password(harbor_core::PasswordSignUpInput {
            email: "service@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
        })
        .await?;
    let unverified = service
        .sign_in_with_password(harbor_core::PasswordSignInInput {
            email: "service@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
            redirect_path: Some(RedirectPath::try_new("/account")?),
        })
        .await;
    let unverified = match unverified {
        Ok(_) => return Err("unverified signin should fail".into()),
        Err(error) => error,
    };
    assert_eq!(unverified.code(), AuthErrorCode::EmailNotVerified);

    let confirmation = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::SignupConfirmation,
            delivery: ChallengeDelivery::MagicLink,
            email: signup.email.email_original.clone(),
            user_id: Some(signup.user.id.clone()),
            redirect_path: Some(RedirectPath::try_new("/account")?),
        })
        .await?;
    let verified = service
        .verify_email_challenge(harbor_core::VerifyChallengeInput {
            challenge_id: confirmation.challenge.id,
            purpose: ChallengePurpose::SignupConfirmation,
            secret: confirmation.secret,
        })
        .await?;
    assert_eq!(
        verified.challenge.email_canonical,
        signup.email.email_canonical
    );

    let signin = service
        .sign_in_with_password(harbor_core::PasswordSignInInput {
            email: "SERVICE@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
            redirect_path: Some(RedirectPath::try_new("/account")?),
        })
        .await?;
    assert_eq!(
        signin.redirect_path,
        Some(RedirectPath::try_new("/account")?)
    );

    let current = service.current_session(&signin.session_token).await?;
    assert!(current.is_some());

    let signed_out = service.sign_out(&signin.session_token).await?;
    assert!(signed_out);
    let current_after_signout = service.current_session(&signin.session_token).await?;
    assert_eq!(current_after_signout, None);
    Ok(())
}

#[test]
fn auth_event_id_is_available_for_later_store_slices() -> Result<(), harbor_core::DomainError> {
    let id = AuthEventId::try_new("event00000000001")?;

    assert_eq!(id.as_str(), "event00000000001");
    Ok(())
}
