//! SQLite row codecs and storage error mapping.

use harbor_core::{
    AuthEventKind, CanonicalEmail, ChallengeDelivery, ChallengeId, ChallengePurpose,
    ChallengeRecord, DomainError, PasswordCredentialRecord, RedirectPath, RetryBudget, SessionId,
    SessionRecord, StoreError, StoreErrorCode, TokenHash, UnixTimestampMicros, UserEmailRecord,
    UserId, UserRecord,
};
use sqlx::Row;

pub(super) fn user_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<UserRecord, StoreError> {
    Ok(UserRecord {
        id: user_id(get_string(row, "id")?)?,
        created_at: timestamp(get_i64(row, "created_at_unix_micros")?)?,
        updated_at: timestamp(get_i64(row, "updated_at_unix_micros")?)?,
        disabled_at: optional_timestamp(get_optional_i64(row, "disabled_at_unix_micros")?)?,
    })
}

pub(super) fn email_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<UserEmailRecord, StoreError> {
    Ok(UserEmailRecord {
        id: harbor_core::UserEmailId::try_new(get_string(row, "id")?).map_err(map_domain_error)?,
        user_id: user_id(get_string(row, "user_id")?)?,
        email_original: get_string(row, "email_original")?,
        email_canonical: CanonicalEmail::try_new(get_string(row, "email_canonical")?)
            .map_err(map_domain_error)?,
        verified_at: optional_timestamp(get_optional_i64(row, "verified_at_unix_micros")?)?,
        is_primary: get_i64(row, "is_primary")? == 1,
        created_at: timestamp(get_i64(row, "created_at_unix_micros")?)?,
        updated_at: timestamp(get_i64(row, "updated_at_unix_micros")?)?,
    })
}

pub(super) fn password_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<PasswordCredentialRecord, StoreError> {
    Ok(PasswordCredentialRecord {
        user_id: user_id(get_string(row, "user_id")?)?,
        password_hash: harbor_core::PasswordHashString::try_new(get_string(row, "password_hash")?)
            .map_err(|_error| {
                StoreError::with_detail(StoreErrorCode::CorruptData, "password_hash")
            })?,
        password_set_at: timestamp(get_i64(row, "password_set_at_unix_micros")?)?,
        password_version: get_i64(row, "password_version")?,
    })
}

pub(super) fn challenge_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<ChallengeRecord, StoreError> {
    Ok(ChallengeRecord {
        id: ChallengeId::try_new(get_string(row, "id")?).map_err(map_domain_error)?,
        purpose: challenge_purpose_from_db(&get_string(row, "purpose")?)?,
        user_id: get_optional_string(row, "user_id")?
            .map(user_id)
            .transpose()?,
        email_canonical: CanonicalEmail::try_new(get_string(row, "email_canonical")?)
            .map_err(map_domain_error)?,
        secret_hash: TokenHash::try_new(get_bytes(row, "secret_hash")?)
            .map_err(map_domain_error)?,
        delivery: challenge_delivery_from_db(&get_string(row, "delivery")?)?,
        redirect_path: get_optional_string(row, "redirect_path")?
            .map(RedirectPath::try_new)
            .transpose()
            .map_err(map_domain_error)?,
        expires_at: timestamp(get_i64(row, "expires_at_unix_micros")?)?,
        consumed_at: optional_timestamp(get_optional_i64(row, "consumed_at_unix_micros")?)?,
        attempt_count: get_i64(row, "attempt_count")?,
        max_attempts: retry_budget(get_i64(row, "max_attempts")?)?,
        resend_after: timestamp(get_i64(row, "resend_after_unix_micros")?)?,
        created_at: timestamp(get_i64(row, "created_at_unix_micros")?)?,
        last_sent_at: optional_timestamp(get_optional_i64(row, "last_sent_at_unix_micros")?)?,
    })
}

pub(super) fn session_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<SessionRecord, StoreError> {
    Ok(SessionRecord {
        id: SessionId::try_new(get_string(row, "id")?).map_err(map_domain_error)?,
        user_id: user_id(get_string(row, "user_id")?)?,
        token_hash: TokenHash::try_new(get_bytes(row, "token_hash")?).map_err(map_domain_error)?,
        created_at: timestamp(get_i64(row, "created_at_unix_micros")?)?,
        last_seen_at: timestamp(get_i64(row, "last_seen_at_unix_micros")?)?,
        idle_expires_at: timestamp(get_i64(row, "idle_expires_at_unix_micros")?)?,
        absolute_expires_at: timestamp(get_i64(row, "absolute_expires_at_unix_micros")?)?,
        revoked_at: optional_timestamp(get_optional_i64(row, "revoked_at_unix_micros")?)?,
        ip_hash: get_optional_bytes(row, "ip_hash")?
            .map(TokenHash::try_new)
            .transpose()
            .map_err(map_domain_error)?,
        user_agent_hash: get_optional_bytes(row, "user_agent_hash")?
            .map(TokenHash::try_new)
            .transpose()
            .map_err(map_domain_error)?,
    })
}

pub(super) fn auth_event_kind_to_db(value: AuthEventKind) -> &'static str {
    match value {
        AuthEventKind::SignupRequested => "signup_requested",
        AuthEventKind::EmailVerified => "email_verified",
        AuthEventKind::SignInSucceeded => "sign_in_succeeded",
        AuthEventKind::SignInFailed => "sign_in_failed",
        AuthEventKind::PasswordResetRequested => "password_reset_requested",
        AuthEventKind::PasswordResetCompleted => "password_reset_completed",
        AuthEventKind::SessionRevoked => "session_revoked",
        _ => "unknown",
    }
}

pub(super) fn challenge_purpose_to_db(value: ChallengePurpose) -> &'static str {
    match value {
        ChallengePurpose::SignupConfirmation => "signup_confirmation",
        ChallengePurpose::EmailSignIn => "email_sign_in",
        ChallengePurpose::PasswordReset => "password_reset",
        _ => "unknown",
    }
}

pub(super) fn challenge_purpose_from_db(value: &str) -> Result<ChallengePurpose, StoreError> {
    match value {
        "signup_confirmation" => Ok(ChallengePurpose::SignupConfirmation),
        "email_sign_in" => Ok(ChallengePurpose::EmailSignIn),
        "password_reset" => Ok(ChallengePurpose::PasswordReset),
        _ => Err(StoreError::with_detail(
            StoreErrorCode::CorruptData,
            "challenge_purpose",
        )),
    }
}

pub(super) fn challenge_delivery_to_db(value: ChallengeDelivery) -> &'static str {
    match value {
        ChallengeDelivery::MagicLink => "magic_link",
        ChallengeDelivery::OtpCode => "otp_code",
        ChallengeDelivery::Both => "both",
        _ => "unknown",
    }
}

pub(super) fn challenge_delivery_from_db(value: &str) -> Result<ChallengeDelivery, StoreError> {
    match value {
        "magic_link" => Ok(ChallengeDelivery::MagicLink),
        "otp_code" => Ok(ChallengeDelivery::OtpCode),
        "both" => Ok(ChallengeDelivery::Both),
        _ => Err(StoreError::with_detail(
            StoreErrorCode::CorruptData,
            "challenge_delivery",
        )),
    }
}

pub(super) fn map_domain_error(_error: DomainError) -> StoreError {
    StoreError::with_detail(StoreErrorCode::CorruptData, "domain_decode")
}

pub(super) fn map_sqlx_error(error: sqlx::Error, detail: &'static str) -> StoreError {
    match error {
        sqlx::Error::Database(database_error) if database_error.is_unique_violation() => {
            StoreError::with_detail(StoreErrorCode::Conflict, detail)
        }
        sqlx::Error::ColumnDecode { .. } | sqlx::Error::ColumnNotFound(_) => {
            StoreError::with_detail(StoreErrorCode::CorruptData, detail)
        }
        _ => StoreError::with_detail(StoreErrorCode::Unavailable, detail),
    }
}

fn get_string(row: &sqlx::sqlite::SqliteRow, column: &'static str) -> Result<String, StoreError> {
    row.try_get(column)
        .map_err(|error| map_sqlx_error(error, column))
}

fn get_optional_string(
    row: &sqlx::sqlite::SqliteRow,
    column: &'static str,
) -> Result<Option<String>, StoreError> {
    row.try_get(column)
        .map_err(|error| map_sqlx_error(error, column))
}

fn get_bytes(row: &sqlx::sqlite::SqliteRow, column: &'static str) -> Result<Vec<u8>, StoreError> {
    row.try_get(column)
        .map_err(|error| map_sqlx_error(error, column))
}

fn get_optional_bytes(
    row: &sqlx::sqlite::SqliteRow,
    column: &'static str,
) -> Result<Option<Vec<u8>>, StoreError> {
    row.try_get(column)
        .map_err(|error| map_sqlx_error(error, column))
}

pub(super) fn get_i64(
    row: &sqlx::sqlite::SqliteRow,
    column: &'static str,
) -> Result<i64, StoreError> {
    row.try_get(column)
        .map_err(|error| map_sqlx_error(error, column))
}

fn get_optional_i64(
    row: &sqlx::sqlite::SqliteRow,
    column: &'static str,
) -> Result<Option<i64>, StoreError> {
    row.try_get(column)
        .map_err(|error| map_sqlx_error(error, column))
}

fn user_id(value: String) -> Result<UserId, StoreError> {
    UserId::try_new(value).map_err(map_domain_error)
}

fn timestamp(value: i64) -> Result<UnixTimestampMicros, StoreError> {
    UnixTimestampMicros::try_new(value).map_err(map_domain_error)
}

fn retry_budget(value: i64) -> Result<RetryBudget, StoreError> {
    let value = usize::try_from(value)
        .map_err(|_error| StoreError::with_detail(StoreErrorCode::CorruptData, "retry_budget"))?;
    RetryBudget::try_new(value).map_err(map_domain_error)
}

fn optional_timestamp(value: Option<i64>) -> Result<Option<UnixTimestampMicros>, StoreError> {
    value.map(timestamp).transpose()
}
