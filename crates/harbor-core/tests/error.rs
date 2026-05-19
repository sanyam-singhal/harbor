//! Integration tests for Harbor error contracts.

use harbor_core::{
    AuthError, AuthErrorCode, ConfigError, ConfigErrorCode, MailError, MailErrorCode, StoreError,
    StoreErrorCode,
};

#[test]
fn auth_error_user_messages_are_safe() {
    let error = AuthError::with_detail(AuthErrorCode::Internal, "sql_unique_email_failed");

    assert_eq!(error.code(), AuthErrorCode::Internal);
    assert_eq!(error.detail(), Some("sql_unique_email_failed"));
    assert_eq!(
        error.to_string(),
        "Authentication is temporarily unavailable."
    );
    assert_eq!(
        error.user_message(),
        "Authentication is temporarily unavailable."
    );
}

#[test]
fn auth_error_codes_are_stable() {
    assert_eq!(
        AuthErrorCode::InvalidCredentials.as_str(),
        "invalid_credentials"
    );
    assert_eq!(
        AuthErrorCode::EmailNotVerified.as_str(),
        "email_not_verified"
    );
    assert_eq!(AuthErrorCode::RateLimited.as_str(), "rate_limited");
    assert_eq!(AuthErrorCode::Csrf.as_str(), "csrf_failed");
    assert_eq!(AuthErrorCode::SessionExpired.as_str(), "session_expired");
    assert_eq!(AuthErrorCode::Forbidden.as_str(), "forbidden");
    assert_eq!(AuthErrorCode::Store.as_str(), "store_error");
    assert_eq!(AuthErrorCode::Mail.as_str(), "mail_error");
    assert_eq!(AuthErrorCode::Config.as_str(), "config_error");
    assert_eq!(AuthErrorCode::Internal.as_str(), "internal_error");
    assert_eq!(StoreErrorCode::NotFound.as_str(), "not_found");
    assert_eq!(StoreErrorCode::Conflict.as_str(), "conflict");
    assert_eq!(StoreErrorCode::CorruptData.as_str(), "corrupt_data");
    assert_eq!(StoreErrorCode::Transaction.as_str(), "transaction");
    assert_eq!(StoreErrorCode::Unavailable.as_str(), "unavailable");
    assert_eq!(StoreErrorCode::Internal.as_str(), "internal");
    assert_eq!(MailErrorCode::InvalidConfig.as_str(), "invalid_config");
    assert_eq!(MailErrorCode::Rejected.as_str(), "rejected");
    assert_eq!(MailErrorCode::RateLimited.as_str(), "rate_limited");
    assert_eq!(MailErrorCode::Unavailable.as_str(), "unavailable");
    assert_eq!(MailErrorCode::Internal.as_str(), "internal");
    assert_eq!(ConfigErrorCode::Missing.as_str(), "missing");
    assert_eq!(ConfigErrorCode::Invalid.as_str(), "invalid");
    assert_eq!(ConfigErrorCode::WeakSecret.as_str(), "weak_secret");
    assert_eq!(ConfigErrorCode::InvalidUrl.as_str(), "invalid_url");
    assert_eq!(ConfigErrorCode::Internal.as_str(), "internal");
}

#[test]
fn auth_error_user_messages_cover_each_code() {
    let cases = [
        (
            AuthErrorCode::InvalidCredentials,
            "The submitted credentials are invalid.",
        ),
        (
            AuthErrorCode::EmailNotVerified,
            "Please verify your email address to continue.",
        ),
        (
            AuthErrorCode::RateLimited,
            "Too many attempts. Please try again later.",
        ),
        (AuthErrorCode::Csrf, "The form expired. Please try again."),
        (AuthErrorCode::SessionExpired, "Please sign in again."),
        (AuthErrorCode::Forbidden, "You cannot perform this action."),
        (
            AuthErrorCode::Store,
            "Authentication is temporarily unavailable.",
        ),
        (
            AuthErrorCode::Mail,
            "Authentication is temporarily unavailable.",
        ),
        (
            AuthErrorCode::Config,
            "Authentication is temporarily unavailable.",
        ),
        (
            AuthErrorCode::Internal,
            "Authentication is temporarily unavailable.",
        ),
    ];

    for (code, message) in cases {
        assert_eq!(AuthError::new(code).user_message(), message);
    }
}

#[test]
fn lower_level_error_accessors_keep_details() {
    let store = StoreError::with_detail(StoreErrorCode::Transaction, "tx");
    let mail = MailError::with_detail(MailErrorCode::Internal, "template");
    let config = ConfigError::with_detail(ConfigErrorCode::Internal, "builder");

    assert_eq!(store.code(), StoreErrorCode::Transaction);
    assert_eq!(store.detail(), Some("tx"));
    assert_eq!(mail.code(), MailErrorCode::Internal);
    assert_eq!(mail.detail(), Some("template"));
    assert_eq!(config.code(), ConfigErrorCode::Internal);
    assert_eq!(config.detail(), Some("builder"));
}

#[test]
fn lower_level_errors_convert_to_auth_error_without_secret_detail() {
    let store = StoreError::with_detail(StoreErrorCode::Conflict, "email_unique");
    let mail = MailError::with_detail(MailErrorCode::Rejected, "resend_403");
    let config = ConfigError::with_detail(ConfigErrorCode::InvalidUrl, "public_base_url");

    let store_auth = AuthError::from(store);
    let mail_auth = AuthError::from(mail);
    let config_auth = AuthError::from(config);

    assert_eq!(store_auth.code(), AuthErrorCode::Store);
    assert_eq!(store_auth.detail(), Some("conflict"));
    assert_eq!(mail_auth.code(), AuthErrorCode::Mail);
    assert_eq!(mail_auth.detail(), Some("rejected"));
    assert_eq!(config_auth.code(), AuthErrorCode::Config);
    assert_eq!(config_auth.detail(), Some("invalid_url"));
}

#[test]
fn lower_level_display_messages_are_generic() {
    assert_eq!(
        StoreError::new(StoreErrorCode::Unavailable).to_string(),
        "storage operation failed"
    );
    assert_eq!(
        MailError::new(MailErrorCode::Unavailable).to_string(),
        "email delivery failed"
    );
    assert_eq!(
        ConfigError::new(ConfigErrorCode::Missing).to_string(),
        "configuration is invalid"
    );
}
