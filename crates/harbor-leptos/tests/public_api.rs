//! Public API integration tests for `harbor-leptos`.

use harbor_core::{
    AuthErrorCode, MailError, PasswordPolicy, RetryBudget, SecretToken, UnixTimestampMicros,
};
use harbor_email::{
    AuthEmail, AuthEmailRenderer, ChallengeEmailInput, EmailRecipient, RecordingMailer, SecretUrl,
};
use harbor_leptos::{
    AuthRateLimits, ChallengeLifetimes, CookieDefaults, CookieName, Harbor, HeaderName,
    PublicBaseUrl, SameSite, build_csrf_cookie, build_delete_csrf_cookie,
    build_delete_session_cookie, build_session_cookie, expect_harbor_context, issue_csrf_token,
    parse_cookie_value, provide_harbor_context, use_harbor_context, validate_csrf_from_headers,
    validate_csrf_tokens,
};
use harbor_test_support::DeterministicSecretGenerator;
use leptos::prelude::Owner;

#[derive(Debug)]
struct TestRenderer;

impl AuthEmailRenderer for TestRenderer {
    fn render_challenge_email(&self, input: ChallengeEmailInput) -> Result<AuthEmail, MailError> {
        AuthEmail::try_new(
            input.purpose,
            input.to,
            input.challenge_id,
            "Test subject".to_owned(),
            "Test body".to_owned(),
            None,
        )
    }
}

#[test]
fn builder_validates_required_configuration() -> Result<(), Box<dyn std::error::Error>> {
    let missing = Harbor::builder().finish();
    assert!(missing.is_err());

    let harbor = Harbor::builder()
        .with_store("store")
        .with_mailer(RecordingMailer::new())
        .with_public_base_url("https://app.example.com/")?
        .with_hmac_secret_key(vec![7; 32])?
        .with_default_email_renderer("TestAuth", "app.example.com")?
        .finish()?;

    assert_eq!(
        harbor.config().public_base_url().as_str(),
        "https://app.example.com"
    );
    assert_eq!(
        harbor
            .config()
            .cookie_defaults()
            .session_cookie_name()
            .as_str(),
        "__Host-harbor-session"
    );
    assert!(!format!("{:?}", harbor.config()).contains("7, 7"));
    Ok(())
}

#[test]
fn public_base_url_requires_https_except_local_development() {
    assert!(PublicBaseUrl::try_new("https://app.example.com").is_ok());
    assert!(PublicBaseUrl::try_new("http://localhost:3000").is_ok());
    assert!(PublicBaseUrl::try_new("http://127.0.0.1:3000").is_ok());
    assert_eq!(
        PublicBaseUrl::try_new("https://app.example.com/").map(|value| value.to_string()),
        Ok("https://app.example.com".to_owned())
    );
    assert!(PublicBaseUrl::try_new("").is_err());
    assert!(PublicBaseUrl::try_new(format!("https://{}", "a".repeat(2050))).is_err());
    assert!(PublicBaseUrl::try_new("https://example.com/\n").is_err());
    assert!(PublicBaseUrl::try_new("http://example.com").is_err());
    assert!(PublicBaseUrl::try_new("https://example.com?x=1").is_err());
    assert!(PublicBaseUrl::try_new("https://example.com#fragment").is_err());
}

#[test]
fn cookie_policy_rejects_insecure_cross_site_and_bad_names()
-> Result<(), Box<dyn std::error::Error>> {
    let insecure_cross_site = CookieDefaults::development().with_same_site(SameSite::None);
    let builder = Harbor::builder()
        .with_store("store")
        .with_mailer(RecordingMailer::new())
        .with_public_base_url("http://localhost:3000")?
        .with_hmac_secret_key(vec![7; 32])?;

    assert!(builder.with_cookie_defaults(insecure_cross_site).is_err());
    assert!(CookieName::try_new("").is_err());
    assert!(CookieName::try_new("a".repeat(65)).is_err());
    assert!(CookieName::try_new("bad name").is_err());
    assert_eq!(
        CookieName::try_new("valid-name_1")?.as_str(),
        "valid-name_1"
    );
    Ok(())
}

#[test]
fn custom_lifetimes_reject_zero_values() -> Result<(), Box<dyn std::error::Error>> {
    let lifetimes = ChallengeLifetimes {
        signup_confirmation: UnixTimestampMicros::EPOCH,
        email_signin: UnixTimestampMicros::try_new(1)?,
        password_reset: UnixTimestampMicros::try_new(1)?,
    };
    let builder = Harbor::builder()
        .with_store("store")
        .with_mailer(RecordingMailer::new())
        .with_public_base_url("http://localhost:3000")?
        .with_hmac_secret_key(vec![7; 32])?;

    assert!(builder.with_challenge_lifetimes(lifetimes).is_err());
    Ok(())
}

#[test]
fn custom_configuration_accessors_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let lifetimes = ChallengeLifetimes {
        signup_confirmation: UnixTimestampMicros::try_new(2_000_000)?,
        email_signin: UnixTimestampMicros::try_new(3_000_000)?,
        password_reset: UnixTimestampMicros::try_new(4_000_000)?,
    };
    let rate_limits = AuthRateLimits {
        signup: RetryBudget::try_new(2)?,
        password_signin: RetryBudget::try_new(3)?,
        email_challenge: RetryBudget::try_new(4)?,
        password_reset: RetryBudget::try_new(5)?,
        window: UnixTimestampMicros::try_new(60_000_000)?,
    };
    let policy = PasswordPolicy::try_new(10, 128)?;
    let harbor = Harbor::builder()
        .with_store("store")
        .with_mailer(RecordingMailer::new())
        .with_public_base_url("http://localhost:3000")?
        .with_cookie_defaults(CookieDefaults::development().with_same_site(SameSite::Strict))?
        .with_hmac_secret_key(vec![7; 32])?
        .with_password_policy(policy)
        .with_challenge_lifetimes(lifetimes)?
        .with_rate_limits(rate_limits)?
        .with_default_email_renderer("TestAuth", "test.local")?
        .finish()?;

    assert_eq!(harbor.store(), &"store");
    assert_eq!(harbor.config().csrf_header_name().as_str(), "x-harbor-csrf");
    assert_eq!(harbor.config().hmac_secret_key().expose_secret(), &[7; 32]);
    assert_eq!(harbor.config().password_policy().min_chars(), 10);
    assert_eq!(harbor.config().password_policy().max_bytes(), 128);
    assert_eq!(harbor.config().challenge_lifetimes(), &lifetimes);
    assert_eq!(harbor.config().rate_limits(), &rate_limits);
    assert_eq!(
        harbor.config().cookie_defaults().same_site(),
        SameSite::Strict
    );
    assert_eq!(harbor.config().cookie_defaults().path(), "/");
    assert!(!harbor.config().cookie_defaults().secure());
    assert!(harbor.config().cookie_defaults().session_http_only());
    assert!(!harbor.config().cookie_defaults().csrf_http_only());
    let rendered = harbor.config().email_renderer().render_challenge_email(
        ChallengeEmailInput {
            purpose: harbor_core::ChallengePurpose::SignupConfirmation,
            delivery: harbor_core::ChallengeDelivery::MagicLink,
            to: EmailRecipient::parse("user@example.com")?,
            challenge_id: harbor_core::ChallengeId::try_new("challenge00000001")?,
            action_url: Some(SecretUrl::try_new(
                "http://localhost:3000/auth/confirm-email?challenge=challenge00000001&token=abc",
            )?),
            otp_code: None,
        },
    )?;
    assert!(rendered.subject().contains("TestAuth"));
    assert!(rendered.text_body().contains("test.local"));
    Ok(())
}

#[test]
fn builder_reports_each_missing_required_part() -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        Harbor::builder()
            .with_mailer(RecordingMailer::new())
            .finish()
            .is_err()
    );
    assert!(Harbor::builder().with_store("store").finish().is_err());
    assert!(
        Harbor::builder()
            .with_store("store")
            .with_mailer(RecordingMailer::new())
            .with_hmac_secret_key(vec![7; 32])?
            .with_default_email_renderer("TestAuth", "localhost")?
            .finish()
            .is_err()
    );
    assert!(
        Harbor::builder()
            .with_store("store")
            .with_mailer(RecordingMailer::new())
            .with_public_base_url("http://localhost:3000")?
            .with_default_email_renderer("TestAuth", "localhost")?
            .finish()
            .is_err()
    );
    assert!(
        Harbor::builder()
            .with_store("store")
            .with_mailer(RecordingMailer::new())
            .with_public_base_url("http://localhost:3000")?
            .with_hmac_secret_key(vec![7; 32])?
            .finish()
            .is_err()
    );
    assert!(
        Harbor::builder()
            .with_store("store")
            .with_mailer(RecordingMailer::new())
            .with_public_base_url("http://localhost:3000")?
            .with_hmac_secret_key(vec![1; 8])
            .is_err()
    );
    Ok(())
}

#[test]
fn header_names_are_conservative() -> Result<(), Box<dyn std::error::Error>> {
    assert!(HeaderName::try_new("").is_err());
    assert!(HeaderName::try_new("a".repeat(65)).is_err());
    assert!(HeaderName::try_new("x harbor csrf").is_err());
    assert_eq!(
        HeaderName::try_new("x-harbor-csrf")?.as_str(),
        "x-harbor-csrf"
    );
    Ok(())
}

#[test]
fn rate_limit_window_must_be_positive() -> Result<(), Box<dyn std::error::Error>> {
    let limits = AuthRateLimits {
        window: UnixTimestampMicros::EPOCH,
        ..AuthRateLimits::default()
    };
    let builder = Harbor::builder()
        .with_store("store")
        .with_mailer(RecordingMailer::new())
        .with_public_base_url("http://localhost:3000")?
        .with_hmac_secret_key(vec![7; 32])?;

    assert!(builder.with_rate_limits(limits).is_err());
    Ok(())
}

#[test]
fn builder_accepts_custom_renderer_and_rejects_bad_default_renderer()
-> Result<(), Box<dyn std::error::Error>> {
    let harbor = Harbor::builder()
        .with_store("store")
        .with_mailer(RecordingMailer::new())
        .with_public_base_url("http://localhost:3000")?
        .with_hmac_secret_key(vec![7; 32])?
        .with_email_renderer(TestRenderer)
        .finish()?;
    let rendered =
        harbor
            .config()
            .email_renderer()
            .render_challenge_email(ChallengeEmailInput {
                purpose: harbor_core::ChallengePurpose::EmailSignIn,
                delivery: harbor_core::ChallengeDelivery::OtpCode,
                to: EmailRecipient::parse("user@example.com")?,
                challenge_id: harbor_core::ChallengeId::try_new("challenge00000002")?,
                action_url: None,
                otp_code: Some(SecretToken::try_new("12345678")?),
            })?;
    assert_eq!(rendered.subject(), "Test subject");

    let invalid = Harbor::builder()
        .with_store("store")
        .with_mailer(RecordingMailer::new())
        .with_public_base_url("http://localhost:3000")?
        .with_hmac_secret_key(vec![7; 32])?
        .with_default_email_renderer("", "localhost");
    assert!(invalid.is_err());
    Ok(())
}

#[test]
fn leptos_context_round_trips_harbor_shell() -> Result<(), Box<dyn std::error::Error>> {
    let harbor = Harbor::builder()
        .with_store("store")
        .with_mailer(RecordingMailer::new())
        .with_public_base_url("http://localhost:3000")?
        .with_hmac_secret_key(vec![7; 32])?
        .with_default_email_renderer("TestAuth", "localhost")?
        .finish()?;
    let owner = Owner::new();

    owner.with(|| {
        provide_harbor_context(harbor.clone());
        let loaded = use_harbor_context::<&'static str, RecordingMailer>();
        let expected = expect_harbor_context::<&'static str, RecordingMailer>();
        assert_eq!(
            expected.harbor().config().public_base_url().as_str(),
            "http://localhost:3000"
        );
        match loaded {
            Some(context) => {
                assert_eq!(
                    context.harbor().config().public_base_url().as_str(),
                    "http://localhost:3000"
                );
                let harbor = context.into_harbor();
                assert_eq!(harbor.mailer().recorded()?.len(), 0);
                Ok(())
            }
            None => Err("harbor context should be available".into()),
        }
    })
}

#[test]
fn cookie_helpers_build_parse_and_delete_headers() -> Result<(), Box<dyn std::error::Error>> {
    let defaults = CookieDefaults::production();
    let session =
        build_session_cookie(&defaults, &SecretToken::try_new("sessiontoken")?, Some(60))?;
    let csrf = build_csrf_cookie(&defaults, &SecretToken::try_new("csrftoken")?, None)?;
    let parsed = parse_cookie_value(
        "other=1; __Host-harbor-session=sessiontoken; harbor_csrf=old",
        defaults.session_cookie_name(),
    );
    let delete = build_delete_session_cookie(&defaults);
    let delete_csrf = build_delete_csrf_cookie(&defaults);

    assert!(session.contains("__Host-harbor-session=sessiontoken"));
    assert!(session.contains("Max-Age=60"));
    assert!(session.contains("Secure"));
    assert!(session.contains("HttpOnly"));
    assert!(csrf.contains("__Host-harbor-csrf=csrftoken"));
    assert!(!csrf.contains("HttpOnly"));
    assert_eq!(parsed, Some("sessiontoken".to_owned()));
    assert_eq!(
        parse_cookie_value("one=1; two=2", defaults.session_cookie_name()),
        None
    );
    assert!(delete.contains("Max-Age=0"));
    assert!(delete_csrf.contains("__Host-harbor-csrf="));
    Ok(())
}

#[test]
fn cookie_headers_cover_variants_and_rejections() -> Result<(), Box<dyn std::error::Error>> {
    let strict = CookieDefaults::production().with_same_site(SameSite::Strict);
    let none = CookieDefaults::production().with_same_site(SameSite::None);
    let token = SecretToken::try_new("sessiontoken")?;

    let strict_header = build_session_cookie(&strict, &token, None)?;
    let none_header = build_session_cookie(&none, &token, Some(0))?;

    assert!(strict_header.contains("SameSite=Strict"));
    assert!(none_header.contains("SameSite=None"));
    assert!(build_session_cookie(&strict, &token, Some(-1)).is_err());
    Ok(())
}

#[test]
fn csrf_tokens_validate_through_cookie_and_header() -> Result<(), Box<dyn std::error::Error>> {
    let harbor = Harbor::builder()
        .with_store("store")
        .with_mailer(RecordingMailer::new())
        .with_public_base_url("http://localhost:3000")?
        .with_hmac_secret_key(vec![7; 32])?
        .with_default_email_renderer("TestAuth", "localhost")?
        .finish()?;
    let token = issue_csrf_token(harbor.config(), &DeterministicSecretGenerator::new())?;
    let csrf_cookie = build_csrf_cookie(harbor.config().cookie_defaults(), &token, None)?;
    let cookie_header = match csrf_cookie.split(';').next() {
        Some(value) => value,
        None => return Err("cookie header should have a name-value pair".into()),
    };

    validate_csrf_tokens(
        harbor.config(),
        Some(token.expose_secret()),
        Some(token.expose_secret()),
    )?;
    validate_csrf_from_headers(
        harbor.config(),
        Some(cookie_header),
        Some(token.expose_secret()),
    )?;

    let mismatch =
        validate_csrf_tokens(harbor.config(), Some(token.expose_secret()), Some("wrong"));
    let mismatch = match mismatch {
        Ok(()) => return Err("csrf mismatch should fail".into()),
        Err(error) => error,
    };
    assert_eq!(mismatch.code(), AuthErrorCode::Csrf);

    let missing = validate_csrf_tokens(harbor.config(), None, Some(token.expose_secret()));
    let missing = match missing {
        Ok(()) => return Err("missing csrf cookie should fail".into()),
        Err(error) => error,
    };
    assert_eq!(missing.code(), AuthErrorCode::Csrf);
    Ok(())
}
