use harbor_core::{
    Argon2Params, Argon2PasswordHasher, AuthError, AuthErrorCode, ChallengeDelivery, ChallengeId,
    HmacSecretKey, PasswordPolicy, PasswordSignInInput, PasswordSignUpInput, RedirectPath,
    RequestPasswordResetInput, ResetPasswordInput, RetryBudget, SecretToken, SystemClock,
    SystemSecretGenerator, UnixTimestampMicros,
};
use harbor_email::RecordingMailer;
use harbor_sqlx::{SqliteAuthStore, SqliteStoreOptions};

use super::*;
use crate::{
    AuthLinkQuery, AuthRateLimits, CookieDefaults, Harbor, build_csrf_cookie,
    handle_confirm_email_link, handle_email_link_signin, handle_reset_password_link,
    issue_csrf_token,
};

type TestService = AuthService<SqliteAuthStore, SystemClock, SystemSecretGenerator>;

async fn test_parts() -> Result<
    (
        TestService,
        RecordingMailer,
        HarborConfig,
        CsrfRequest,
        String,
    ),
    Box<dyn std::error::Error>,
> {
    test_parts_with_rate_limits(None).await
}

async fn test_parts_with_rate_limits(
    rate_limits: Option<AuthRateLimits>,
) -> Result<
    (
        TestService,
        RecordingMailer,
        HarborConfig,
        CsrfRequest,
        String,
    ),
    Box<dyn std::error::Error>,
> {
    let store =
        SqliteAuthStore::connect_and_migrate("sqlite::memory:", SqliteStoreOptions::in_memory())
            .await?;
    let service = AuthService::new(
        store,
        SystemClock,
        SystemSecretGenerator,
        HmacSecretKey::try_new(vec![7; 32])?,
        Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ),
    );
    let mailer = RecordingMailer::new();
    let builder = Harbor::builder()
        .with_store(())
        .with_mailer(mailer.clone())
        .with_public_base_url("http://localhost:3000")?
        .with_cookie_defaults(CookieDefaults::development())?
        .with_hmac_secret_key(vec![7; 32])?;
    let builder = match rate_limits {
        Some(rate_limits) => builder.with_rate_limits(rate_limits)?,
        None => builder,
    };
    let harbor = builder
        .with_default_email_renderer("TestAuth", "test.local")?
        .finish()?;
    let csrf = issue_csrf_token(harbor.config(), &SystemSecretGenerator)?;
    let csrf_cookie = build_csrf_cookie(harbor.config().cookie_defaults(), &csrf, None)?;
    let csrf_pair = first_cookie_pair(&csrf_cookie)?.to_owned();
    let request = CsrfRequest {
        cookie_header: Some(csrf_pair.clone()),
        csrf_header: Some(csrf.expose_secret().to_owned()),
        rate_limit_key: None,
    };
    Ok((service, mailer, harbor.config().clone(), request, csrf_pair))
}

#[tokio::test]
async fn password_workflow_confirms_signs_in_loads_and_signs_out()
-> Result<(), Box<dyn std::error::Error>> {
    let (service, mailer, config, csrf, csrf_pair) = test_parts().await?;
    let email = "password-flow@example.com".to_owned();
    let password = "correct horse battery staple".to_owned();

    let signup = signup_with_password(
        &service,
        &mailer,
        &config,
        csrf.clone(),
        PasswordSignUpInput {
            email: email.clone(),
            password: password.clone(),
        },
    )
    .await?;
    assert_eq!(signup.message, "Check your email to continue.");
    handle_confirm_email_link(&service, latest_link_query(&mailer)?).await?;

    let signin = signin_with_password(
        &service,
        &config,
        csrf.clone(),
        PasswordSignInInput {
            email,
            password,
            redirect_path: Some(RedirectPath::try_new("/account")?),
        },
    )
    .await?;
    let session_pair = first_cookie_pair(&signin.set_cookie)?;
    assert!(signin.set_cookie.contains("HttpOnly"));
    assert!(
        current_session(&service, &config, Some(session_pair))
            .await?
            .is_some()
    );

    let delete_cookie = sign_out(
        &service,
        &config,
        CsrfRequest {
            cookie_header: Some(format!("{csrf_pair}; {session_pair}")),
            csrf_header: csrf.csrf_header,
            rate_limit_key: None,
        },
    )
    .await?;
    assert!(delete_cookie.contains("Max-Age=0"));
    assert!(
        current_session(&service, &config, Some(session_pair))
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn email_link_and_code_workflows_create_sessions() -> Result<(), Box<dyn std::error::Error>> {
    let (service, mailer, config, csrf, _csrf_pair) = test_parts().await?;

    request_email_signin(
        &service,
        &mailer,
        &config,
        csrf.clone(),
        "link-flow@example.com".to_owned(),
        Some(RedirectPath::try_new("/account")?),
    )
    .await?;
    let link = handle_email_link_signin(&service, &config, latest_link_query(&mailer)?).await?;
    let link_cookie = link.set_cookie.ok_or("email link should set cookie")?;
    assert!(link_cookie.contains("harbor_session="));

    let code = request_email_code_signin(
        &service,
        &mailer,
        &config,
        csrf.clone(),
        "code-flow@example.com".to_owned(),
        Some(RedirectPath::try_new("/account")?),
    )
    .await?;
    let code_signin = verify_email_code(
        &service,
        &config,
        csrf,
        harbor_core::EmailChallengeSignInInput {
            challenge_id: code.challenge_id,
            secret: SecretToken::try_new(latest_otp_code(&mailer)?)?,
            redirect_path: Some(RedirectPath::try_new("/account")?),
        },
    )
    .await?;
    assert!(code_signin.set_cookie.contains("harbor_session="));
    Ok(())
}

#[tokio::test]
async fn password_reset_revokes_existing_session_and_accepts_new_password()
-> Result<(), Box<dyn std::error::Error>> {
    let (service, mailer, config, csrf, _csrf_pair) = test_parts().await?;
    let email = "reset-flow@example.com".to_owned();
    let old_password = "correct horse battery staple".to_owned();
    let new_password = "new correct horse battery staple".to_owned();

    signup_with_password(
        &service,
        &mailer,
        &config,
        csrf.clone(),
        PasswordSignUpInput {
            email: email.clone(),
            password: old_password.clone(),
        },
    )
    .await?;
    handle_confirm_email_link(&service, latest_link_query(&mailer)?).await?;
    let signin = signin_with_password(
        &service,
        &config,
        csrf.clone(),
        PasswordSignInInput {
            email: email.clone(),
            password: old_password,
            redirect_path: None,
        },
    )
    .await?;
    let old_session = first_cookie_pair(&signin.set_cookie)?.to_owned();

    request_password_reset(
        &service,
        &mailer,
        &config,
        csrf.clone(),
        RequestPasswordResetInput {
            email: email.clone(),
            delivery: ChallengeDelivery::MagicLink,
            redirect_path: Some(RedirectPath::try_new("/signin")?),
        },
    )
    .await?;
    let reset = latest_link_query(&mailer)?;
    reset_password(
        &service,
        &config,
        csrf.clone(),
        ResetPasswordInput {
            challenge_id: ChallengeId::try_new(reset.challenge)?,
            secret: SecretToken::try_new(reset.token)?,
            new_password: new_password.clone(),
        },
    )
    .await?;
    assert!(
        current_session(&service, &config, Some(&old_session))
            .await?
            .is_none()
    );

    let signin = signin_with_password(
        &service,
        &config,
        csrf,
        PasswordSignInInput {
            email,
            password: new_password,
            redirect_path: None,
        },
    )
    .await?;
    assert!(signin.set_cookie.contains("harbor_session="));
    Ok(())
}

#[tokio::test]
async fn passive_session_helpers_accept_absent_cookies() -> Result<(), Box<dyn std::error::Error>> {
    let (service, _mailer, config, csrf, _csrf_pair) = test_parts().await?;

    assert!(current_session(&service, &config, None).await?.is_none());
    assert!(
        current_session(&service, &config, Some("other=value"))
            .await?
            .is_none()
    );

    let deleted = sign_out(
        &service,
        &config,
        CsrfRequest {
            cookie_header: csrf.cookie_header,
            csrf_header: csrf.csrf_header,
            rate_limit_key: None,
        },
    )
    .await?;
    assert!(deleted.contains("Max-Age=0"));
    Ok(())
}

#[tokio::test]
async fn state_changing_workflows_apply_email_rate_limits() -> Result<(), Box<dyn std::error::Error>>
{
    let limits = AuthRateLimits {
        signup: RetryBudget::try_new(1)?,
        password_signin: RetryBudget::try_new(1)?,
        email_challenge: RetryBudget::try_new(1)?,
        password_reset: RetryBudget::try_new(1)?,
        window: UnixTimestampMicros::try_new(60_000_000)?,
    };
    let (service, mailer, config, csrf, _csrf_pair) =
        test_parts_with_rate_limits(Some(limits)).await?;
    let email = "limited@example.com".to_owned();
    let password = "correct horse battery staple".to_owned();

    signup_with_password(
        &service,
        &mailer,
        &config,
        csrf.clone(),
        PasswordSignUpInput {
            email: email.clone(),
            password: password.clone(),
        },
    )
    .await?;
    assert_rate_limited(
        signup_with_password(
            &service,
            &mailer,
            &config,
            csrf.clone(),
            PasswordSignUpInput {
                email: email.clone(),
                password: password.clone(),
            },
        )
        .await,
    )?;
    handle_confirm_email_link(&service, latest_link_query(&mailer)?).await?;

    signin_with_password(
        &service,
        &config,
        csrf.clone(),
        PasswordSignInInput {
            email: email.clone(),
            password: password.clone(),
            redirect_path: None,
        },
    )
    .await?;
    assert_rate_limited(
        signin_with_password(
            &service,
            &config,
            csrf.clone(),
            PasswordSignInInput {
                email: email.clone(),
                password,
                redirect_path: None,
            },
        )
        .await,
    )?;

    request_email_signin(
        &service,
        &mailer,
        &config,
        csrf.clone(),
        "limited-link@example.com".to_owned(),
        None,
    )
    .await?;
    assert_rate_limited(
        request_email_signin(
            &service,
            &mailer,
            &config,
            csrf.clone(),
            "limited-link@example.com".to_owned(),
            None,
        )
        .await,
    )?;

    request_password_reset(
        &service,
        &mailer,
        &config,
        csrf.clone(),
        RequestPasswordResetInput {
            email: email.clone(),
            delivery: ChallengeDelivery::MagicLink,
            redirect_path: None,
        },
    )
    .await?;
    assert_rate_limited(
        request_password_reset(
            &service,
            &mailer,
            &config,
            csrf,
            RequestPasswordResetInput {
                email,
                delivery: ChallengeDelivery::MagicLink,
                redirect_path: None,
            },
        )
        .await,
    )?;
    Ok(())
}

#[tokio::test]
async fn workflows_apply_optional_request_fingerprint_rate_limits()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = AuthRateLimits {
        signup: RetryBudget::try_new(1)?,
        password_signin: RetryBudget::try_new(10)?,
        email_challenge: RetryBudget::try_new(10)?,
        password_reset: RetryBudget::try_new(10)?,
        window: UnixTimestampMicros::try_new(60_000_000)?,
    };
    let (service, mailer, config, mut csrf, _csrf_pair) =
        test_parts_with_rate_limits(Some(limits)).await?;
    csrf.rate_limit_key = Some("client=203.0.113.7;ua=test".to_owned());

    signup_with_password(
        &service,
        &mailer,
        &config,
        csrf.clone(),
        PasswordSignUpInput {
            email: "fingerprint-one@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
        },
    )
    .await?;
    assert_rate_limited(
        signup_with_password(
            &service,
            &mailer,
            &config,
            csrf,
            PasswordSignUpInput {
                email: "fingerprint-two@example.com".to_owned(),
                password: "correct horse battery staple".to_owned(),
            },
        )
        .await,
    )?;
    Ok(())
}

#[test]
fn reset_link_handler_validates_and_preserves_safe_redirects()
-> Result<(), Box<dyn std::error::Error>> {
    let response = handle_reset_password_link(AuthLinkQuery {
        challenge: "challenge00000001".to_owned(),
        token: "reset-token".to_owned(),
        redirect: Some(RedirectPath::try_new("/signin?after=reset")?),
    })?;

    assert_eq!(
        response.location,
        "/reset-password?challenge=challenge00000001&token=reset-token&redirect=%2Fsignin%3Fafter%3Dreset"
    );
    assert_eq!(response.set_cookie, None);
    assert!(
        handle_reset_password_link(AuthLinkQuery {
            challenge: "bad id".to_owned(),
            token: "reset-token".to_owned(),
            redirect: None,
        })
        .is_err()
    );
    assert!(
        handle_reset_password_link(AuthLinkQuery {
            challenge: "challenge00000001".to_owned(),
            token: String::new(),
            redirect: None,
        })
        .is_err()
    );
    Ok(())
}

fn first_cookie_pair(set_cookie: &str) -> Result<&str, Box<dyn std::error::Error>> {
    match set_cookie.split(';').next() {
        Some(value) => Ok(value),
        None => Err("set-cookie should include a pair".into()),
    }
}

fn assert_rate_limited<T>(result: Result<T, AuthError>) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(error) if error.code() == AuthErrorCode::RateLimited => Ok(()),
        Err(error) => Err(format!("expected rate_limited, got {}", error.code().as_str()).into()),
        Ok(_) => Err("expected rate limit error".into()),
    }
}

fn latest_link_query(
    mailer: &RecordingMailer,
) -> Result<AuthLinkQuery, Box<dyn std::error::Error>> {
    let recorded = mailer.recorded()?;
    let email = match recorded.last() {
        Some(email) => email,
        None => return Err("recording mailer should contain email".into()),
    };
    let link = match email
        .text_body()
        .lines()
        .find(|line| line.starts_with("http://") || line.starts_with("https://"))
    {
        Some(value) => value,
        None => return Err("auth email should contain link".into()),
    };
    let query = match link.split_once('?') {
        Some((_path, query)) => query,
        None => return Err("auth link should contain query".into()),
    };
    let mut challenge = None;
    let mut token = None;
    for part in query.split('&') {
        if let Some((name, value)) = part.split_once('=') {
            match name {
                "challenge" => challenge = Some(value.to_owned()),
                "token" => token = Some(value.to_owned()),
                _ => {}
            }
        }
    }
    Ok(AuthLinkQuery {
        challenge: challenge.ok_or("auth link should include challenge")?,
        token: token.ok_or("auth link should include token")?,
        redirect: None,
    })
}

fn latest_otp_code(mailer: &RecordingMailer) -> Result<String, Box<dyn std::error::Error>> {
    let recorded = mailer.recorded()?;
    let email = match recorded.last() {
        Some(email) => email,
        None => return Err("recording mailer should contain email".into()),
    };
    let mut lines = email.text_body().lines();
    while let Some(line) = lines.next() {
        if line == "Use this code:" {
            return lines
                .next()
                .map(str::to_owned)
                .ok_or_else(|| "auth email should contain OTP code".into());
        }
    }
    Err("auth email should contain OTP code".into())
}
