//! Leptos-facing auth workflow wrappers.

use harbor_core::{
    AuthError, AuthErrorCode, AuthService, AuthStore, ChallengeDelivery, ChallengeId,
    ChallengePurpose, Clock, PasswordBlocklist, RedirectPath, SecretGenerator, SecretToken,
};
use harbor_email::{
    AuthMailer, ChallengeEmailInput, EmailRecipient, SecretUrl, render_challenge_email,
};

use crate::{
    CsrfRequest, HarborConfig, build_delete_session_cookie, build_session_cookie,
    parse_cookie_value, percent_encode_query, validate_csrf_from_headers,
};

/// Generic auth action response for enumeration-resistant flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthActionResponse {
    /// Stable user-facing message.
    pub message: String,
}

/// Response that sets a session cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionActionResponse {
    /// Created session cookie header value.
    pub set_cookie: String,
    /// Optional redirect path.
    pub redirect_path: Option<RedirectPath>,
}

/// Response returned after requesting an email OTP challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailCodeActionResponse {
    /// Stable user-facing message.
    pub message: String,
    /// Non-secret challenge id to submit with the OTP code.
    pub challenge_id: ChallengeId,
}

/// Signs up with password and sends a signup confirmation email.
///
/// # Errors
///
/// Returns [`AuthError`] when CSRF validation, signup, challenge creation, mail
/// rendering, or delivery fails.
pub async fn signup_with_password<S, C, G, B, M>(
    service: &AuthService<S, C, G, B>,
    mailer: &M,
    config: &HarborConfig,
    csrf: CsrfRequest,
    input: harbor_core::PasswordSignUpInput,
) -> Result<AuthActionResponse, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
    M: AuthMailer,
{
    validate_csrf_request(config, &csrf)?;
    let signup = service.sign_up_with_password(input).await?;
    let challenge = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::SignupConfirmation,
            delivery: ChallengeDelivery::MagicLink,
            email: signup.email.email_original.clone(),
            user_id: Some(signup.user.id),
            redirect_path: None,
        })
        .await?;
    send_challenge_email(mailer, config, challenge, "/auth/confirm-email").await?;
    Ok(AuthActionResponse {
        message: "Check your email to continue.".to_owned(),
    })
}

/// Signs in with password and returns a session cookie.
///
/// # Errors
///
/// Returns [`AuthError`] when CSRF validation or signin fails.
pub async fn signin_with_password<S, C, G, B>(
    service: &AuthService<S, C, G, B>,
    config: &HarborConfig,
    csrf: CsrfRequest,
    input: harbor_core::PasswordSignInInput,
) -> Result<SessionActionResponse, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    validate_csrf_request(config, &csrf)?;
    let signin = service.sign_in_with_password(input).await?;
    let set_cookie = build_session_cookie(config.cookie_defaults(), &signin.session_token, None)
        .map_err(AuthError::from)?;
    Ok(SessionActionResponse {
        set_cookie,
        redirect_path: signin.redirect_path,
    })
}

/// Requests an email signin challenge.
///
/// # Errors
///
/// Returns [`AuthError`] when CSRF validation, challenge creation, rendering,
/// or delivery fails.
pub async fn request_email_signin<S, C, G, B, M>(
    service: &AuthService<S, C, G, B>,
    mailer: &M,
    config: &HarborConfig,
    csrf: CsrfRequest,
    email: String,
    redirect_path: Option<RedirectPath>,
) -> Result<AuthActionResponse, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
    M: AuthMailer,
{
    validate_csrf_request(config, &csrf)?;
    let challenge = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::MagicLink,
            email,
            user_id: None,
            redirect_path,
        })
        .await?;
    send_challenge_email(mailer, config, challenge, "/auth/email-link").await?;
    Ok(AuthActionResponse {
        message: "Check your email to continue.".to_owned(),
    })
}

/// Requests an email OTP signin challenge.
///
/// # Errors
///
/// Returns [`AuthError`] when CSRF validation, challenge creation, rendering,
/// or delivery fails.
pub async fn request_email_code_signin<S, C, G, B, M>(
    service: &AuthService<S, C, G, B>,
    mailer: &M,
    config: &HarborConfig,
    csrf: CsrfRequest,
    email: String,
    redirect_path: Option<RedirectPath>,
) -> Result<EmailCodeActionResponse, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
    M: AuthMailer,
{
    validate_csrf_request(config, &csrf)?;
    let challenge = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::OtpCode,
            email,
            user_id: None,
            redirect_path,
        })
        .await?;
    let challenge_id = challenge.challenge.id.clone();
    send_challenge_email(mailer, config, challenge, "/auth/email-code").await?;
    Ok(EmailCodeActionResponse {
        message: "Check your email to continue.".to_owned(),
        challenge_id,
    })
}

/// Verifies an email signin challenge and returns a session cookie.
///
/// # Errors
///
/// Returns [`AuthError`] when CSRF validation or challenge signin fails.
pub async fn verify_email_code<S, C, G, B>(
    service: &AuthService<S, C, G, B>,
    config: &HarborConfig,
    csrf: CsrfRequest,
    input: harbor_core::EmailChallengeSignInInput,
) -> Result<SessionActionResponse, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    validate_csrf_request(config, &csrf)?;
    let signin = service.sign_in_with_email_challenge(input).await?;
    let set_cookie = build_session_cookie(config.cookie_defaults(), &signin.session_token, None)
        .map_err(AuthError::from)?;
    Ok(SessionActionResponse {
        set_cookie,
        redirect_path: signin.redirect_path,
    })
}

/// Requests a password reset email.
///
/// # Errors
///
/// Returns [`AuthError`] when CSRF validation, reset challenge creation, mail
/// rendering, or delivery fails.
pub async fn request_password_reset<S, C, G, B, M>(
    service: &AuthService<S, C, G, B>,
    mailer: &M,
    config: &HarborConfig,
    csrf: CsrfRequest,
    input: harbor_core::RequestPasswordResetInput,
) -> Result<AuthActionResponse, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
    M: AuthMailer,
{
    validate_csrf_request(config, &csrf)?;
    let reset = service.request_password_reset(input).await?;
    if let Some(challenge) = reset.challenge {
        send_challenge_email(mailer, config, challenge, "/auth/reset-password").await?;
    }
    Ok(AuthActionResponse {
        message: "If the address is eligible, a reset email has been sent.".to_owned(),
    })
}

/// Resets a password.
///
/// # Errors
///
/// Returns [`AuthError`] when CSRF validation or password reset fails.
pub async fn reset_password<S, C, G, B>(
    service: &AuthService<S, C, G, B>,
    config: &HarborConfig,
    csrf: CsrfRequest,
    input: harbor_core::ResetPasswordInput,
) -> Result<AuthActionResponse, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    validate_csrf_request(config, &csrf)?;
    service.reset_password(input).await?;
    Ok(AuthActionResponse {
        message: "Your password has been reset.".to_owned(),
    })
}

/// Signs out from the current session cookie.
///
/// # Errors
///
/// Returns [`AuthError`] when CSRF validation or signout fails.
pub async fn sign_out<S, C, G, B>(
    service: &AuthService<S, C, G, B>,
    config: &HarborConfig,
    csrf: CsrfRequest,
) -> Result<String, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    validate_csrf_request(config, &csrf)?;
    if let Some(cookie_header) = csrf.cookie_header.as_deref()
        && let Some(session_token) = parse_cookie_value(
            cookie_header,
            config.cookie_defaults().session_cookie_name(),
        )
    {
        let token = SecretToken::try_new(session_token)
            .map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))?;
        service.sign_out(&token).await?;
    }
    Ok(build_delete_session_cookie(config.cookie_defaults()))
}

/// Loads the current session from the request cookie header.
///
/// # Errors
///
/// Returns [`AuthError`] when session token hashing or storage fails.
pub async fn current_session<S, C, G, B>(
    service: &AuthService<S, C, G, B>,
    config: &HarborConfig,
    cookie_header: Option<&str>,
) -> Result<Option<harbor_core::CurrentSession>, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    let Some(cookie_header) = cookie_header else {
        return Ok(None);
    };
    let Some(session_token) = parse_cookie_value(
        cookie_header,
        config.cookie_defaults().session_cookie_name(),
    ) else {
        return Ok(None);
    };
    let token = SecretToken::try_new(session_token)
        .map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))?;
    service.current_session(&token).await
}

fn validate_csrf_request(config: &HarborConfig, csrf: &CsrfRequest) -> Result<(), AuthError> {
    validate_csrf_from_headers(
        config,
        csrf.cookie_header.as_deref(),
        csrf.csrf_header.as_deref(),
    )
}

async fn send_challenge_email<M: AuthMailer>(
    mailer: &M,
    config: &HarborConfig,
    challenge: harbor_core::EmailChallengeOutput,
    route: &str,
) -> Result<(), AuthError> {
    let action_url = match challenge.challenge.delivery {
        ChallengeDelivery::MagicLink | ChallengeDelivery::Both => {
            Some(challenge_action_url(config, route, &challenge)?)
        }
        ChallengeDelivery::OtpCode => None,
        _ => {
            return Err(AuthError::with_detail(
                AuthErrorCode::Internal,
                "unknown_delivery",
            ));
        }
    };
    let otp_code = match challenge.challenge.delivery {
        ChallengeDelivery::OtpCode | ChallengeDelivery::Both => Some(challenge.secret.clone()),
        ChallengeDelivery::MagicLink => None,
        _ => {
            return Err(AuthError::with_detail(
                AuthErrorCode::Internal,
                "unknown_delivery",
            ));
        }
    };
    let recipient = EmailRecipient::parse(challenge.challenge.email_canonical.as_str())?;
    let email = render_challenge_email(ChallengeEmailInput {
        purpose: challenge.challenge.purpose,
        delivery: challenge.challenge.delivery,
        to: recipient,
        challenge_id: challenge.challenge.id,
        action_url,
        otp_code,
    })?;
    mailer
        .send_auth_email(email)
        .await
        .map_err(AuthError::from)?;
    Ok(())
}

fn challenge_action_url(
    config: &HarborConfig,
    route: &str,
    challenge: &harbor_core::EmailChallengeOutput,
) -> Result<SecretUrl, AuthError> {
    let mut url = format!(
        "{}{}?challenge={}&token={}",
        config.public_base_url().as_str(),
        route,
        challenge.challenge.id.as_str(),
        challenge.secret.expose_secret()
    );
    if let Some(redirect_path) = challenge.challenge.redirect_path.as_ref() {
        url.push_str("&redirect=");
        url.push_str(percent_encode_query(redirect_path.as_str()).as_str());
    }
    SecretUrl::try_new(url).map_err(AuthError::from)
}

#[cfg(test)]
mod tests {
    use harbor_core::{
        Argon2Params, Argon2PasswordHasher, ChallengeDelivery, ChallengeId, HmacSecretKey,
        PasswordPolicy, PasswordSignInInput, PasswordSignUpInput, RedirectPath,
        RequestPasswordResetInput, ResetPasswordInput, SecretToken, SystemClock,
        SystemSecretGenerator,
    };
    use harbor_email::RecordingMailer;
    use harbor_sqlx::{SqliteAuthStore, SqliteStoreOptions};

    use super::*;
    use crate::{
        AuthLinkQuery, CookieDefaults, Harbor, build_csrf_cookie, handle_confirm_email_link,
        handle_email_link_signin, issue_csrf_token,
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
        let store = SqliteAuthStore::connect_and_migrate(
            "sqlite::memory:",
            SqliteStoreOptions::in_memory(),
        )
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
        let harbor = Harbor::builder()
            .with_store(())
            .with_mailer(mailer.clone())
            .with_public_base_url("http://localhost:3000")?
            .with_cookie_defaults(CookieDefaults::development())?
            .with_hmac_secret_key(vec![7; 32])?
            .finish()?;
        let csrf = issue_csrf_token(&SystemSecretGenerator)?;
        let csrf_cookie = build_csrf_cookie(harbor.config().cookie_defaults(), &csrf, None)?;
        let csrf_pair = first_cookie_pair(&csrf_cookie)?.to_owned();
        let request = CsrfRequest {
            cookie_header: Some(csrf_pair.clone()),
            csrf_header: Some(csrf.expose_secret().to_owned()),
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
    async fn email_link_and_code_workflows_create_sessions()
    -> Result<(), Box<dyn std::error::Error>> {
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

    fn first_cookie_pair(set_cookie: &str) -> Result<&str, Box<dyn std::error::Error>> {
        match set_cookie.split(';').next() {
            Some(value) => Ok(value),
            None => Err("set-cookie should include a pair".into()),
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
}
