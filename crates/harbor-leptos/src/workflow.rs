//! Leptos-facing auth workflow wrappers.

use harbor_core::{
    AuthError, AuthErrorCode, AuthService, AuthStore, ChallengeDelivery, ChallengePurpose, Clock,
    PasswordBlocklist, RedirectPath, SecretGenerator, SecretToken,
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
