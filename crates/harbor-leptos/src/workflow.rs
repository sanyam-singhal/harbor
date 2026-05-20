//! Leptos-facing auth workflow wrappers.

use harbor_core::{
    AuthError, AuthErrorCode, AuthRateLimitScope, AuthService, AuthStore, ChallengeDelivery,
    ChallengeId, ChallengePolicy, ChallengePurpose, Clock, EmailAddress, PasswordBlocklist,
    RateLimitInput, RedirectPath, RetryBudget, SecretGenerator, SecretToken,
};
use harbor_email::{
    AuthMailer, ChallengeEmailInput, EmailRecipient, SecretUrl,
    render_challenge_email_with_renderer,
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
    enforce_email_rate_limit(
        service,
        config,
        &csrf,
        AuthRateLimitScope::Signup,
        &input.email,
        config.rate_limits().signup,
    )
    .await?;
    let signup = service.sign_up_with_password(input).await?;
    let harbor_core::PasswordSignUpOutput { user, email } = signup;
    let challenge = service
        .create_email_challenge_with_policy(
            harbor_core::EmailChallengeInput {
                purpose: ChallengePurpose::SignupConfirmation,
                delivery: ChallengeDelivery::MagicLink,
                email: email.email_original,
                user_id: Some(user.id),
                redirect_path: None,
            },
            challenge_policy(config, ChallengePurpose::SignupConfirmation)?,
        )
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
    enforce_email_rate_limit(
        service,
        config,
        &csrf,
        AuthRateLimitScope::PasswordSignin,
        &input.email,
        config.rate_limits().password_signin,
    )
    .await?;
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
    enforce_email_rate_limit(
        service,
        config,
        &csrf,
        AuthRateLimitScope::EmailChallenge,
        &email,
        config.rate_limits().email_challenge,
    )
    .await?;
    let challenge = service
        .create_email_challenge_with_policy(
            harbor_core::EmailChallengeInput {
                purpose: ChallengePurpose::EmailSignIn,
                delivery: ChallengeDelivery::MagicLink,
                email,
                user_id: None,
                redirect_path,
            },
            challenge_policy(config, ChallengePurpose::EmailSignIn)?,
        )
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
    enforce_email_rate_limit(
        service,
        config,
        &csrf,
        AuthRateLimitScope::EmailChallenge,
        &email,
        config.rate_limits().email_challenge,
    )
    .await?;
    let challenge = service
        .create_email_challenge_with_policy(
            harbor_core::EmailChallengeInput {
                purpose: ChallengePurpose::EmailSignIn,
                delivery: ChallengeDelivery::OtpCode,
                email,
                user_id: None,
                redirect_path,
            },
            challenge_policy(config, ChallengePurpose::EmailSignIn)?,
        )
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
    enforce_email_rate_limit(
        service,
        config,
        &csrf,
        AuthRateLimitScope::PasswordReset,
        &input.email,
        config.rate_limits().password_reset,
    )
    .await?;
    let reset = service
        .request_password_reset_with_policy(
            input,
            challenge_policy(config, ChallengePurpose::PasswordReset)?,
        )
        .await?;
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

fn challenge_policy(
    config: &HarborConfig,
    purpose: ChallengePurpose,
) -> Result<ChallengePolicy, AuthError> {
    let lifetime = match purpose {
        ChallengePurpose::SignupConfirmation => config.challenge_lifetimes().signup_confirmation,
        ChallengePurpose::EmailSignIn => config.challenge_lifetimes().email_signin,
        ChallengePurpose::PasswordReset => config.challenge_lifetimes().password_reset,
        _ => {
            return Err(AuthError::with_detail(
                AuthErrorCode::Internal,
                "challenge_purpose",
            ));
        }
    };
    let default = ChallengePolicy::for_purpose(purpose)?;
    ChallengePolicy::new(lifetime, default.max_attempts(), default.resend_cooldown())
}

async fn enforce_email_rate_limit<S, C, G, B>(
    service: &AuthService<S, C, G, B>,
    config: &HarborConfig,
    csrf: &CsrfRequest,
    scope: AuthRateLimitScope,
    email: &str,
    max_count: RetryBudget,
) -> Result<(), AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    let email = EmailAddress::parse(email.to_owned())
        .map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))?;
    enforce_rate_limit_key(
        service,
        config,
        scope,
        format!("email:{}", email.canonical().as_str()),
        max_count,
    )
    .await?;
    if let Some(rate_limit_key) = csrf.rate_limit_key.as_deref() {
        enforce_rate_limit_key(
            service,
            config,
            scope,
            format!("fingerprint:{rate_limit_key}"),
            max_count,
        )
        .await?;
    }
    Ok(())
}

async fn enforce_rate_limit_key<S, C, G, B>(
    service: &AuthService<S, C, G, B>,
    config: &HarborConfig,
    scope: AuthRateLimitScope,
    key: String,
    max_count: RetryBudget,
) -> Result<(), AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    service
        .enforce_rate_limit(RateLimitInput {
            scope,
            key,
            max_count,
            window: config.rate_limits().window,
        })
        .await
}

async fn send_challenge_email<M: AuthMailer>(
    mailer: &M,
    config: &HarborConfig,
    challenge: harbor_core::EmailChallengeOutput,
    route: &str,
) -> Result<(), AuthError> {
    let harbor_core::EmailChallengeOutput { challenge, secret } = challenge;
    let action_url = match challenge.delivery {
        ChallengeDelivery::MagicLink => {
            Some(challenge_action_url(config, route, &challenge, &secret)?)
        }
        ChallengeDelivery::OtpCode => None,
        _ => {
            return Err(AuthError::with_detail(
                AuthErrorCode::Internal,
                "unknown_delivery",
            ));
        }
    };
    let otp_code = match challenge.delivery {
        ChallengeDelivery::OtpCode => Some(secret),
        ChallengeDelivery::MagicLink => None,
        _ => {
            return Err(AuthError::with_detail(
                AuthErrorCode::Internal,
                "unknown_delivery",
            ));
        }
    };
    let recipient = EmailRecipient::parse(challenge.email_canonical.as_str())?;
    let email = render_challenge_email_with_renderer(
        ChallengeEmailInput {
            purpose: challenge.purpose,
            delivery: challenge.delivery,
            to: recipient,
            challenge_id: challenge.id,
            action_url,
            otp_code,
        },
        config.email_renderer(),
    )?;
    mailer
        .send_auth_email(email)
        .await
        .map_err(AuthError::from)?;
    Ok(())
}

fn challenge_action_url(
    config: &HarborConfig,
    route: &str,
    challenge: &harbor_core::ChallengeRecord,
    secret: &SecretToken,
) -> Result<SecretUrl, AuthError> {
    let mut url = format!(
        "{}{}?challenge={}&token={}",
        config.public_base_url().as_str(),
        route,
        challenge.id.as_str(),
        secret.expose_secret()
    );
    if let Some(redirect_path) = challenge.redirect_path.as_ref() {
        url.push_str("&redirect=");
        url.push_str(percent_encode_query(redirect_path.as_str()).as_str());
    }
    SecretUrl::try_new(url).map_err(AuthError::from)
}
