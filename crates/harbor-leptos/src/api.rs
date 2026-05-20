//! High-level auth verbs for Harbor Leptos applications.

use harbor_core::{
    AuthError, AuthErrorCode, AuthStore, ChallengeDelivery, ChallengeId, EmailChallengeSignInInput,
    EmailChallengeSignInPolicy, PasswordBlocklist, PasswordSignInInput, PasswordSignUpInput,
    PasswordlessSignup, RedirectPath, RequestPasswordResetInput, ResetPasswordInput, SecretToken,
};
use harbor_email::AuthMailer;

use crate::{
    AuthActionResponse, AuthFlowConfig, AuthRouteConfig, AuthRuntime, CsrfRequest,
    EmailCodeActionResponse, Harbor, SessionActionResponse, request_email_code_signin,
    request_email_signin, request_password_reset, reset_password, sign_out, signin_with_password,
    signup_with_password,
};

/// High-level auth API for standard Harbor v0.1 flows.
#[derive(Clone, Copy)]
pub struct AuthApi<'a, S, M, C, G, B> {
    harbor: &'a Harbor<S, M>,
    service: &'a harbor_core::AuthService<S, C, G, B>,
    flow_config: &'a AuthFlowConfig,
    route_config: &'a AuthRouteConfig,
}

impl<'a, S, M, C, G, B> AuthApi<'a, S, M, C, G, B> {
    /// Creates an auth API view over a runtime.
    #[must_use]
    pub const fn new(runtime: &'a AuthRuntime<S, M, C, G, B>) -> Self {
        Self::new_runtime_parts(
            runtime.harbor(),
            runtime.service(),
            runtime.flow_config(),
            runtime.route_config(),
        )
    }

    /// Creates an auth API view over initialized runtime parts.
    #[must_use]
    pub const fn new_runtime_parts(
        harbor: &'a Harbor<S, M>,
        service: &'a harbor_core::AuthService<S, C, G, B>,
        flow_config: &'a AuthFlowConfig,
        route_config: &'a AuthRouteConfig,
    ) -> Self {
        Self {
            harbor,
            service,
            flow_config,
            route_config,
        }
    }

    /// Returns route configuration used by this API.
    #[must_use]
    pub const fn route_config(&self) -> &AuthRouteConfig {
        self.route_config
    }
}

impl<S, M, C, G, B> AuthApi<'_, S, M, C, G, B>
where
    S: AuthStore,
    M: AuthMailer,
    C: harbor_core::Clock,
    G: harbor_core::SecretGenerator,
    B: PasswordBlocklist,
{
    /// Signs up a password-backed email account and sends confirmation email.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the flow is disabled or signup fails.
    pub async fn sign_up_email(
        self,
        request: SignUpEmailRequest,
    ) -> Result<AuthActionResponse, AuthError> {
        if !self.flow_config.email_and_password().is_enabled() {
            return Err(AuthError::new(AuthErrorCode::Forbidden));
        }
        signup_with_password(
            self.service,
            self.harbor.mailer(),
            self.harbor.config(),
            request.csrf,
            PasswordSignUpInput {
                email: request.email,
                password: request.password,
            },
        )
        .await
    }

    /// Signs in a password-backed email account.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the flow is disabled or signin fails.
    pub async fn sign_in_email(
        self,
        request: SignInEmailRequest,
    ) -> Result<SessionActionResponse, AuthError> {
        if !self.flow_config.email_and_password().is_enabled() {
            return Err(AuthError::new(AuthErrorCode::Forbidden));
        }
        signin_with_password(
            self.service,
            self.harbor.config(),
            request.csrf,
            PasswordSignInInput {
                email: request.email,
                password: request.password,
                redirect_path: request.redirect_path,
            },
        )
        .await
    }

    /// Sends a magic link to an email address.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the flow is disabled or request handling
    /// fails.
    pub async fn sign_in_magic_link(
        self,
        request: SignInMagicLinkRequest,
    ) -> Result<AuthActionResponse, AuthError> {
        if !self.flow_config.magic_link().is_enabled() {
            return Err(AuthError::new(AuthErrorCode::Forbidden));
        }
        request_email_signin(
            self.service,
            self.harbor.mailer(),
            self.harbor.config(),
            request.csrf,
            request.email,
            request.redirect_path,
        )
        .await
    }

    /// Sends an email OTP to an email address.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the flow is disabled or request handling
    /// fails.
    pub async fn send_email_otp(
        self,
        request: SendEmailOtpRequest,
    ) -> Result<EmailCodeActionResponse, AuthError> {
        if !self.flow_config.email_otp().is_enabled() {
            return Err(AuthError::new(AuthErrorCode::Forbidden));
        }
        request_email_code_signin(
            self.service,
            self.harbor.mailer(),
            self.harbor.config(),
            request.csrf,
            request.email,
            request.redirect_path,
        )
        .await
    }

    /// Signs in with an email OTP code.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the flow is disabled or verification fails.
    pub async fn sign_in_email_otp(
        self,
        request: SignInEmailOtpRequest,
    ) -> Result<SessionActionResponse, AuthError> {
        if !self.flow_config.email_otp().is_enabled() {
            return Err(AuthError::new(AuthErrorCode::Forbidden));
        }
        verify_email_challenge_with_policy(
            self.harbor,
            self.service,
            request.csrf,
            request.challenge_id,
            request.code,
            request.redirect_path,
            self.flow_config.email_otp().passwordless_signup(),
        )
        .await
    }

    /// Requests a password reset email.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the flow is disabled or request handling
    /// fails.
    pub async fn request_password_reset(
        self,
        request: PasswordResetRequest,
    ) -> Result<AuthActionResponse, AuthError> {
        if !self.flow_config.password_reset().is_enabled() {
            return Err(AuthError::new(AuthErrorCode::Forbidden));
        }
        request_password_reset(
            self.service,
            self.harbor.mailer(),
            self.harbor.config(),
            request.csrf,
            RequestPasswordResetInput {
                email: request.email,
                delivery: ChallengeDelivery::MagicLink,
                redirect_path: request.redirect_path,
            },
        )
        .await
    }

    /// Resets a password from an email challenge.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the flow is disabled or reset fails.
    pub async fn reset_password(
        self,
        request: ResetPasswordRequest,
    ) -> Result<AuthActionResponse, AuthError> {
        if !self.flow_config.password_reset().is_enabled() {
            return Err(AuthError::new(AuthErrorCode::Forbidden));
        }
        reset_password(
            self.service,
            self.harbor.config(),
            request.csrf,
            ResetPasswordInput {
                challenge_id: request.challenge_id,
                secret: request.token,
                new_password: request.new_password,
            },
        )
        .await
    }

    /// Signs out the current browser session.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when CSRF validation or signout fails.
    pub async fn sign_out(self, request: SignOutRequest) -> Result<String, AuthError> {
        sign_out(self.service, self.harbor.config(), request.csrf).await
    }
}

/// Email/password signup request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignUpEmailRequest {
    /// CSRF request material.
    pub csrf: CsrfRequest,
    /// User email.
    pub email: String,
    /// User password.
    pub password: String,
}

/// Email/password signin request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInEmailRequest {
    /// CSRF request material.
    pub csrf: CsrfRequest,
    /// User email.
    pub email: String,
    /// User password.
    pub password: String,
    /// Optional post-signin redirect.
    pub redirect_path: Option<RedirectPath>,
}

/// Magic-link request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInMagicLinkRequest {
    /// CSRF request material.
    pub csrf: CsrfRequest,
    /// User email.
    pub email: String,
    /// Optional post-signin redirect.
    pub redirect_path: Option<RedirectPath>,
}

/// Email OTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendEmailOtpRequest {
    /// CSRF request material.
    pub csrf: CsrfRequest,
    /// User email.
    pub email: String,
    /// Optional post-signin redirect.
    pub redirect_path: Option<RedirectPath>,
}

/// Email OTP signin request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInEmailOtpRequest {
    /// CSRF request material.
    pub csrf: CsrfRequest,
    /// Challenge id sent by the OTP request.
    pub challenge_id: ChallengeId,
    /// OTP code from the email.
    pub code: SecretToken,
    /// Optional post-signin redirect.
    pub redirect_path: Option<RedirectPath>,
}

/// Password reset request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordResetRequest {
    /// CSRF request material.
    pub csrf: CsrfRequest,
    /// Email address requesting password reset.
    pub email: String,
    /// Optional post-reset redirect.
    pub redirect_path: Option<RedirectPath>,
}

/// Password reset completion request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetPasswordRequest {
    /// CSRF request material.
    pub csrf: CsrfRequest,
    /// Password reset challenge id.
    pub challenge_id: ChallengeId,
    /// Password reset token.
    pub token: SecretToken,
    /// Replacement password.
    pub new_password: String,
}

/// Sign-out request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignOutRequest {
    /// CSRF request material.
    pub csrf: CsrfRequest,
}

async fn verify_email_challenge_with_policy<S, M, C, G, B>(
    harbor: &Harbor<S, M>,
    service: &harbor_core::AuthService<S, C, G, B>,
    csrf: CsrfRequest,
    challenge_id: ChallengeId,
    secret: SecretToken,
    redirect_path: Option<RedirectPath>,
    passwordless_signup: PasswordlessSignup,
) -> Result<SessionActionResponse, AuthError>
where
    S: AuthStore,
    C: harbor_core::Clock,
    G: harbor_core::SecretGenerator,
    B: PasswordBlocklist,
{
    crate::validate_csrf_from_headers(
        harbor.config(),
        csrf.cookie_header.as_deref(),
        csrf.csrf_header.as_deref(),
    )?;
    let signin = service
        .sign_in_with_email_challenge_with_policy(
            EmailChallengeSignInInput {
                challenge_id,
                secret,
                redirect_path,
            },
            EmailChallengeSignInPolicy::new(passwordless_signup),
        )
        .await?;
    let set_cookie = crate::build_session_cookie(
        harbor.config().cookie_defaults(),
        &signin.session_token,
        None,
    )
    .map_err(AuthError::from)?;
    Ok(SessionActionResponse {
        set_cookie,
        redirect_path: signin.redirect_path,
    })
}
