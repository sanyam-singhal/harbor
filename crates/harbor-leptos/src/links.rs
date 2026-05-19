//! Email link route helpers.

use harbor_core::{
    AuthError, AuthErrorCode, AuthService, AuthStore, ChallengeId, ChallengePurpose, Clock,
    PasswordBlocklist, RedirectPath, SecretGenerator, SecretToken,
};

use crate::{HarborConfig, build_session_cookie, percent_encode_query};

/// Query values accepted by auth email link routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthLinkQuery {
    /// Challenge id from the email URL.
    pub challenge: String,
    /// Secret token from the email URL.
    pub token: String,
    /// Optional validated redirect path.
    pub redirect: Option<RedirectPath>,
}

/// Link route outcome for an Axum adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRouteResponse {
    /// Redirect target.
    pub location: String,
    /// Optional `Set-Cookie` value.
    pub set_cookie: Option<String>,
}

/// Handles a signup confirmation email link.
///
/// # Errors
///
/// Returns [`AuthError`] when the link is invalid or verification fails.
pub async fn handle_confirm_email_link<S, C, G, B>(
    service: &AuthService<S, C, G, B>,
    query: AuthLinkQuery,
) -> Result<LinkRouteResponse, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    let challenge_id = parse_link_challenge_id(query.challenge)?;
    let secret = parse_link_token(query.token)?;
    let verified = service
        .verify_email_challenge(harbor_core::VerifyChallengeInput {
            challenge_id,
            purpose: ChallengePurpose::SignupConfirmation,
            secret,
        })
        .await?;
    Ok(LinkRouteResponse {
        location: link_redirect(
            verified.challenge.redirect_path.as_ref(),
            query.redirect.as_ref(),
            "/signin",
        ),
        set_cookie: None,
    })
}

/// Handles an email signin link and returns a session cookie.
///
/// # Errors
///
/// Returns [`AuthError`] when the link is invalid, signin fails, or the cookie
/// cannot be built.
pub async fn handle_email_link_signin<S, C, G, B>(
    service: &AuthService<S, C, G, B>,
    config: &HarborConfig,
    query: AuthLinkQuery,
) -> Result<LinkRouteResponse, AuthError>
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    let AuthLinkQuery {
        challenge,
        token,
        redirect,
    } = query;
    let signin = service
        .sign_in_with_email_challenge(harbor_core::EmailChallengeSignInInput {
            challenge_id: parse_link_challenge_id(challenge)?,
            secret: parse_link_token(token)?,
            redirect_path: redirect,
        })
        .await?;
    let set_cookie = build_session_cookie(config.cookie_defaults(), &signin.session_token, None)
        .map_err(AuthError::from)?;
    Ok(LinkRouteResponse {
        location: link_redirect(None, signin.redirect_path.as_ref(), "/account"),
        set_cookie: Some(set_cookie),
    })
}

/// Handles a reset-password email link.
///
/// This route does not consume the challenge. It moves the user to the reset
/// form where the new password is submitted with the token.
///
/// # Errors
///
/// Returns [`AuthError`] when the link id or token shape is invalid.
pub fn handle_reset_password_link(query: AuthLinkQuery) -> Result<LinkRouteResponse, AuthError> {
    let challenge_id = parse_link_challenge_id(query.challenge)?;
    let token = parse_link_token(query.token)?;
    let mut location = format!(
        "/reset-password?challenge={}&token={}",
        challenge_id.as_str(),
        token.expose_secret()
    );
    if let Some(redirect) = query.redirect.as_ref() {
        location.push_str("&redirect=");
        location.push_str(percent_encode_query(redirect.as_str()).as_str());
    }
    Ok(LinkRouteResponse {
        location,
        set_cookie: None,
    })
}

fn parse_link_challenge_id(value: String) -> Result<ChallengeId, AuthError> {
    ChallengeId::try_new(value).map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))
}

fn parse_link_token(value: String) -> Result<SecretToken, AuthError> {
    SecretToken::try_new(value).map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))
}

fn link_redirect(
    stored: Option<&RedirectPath>,
    query: Option<&RedirectPath>,
    fallback: &str,
) -> String {
    stored.or(query).map_or_else(
        || fallback.to_owned(),
        |redirect| redirect.as_str().to_owned(),
    )
}
