//! Axum adapters for Harbor email link routes.

use std::collections::HashMap;

use ::axum::{
    Router,
    extract::{Query, State},
    http::{
        HeaderValue, StatusCode,
        header::{LOCATION, REFERRER_POLICY, SET_COOKIE},
    },
    response::{IntoResponse, Response},
    routing::get,
};
use harbor_core::{
    AuthError, AuthErrorCode, AuthService, AuthStore, Clock, PasswordBlocklist, RedirectPath,
    SecretGenerator,
};

use crate::{
    AuthLinkQuery, HarborConfig, handle_confirm_email_link, handle_email_link_signin,
    handle_reset_password_link,
};

/// Cloneable state for Harbor's Axum email link routes.
#[derive(Clone)]
pub struct HarborAxumState<S, C, G, B> {
    service: AuthService<S, C, G, B>,
    config: HarborConfig,
}

impl<S, C, G, B> HarborAxumState<S, C, G, B> {
    /// Creates Axum link-route state from an auth service and config.
    #[must_use]
    pub const fn new(service: AuthService<S, C, G, B>, config: HarborConfig) -> Self {
        Self { service, config }
    }

    /// Returns the configured service.
    #[must_use]
    pub const fn service(&self) -> &AuthService<S, C, G, B> {
        &self.service
    }

    /// Returns the Harbor config.
    #[must_use]
    pub const fn config(&self) -> &HarborConfig {
        &self.config
    }
}

/// Builds Axum GET routes for Harbor email links.
///
/// The returned router owns state and mounts:
///
/// - `/auth/confirm-email`
/// - `/auth/email-link`
/// - `/auth/reset-password`
pub fn auth_link_router<S, C, G, B>(state: HarborAxumState<S, C, G, B>) -> Router
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    Router::new()
        .route("/auth/confirm-email", get(confirm_email::<S, C, G, B>))
        .route("/auth/email-link", get(email_link::<S, C, G, B>))
        .route("/auth/reset-password", get(reset_password::<S, C, G, B>))
        .with_state(state)
}

async fn confirm_email<S, C, G, B>(
    State(state): State<HarborAxumState<S, C, G, B>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    route_response(handle_confirm_email_link(&state.service, parse_query(query)).await)
}

async fn email_link<S, C, G, B>(
    State(state): State<HarborAxumState<S, C, G, B>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    route_response(
        handle_email_link_signin(&state.service, &state.config, parse_query(query)).await,
    )
}

async fn reset_password<S, C, G, B>(
    State(_state): State<HarborAxumState<S, C, G, B>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response
where
    S: AuthStore,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    route_response(handle_reset_password_link(parse_query(query)))
}

fn parse_query(query: HashMap<String, String>) -> AuthLinkQuery {
    AuthLinkQuery {
        challenge: query.get("challenge").cloned().unwrap_or_default(),
        token: query.get("token").cloned().unwrap_or_default(),
        redirect: query
            .get("redirect")
            .and_then(|value| RedirectPath::try_new(value.clone()).ok()),
    }
}

fn route_response(result: Result<crate::LinkRouteResponse, AuthError>) -> Response {
    match result {
        Ok(response) => see_other(response),
        Err(error) => auth_error_response(error),
    }
}

fn see_other(route: crate::LinkRouteResponse) -> Response {
    let mut response = (StatusCode::SEE_OTHER, "").into_response();
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&route.location) {
        headers.insert(LOCATION, value);
    }
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    if let Some(cookie) = route.set_cookie
        && let Ok(value) = HeaderValue::from_str(&cookie)
    {
        headers.append(SET_COOKIE, value);
    }
    response
}

fn auth_error_response(error: AuthError) -> Response {
    let status = match error.code() {
        AuthErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        AuthErrorCode::Store
        | AuthErrorCode::Mail
        | AuthErrorCode::Config
        | AuthErrorCode::Internal => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    let mut response = (status, error.user_message()).into_response();
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response
}

#[cfg(test)]
mod tests {
    use ::axum::http::{
        HeaderValue,
        header::{LOCATION, REFERRER_POLICY, SET_COOKIE},
    };
    use harbor_core::{AuthError, AuthErrorCode};

    use super::{auth_error_response, parse_query, see_other};
    use crate::LinkRouteResponse;

    #[test]
    fn redirect_response_sets_location_cookie_and_referrer_policy() {
        let response = see_other(LinkRouteResponse {
            location: "/account".to_owned(),
            set_cookie: Some("harbor_session=token; Path=/; HttpOnly".to_owned()),
        });

        assert_eq!(response.status(), 303);
        assert_eq!(
            response.headers().get(LOCATION),
            Some(&HeaderValue::from_static("/account"))
        );
        assert_eq!(
            response.headers().get(REFERRER_POLICY),
            Some(&HeaderValue::from_static("no-referrer"))
        );
        assert!(response.headers().get(SET_COOKIE).is_some());
    }

    #[test]
    fn auth_errors_map_to_safe_http_responses() {
        let rate = auth_error_response(AuthError::new(AuthErrorCode::RateLimited));
        let invalid = auth_error_response(AuthError::new(AuthErrorCode::InvalidCredentials));
        let internal = auth_error_response(AuthError::new(AuthErrorCode::Internal));

        assert_eq!(rate.status(), 429);
        assert_eq!(invalid.status(), 400);
        assert_eq!(internal.status(), 503);
        assert_eq!(
            invalid.headers().get(REFERRER_POLICY),
            Some(&HeaderValue::from_static("no-referrer"))
        );
    }

    #[test]
    fn query_parser_keeps_only_safe_redirects() {
        let query = std::collections::HashMap::from([
            ("challenge".to_owned(), "abc123".to_owned()),
            ("token".to_owned(), "secret".to_owned()),
            ("redirect".to_owned(), "/account".to_owned()),
        ]);
        let parsed = parse_query(query);
        assert_eq!(parsed.challenge, "abc123");
        assert_eq!(parsed.token, "secret");
        assert_eq!(
            parsed
                .redirect
                .as_ref()
                .map(harbor_core::RedirectPath::as_str),
            Some("/account")
        );

        let escaped = parse_query(std::collections::HashMap::from([(
            "redirect".to_owned(),
            "https://example.com".to_owned(),
        )]));
        assert!(escaped.redirect.is_none());
    }
}
