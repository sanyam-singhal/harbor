//! Axum adapters for Harbor email link routes.

use std::collections::HashMap;

use ::axum::{
    Router,
    extract::{Query, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{COOKIE, LOCATION, REFERRER_POLICY, SET_COOKIE, USER_AGENT},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use harbor_core::{
    AuthError, AuthErrorCode, AuthService, AuthStore, ChallengeId, Clock, PasswordBlocklist,
    RedirectPath, SecretGenerator, SecretToken, SystemSecretGenerator,
};
use harbor_email::AuthMailer;

use crate::{
    AuthApi, AuthFlowConfig, AuthLinkQuery, AuthRouteConfig, Harbor, HarborConfig,
    LinkRouteResponse, PasswordResetRequest, ResetPasswordRequest, SendEmailOtpRequest,
    SignInEmailOtpRequest, SignInEmailRequest, SignInMagicLinkRequest, SignOutRequest,
    SignUpEmailRequest, build_csrf_cookie, handle_confirm_email_link, handle_email_link_signin,
    handle_email_link_signin_with_policy, handle_reset_password_link, issue_csrf_token,
    percent_encode_query,
};

const MAX_FORM_BODY_BYTES: usize = 16 * 1024;
const MAX_FORM_FIELDS: usize = 32;

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
        .route(
            "/auth/reset-password",
            get(reset_password_legacy::<S, C, G, B>),
        )
        .with_state(state)
}

/// Cloneable state for Harbor's full Axum auth route bundle.
#[derive(Clone)]
pub struct HarborAuthAxumState<S, M, C, G, B> {
    harbor: Harbor<S, M>,
    service: AuthService<S, C, G, B>,
    flow_config: AuthFlowConfig,
    route_config: AuthRouteConfig,
}

impl<S, M, C, G, B> HarborAuthAxumState<S, M, C, G, B> {
    /// Creates Axum state for Harbor auth routes.
    #[must_use]
    pub const fn new(
        harbor: Harbor<S, M>,
        service: AuthService<S, C, G, B>,
        flow_config: AuthFlowConfig,
        route_config: AuthRouteConfig,
    ) -> Self {
        Self {
            harbor,
            service,
            flow_config,
            route_config,
        }
    }

    /// Returns the configured Harbor shell.
    #[must_use]
    pub const fn harbor(&self) -> &Harbor<S, M> {
        &self.harbor
    }

    /// Returns the configured service.
    #[must_use]
    pub const fn service(&self) -> &AuthService<S, C, G, B> {
        &self.service
    }

    /// Returns flow config.
    #[must_use]
    pub const fn flow_config(&self) -> &AuthFlowConfig {
        &self.flow_config
    }

    /// Returns route config.
    #[must_use]
    pub const fn route_config(&self) -> &AuthRouteConfig {
        &self.route_config
    }

    fn api(&self) -> AuthApi<'_, S, M, C, G, B> {
        AuthApi::new_runtime_parts(
            &self.harbor,
            &self.service,
            &self.flow_config,
            &self.route_config,
        )
    }
}

/// Builds Axum routes for Harbor's full email-auth surface.
///
/// The returned router owns its auth state and mounts both API form endpoints
/// and email link endpoints.
pub fn auth_router<S, M, C, G, B>(state: HarborAuthAxumState<S, M, C, G, B>) -> Router
where
    S: AuthStore,
    M: AuthMailer,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    let routes = state.route_config().clone();
    let csrf = api_route(&routes, "/csrf");
    let sign_up_email_path = api_route(&routes, "/sign-up/email");
    let sign_in_email_path = api_route(&routes, "/sign-in/email");
    let magic_link = api_route(&routes, "/sign-in/magic-link");
    let email_otp_send = api_route(&routes, "/email-otp/send");
    let email_otp_sign_in = api_route(&routes, "/email-otp/sign-in");
    let forgot_password = api_route(&routes, "/password/forgot");
    let reset_password_api = api_route(&routes, "/password/reset");
    let sign_out_path = api_route(&routes, "/sign-out");
    let confirm_email = routes.confirm_email_link();
    let email_link = routes.magic_link();
    let reset_password_link = routes.reset_password_link();

    Router::new()
        .route(&csrf, get(issue_csrf::<S, M, C, G, B>))
        .route(&sign_up_email_path, post(sign_up_email::<S, M, C, G, B>))
        .route(&sign_in_email_path, post(sign_in_email::<S, M, C, G, B>))
        .route(&magic_link, post(send_magic_link::<S, M, C, G, B>))
        .route(&email_otp_send, post(send_email_otp::<S, M, C, G, B>))
        .route(&email_otp_sign_in, post(sign_in_email_otp::<S, M, C, G, B>))
        .route(
            &forgot_password,
            post(request_password_reset::<S, M, C, G, B>),
        )
        .route(
            &reset_password_api,
            post(reset_password_action::<S, M, C, G, B>),
        )
        .route(&sign_out_path, post(sign_out::<S, M, C, G, B>))
        .route(&confirm_email, get(confirm_email_full::<S, M, C, G, B>))
        .route(&email_link, get(email_link_full::<S, M, C, G, B>))
        .route(
            &reset_password_link,
            get(reset_password_link_full::<S, M, C, G, B>),
        )
        .with_state(state)
}

async fn issue_csrf<S, M, C, G, B>(
    State(state): State<HarborAuthAxumState<S, M, C, G, B>>,
) -> Response
where
    S: AuthStore,
    M: AuthMailer,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    match issue_csrf_token(state.harbor().config(), &SystemSecretGenerator).and_then(|token| {
        let cookie = build_csrf_cookie(state.harbor().config().cookie_defaults(), &token, None)?;
        Ok((token.expose_secret().to_owned(), cookie))
    }) {
        Ok((token, cookie)) => {
            let mut response = (StatusCode::OK, token).into_response();
            if let Ok(value) = HeaderValue::from_str(&cookie) {
                response.headers_mut().append(SET_COOKIE, value);
            }
            response
        }
        Err(error) => auth_error_response(error),
    }
}

async fn sign_up_email<S, M, C, G, B>(
    State(state): State<HarborAuthAxumState<S, M, C, G, B>>,
    headers: HeaderMap,
    body: String,
) -> Response
where
    S: AuthStore,
    M: AuthMailer,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    let result = async {
        let form = parse_form_body(&body)?;
        let request = SignUpEmailRequest {
            csrf: csrf_request(&headers, &form),
            email: required_form_value(&form, "email")?,
            password: required_form_value(&form, "password")?,
        };
        state.api().sign_up_email(request).await
    }
    .await;
    form_action_response(
        result.map(|_response| None),
        state.route_config().signin().as_str(),
        state.route_config(),
    )
}

async fn sign_in_email<S, M, C, G, B>(
    State(state): State<HarborAuthAxumState<S, M, C, G, B>>,
    headers: HeaderMap,
    body: String,
) -> Response
where
    S: AuthStore,
    M: AuthMailer,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    let result = async {
        let form = parse_form_body(&body)?;
        let request = SignInEmailRequest {
            csrf: csrf_request(&headers, &form),
            email: required_form_value(&form, "email")?,
            password: required_form_value(&form, "password")?,
            redirect_path: optional_redirect(&form)?,
        };
        state.api().sign_in_email(request).await
    }
    .await;
    match result {
        Ok(response) => {
            let location = response.redirect_path.as_ref().map_or(
                state.route_config().account().as_str(),
                RedirectPath::as_str,
            );
            see_other(LinkRouteResponse {
                location: location.to_owned(),
                set_cookie: Some(response.set_cookie),
            })
        }
        Err(_error) => see_other(LinkRouteResponse {
            location: state.route_config().error_redirect().as_str().to_owned(),
            set_cookie: None,
        }),
    }
}

async fn send_magic_link<S, M, C, G, B>(
    State(state): State<HarborAuthAxumState<S, M, C, G, B>>,
    headers: HeaderMap,
    body: String,
) -> Response
where
    S: AuthStore,
    M: AuthMailer,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    let result = async {
        let form = parse_form_body(&body)?;
        let request = SignInMagicLinkRequest {
            csrf: csrf_request(&headers, &form),
            email: required_form_value(&form, "email")?,
            redirect_path: optional_redirect(&form)?,
        };
        state.api().sign_in_magic_link(request).await
    }
    .await;
    form_action_response(
        result.map(|_response| None),
        state.route_config().signin().as_str(),
        state.route_config(),
    )
}

async fn send_email_otp<S, M, C, G, B>(
    State(state): State<HarborAuthAxumState<S, M, C, G, B>>,
    headers: HeaderMap,
    body: String,
) -> Response
where
    S: AuthStore,
    M: AuthMailer,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    let result = async {
        let form = parse_form_body(&body)?;
        let request = SendEmailOtpRequest {
            csrf: csrf_request(&headers, &form),
            email: required_form_value(&form, "email")?,
            redirect_path: optional_redirect(&form)?,
        };
        state.api().send_email_otp(request).await
    }
    .await;
    match result {
        Ok(response) => see_other(LinkRouteResponse {
            location: append_query(
                state.route_config().signin().as_str(),
                "challenge",
                response.challenge_id.as_str(),
            ),
            set_cookie: None,
        }),
        Err(_error) => see_other(LinkRouteResponse {
            location: state.route_config().error_redirect().as_str().to_owned(),
            set_cookie: None,
        }),
    }
}

async fn sign_in_email_otp<S, M, C, G, B>(
    State(state): State<HarborAuthAxumState<S, M, C, G, B>>,
    headers: HeaderMap,
    body: String,
) -> Response
where
    S: AuthStore,
    M: AuthMailer,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    let result = async {
        let form = parse_form_body(&body)?;
        let request = SignInEmailOtpRequest {
            csrf: csrf_request(&headers, &form),
            challenge_id: ChallengeId::try_new(required_form_value(&form, "challenge")?)
                .map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))?,
            code: SecretToken::try_new(required_form_value(&form, "code")?)
                .map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))?,
            redirect_path: optional_redirect(&form)?,
        };
        state.api().sign_in_email_otp(request).await
    }
    .await;
    match result {
        Ok(response) => {
            let location = response.redirect_path.as_ref().map_or(
                state.route_config().account().as_str(),
                RedirectPath::as_str,
            );
            see_other(LinkRouteResponse {
                location: location.to_owned(),
                set_cookie: Some(response.set_cookie),
            })
        }
        Err(_error) => see_other(LinkRouteResponse {
            location: state.route_config().error_redirect().as_str().to_owned(),
            set_cookie: None,
        }),
    }
}

async fn request_password_reset<S, M, C, G, B>(
    State(state): State<HarborAuthAxumState<S, M, C, G, B>>,
    headers: HeaderMap,
    body: String,
) -> Response
where
    S: AuthStore,
    M: AuthMailer,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    let result = async {
        let form = parse_form_body(&body)?;
        let request = PasswordResetRequest {
            csrf: csrf_request(&headers, &form),
            email: required_form_value(&form, "email")?,
            redirect_path: optional_redirect(&form)?,
        };
        state.api().request_password_reset(request).await
    }
    .await;
    form_action_response(
        result.map(|_response| None),
        state.route_config().signin().as_str(),
        state.route_config(),
    )
}

async fn reset_password_action<S, M, C, G, B>(
    State(state): State<HarborAuthAxumState<S, M, C, G, B>>,
    headers: HeaderMap,
    body: String,
) -> Response
where
    S: AuthStore,
    M: AuthMailer,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    let result = async {
        let form = parse_form_body(&body)?;
        let request = ResetPasswordRequest {
            csrf: csrf_request(&headers, &form),
            challenge_id: ChallengeId::try_new(required_form_value(&form, "challenge")?)
                .map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))?,
            token: SecretToken::try_new(required_form_value(&form, "token")?)
                .map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))?,
            new_password: required_form_value(&form, "new_password")?,
        };
        state.api().reset_password(request).await
    }
    .await;
    form_action_response(
        result.map(|_response| None),
        state.route_config().signin().as_str(),
        state.route_config(),
    )
}

async fn sign_out<S, M, C, G, B>(
    State(state): State<HarborAuthAxumState<S, M, C, G, B>>,
    headers: HeaderMap,
    body: String,
) -> Response
where
    S: AuthStore,
    M: AuthMailer,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    let result = async {
        let form = parse_form_body(&body)?;
        let request = SignOutRequest {
            csrf: csrf_request(&headers, &form),
        };
        state.api().sign_out(request).await
    }
    .await;
    match result {
        Ok(delete_cookie) => see_other(LinkRouteResponse {
            location: state.route_config().signin().as_str().to_owned(),
            set_cookie: Some(delete_cookie),
        }),
        Err(_error) => see_other(LinkRouteResponse {
            location: state.route_config().error_redirect().as_str().to_owned(),
            set_cookie: None,
        }),
    }
}

async fn confirm_email_full<S, M, C, G, B>(
    State(state): State<HarborAuthAxumState<S, M, C, G, B>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response
where
    S: AuthStore,
    M: AuthMailer,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    route_response(
        handle_confirm_email_link(&state.service, parse_query(query))
            .await
            .map(|mut response| {
                response.location = state.route_config().verified_redirect().as_str().to_owned();
                response
            }),
    )
}

async fn email_link_full<S, M, C, G, B>(
    State(state): State<HarborAuthAxumState<S, M, C, G, B>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response
where
    S: AuthStore,
    M: AuthMailer,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    route_response(
        handle_email_link_signin_with_policy(
            &state.service,
            state.harbor().config(),
            parse_query(query),
            state.flow_config().magic_link().passwordless_signup(),
        )
        .await
        .map(|mut response| {
            if response.location == "/account" {
                response.location = state.route_config().account().as_str().to_owned();
            }
            response
        }),
    )
}

async fn reset_password_link_full<S, M, C, G, B>(
    State(state): State<HarborAuthAxumState<S, M, C, G, B>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response
where
    S: AuthStore,
    M: AuthMailer,
    C: Clock,
    G: SecretGenerator,
    B: PasswordBlocklist,
{
    route_response(
        handle_reset_password_link(parse_query(query)).map(|mut response| {
            if let Some(suffix) = response.location.strip_prefix("/reset-password") {
                response.location = format!(
                    "{}{}",
                    state.route_config().reset_password().as_str(),
                    suffix
                );
            }
            response
        }),
    )
}

fn api_route(routes: &AuthRouteConfig, suffix: &str) -> String {
    let mut route = String::with_capacity(routes.api_prefix().as_str().len() + suffix.len());
    route.push_str(routes.api_prefix().as_str());
    route.push_str(suffix);
    route
}

fn form_action_response(
    result: Result<Option<String>, AuthError>,
    success_location: &str,
    routes: &AuthRouteConfig,
) -> Response {
    match result {
        Ok(set_cookie) => see_other(LinkRouteResponse {
            location: success_location.to_owned(),
            set_cookie,
        }),
        Err(_error) => see_other(LinkRouteResponse {
            location: routes.error_redirect().as_str().to_owned(),
            set_cookie: None,
        }),
    }
}

fn csrf_request(headers: &HeaderMap, form: &HashMap<String, String>) -> crate::CsrfRequest {
    let cookie_header = header_to_string(headers, COOKIE);
    let csrf_header = form
        .get("csrf_token")
        .cloned()
        .or_else(|| header_to_string(headers, "x-harbor-csrf"));
    let rate_limit_key = header_to_string(headers, "x-forwarded-for")
        .or_else(|| header_to_string(headers, "x-real-ip"))
        .or_else(|| header_to_string(headers, USER_AGENT));
    crate::CsrfRequest {
        cookie_header,
        csrf_header,
        rate_limit_key,
    }
}

fn header_to_string(
    headers: &HeaderMap,
    name: impl axum::http::header::AsHeaderName,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn optional_redirect(form: &HashMap<String, String>) -> Result<Option<RedirectPath>, AuthError> {
    form.get("redirect")
        .or_else(|| form.get("callback_url"))
        .filter(|value| !value.is_empty())
        .map(|value| RedirectPath::try_new(value.clone()))
        .transpose()
        .map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))
}

fn required_form_value(
    form: &HashMap<String, String>,
    name: &'static str,
) -> Result<String, AuthError> {
    form.get(name)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| AuthError::with_detail(AuthErrorCode::InvalidCredentials, name))
}

fn parse_form_body(body: &str) -> Result<HashMap<String, String>, AuthError> {
    if body.len() > MAX_FORM_BODY_BYTES {
        return Err(AuthError::new(AuthErrorCode::InvalidCredentials));
    }
    let mut form = HashMap::new();
    if body.is_empty() {
        return Ok(form);
    }
    for pair in body.split('&') {
        if form.len() >= MAX_FORM_FIELDS {
            return Err(AuthError::new(AuthErrorCode::InvalidCredentials));
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = decode_form_component(name)?;
        let value = decode_form_component(value)?;
        form.insert(name, value);
    }
    Ok(form)
}

fn decode_form_component(value: &str) -> Result<String, AuthError> {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                let high = bytes
                    .get(index + 1)
                    .and_then(|byte| hex_value(*byte))
                    .ok_or_else(|| AuthError::new(AuthErrorCode::InvalidCredentials))?;
                let low = bytes
                    .get(index + 2)
                    .and_then(|byte| hex_value(*byte))
                    .ok_or_else(|| AuthError::new(AuthErrorCode::InvalidCredentials))?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_error| AuthError::new(AuthErrorCode::InvalidCredentials))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn append_query(path: &str, name: &str, value: &str) -> String {
    let separator = if path.contains('?') { '&' } else { '?' };
    format!("{path}{separator}{name}={}", percent_encode_query(value))
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

async fn reset_password_legacy<S, C, G, B>(
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

fn parse_query(mut query: HashMap<String, String>) -> AuthLinkQuery {
    AuthLinkQuery {
        challenge: query.remove("challenge").unwrap_or_default(),
        token: query.remove("token").unwrap_or_default(),
        redirect: query
            .remove("redirect")
            .and_then(|value| RedirectPath::try_new(value).ok()),
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
