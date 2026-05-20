//! SSR entrypoint for the Harbor Leptos demo.

#[cfg(feature = "ssr")]
use axum::extract::{Query, State};
#[cfg(feature = "ssr")]
use axum::response::IntoResponse;
#[cfg(feature = "ssr")]
use harbor::{core as harbor_core, leptos as harbor_leptos};

#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use axum::Router;
    use axum::routing::get;
    use harbor_demo::app::{App, shell};
    use harbor_demo::auth::{DemoState, provide_demo_state};
    use leptos::config::get_configuration;
    use leptos_axum::{LeptosRoutes, file_and_error_handler_with_context, generate_route_list};

    let configuration = get_configuration(None)
        .or_else(|_error| get_configuration(Some("crates/harbor-demo/Cargo.toml")))?;
    let leptos_options = configuration.leptos_options;
    let addr = leptos_options.site_addr;
    let state = DemoState::from_env(leptos_options.clone()).await?;
    let routes = generate_route_list(App);
    let context = {
        let state = state.clone();
        move || provide_demo_state(state.clone())
    };
    let fallback_context = {
        let state = state.clone();
        move || provide_demo_state(state.clone())
    };
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/auth/confirm-email", get(confirm_email))
        .route("/auth/email-link", get(email_link_signin))
        .route("/auth/reset-password", get(reset_password_link))
        .leptos_routes_with_context(&state, routes, context, {
            let leptos_options = leptos_options.clone();
            move || shell(leptos_options.clone())
        })
        .fallback(file_and_error_handler_with_context::<DemoState, _>(
            fallback_context,
            shell,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

#[cfg(not(feature = "ssr"))]
/// Client builds hydrate through `lib.rs`.
pub fn main() {}

#[cfg(feature = "ssr")]
async fn confirm_email(
    State(state): axum::extract::State<harbor_demo::auth::DemoState>,
    Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    let query = match auth_link_query(query) {
        Ok(query) => query,
        Err(_error) => return error_response(axum::http::StatusCode::BAD_REQUEST),
    };
    match harbor_leptos::handle_confirm_email_link(state.service(), query).await {
        Ok(mut response) => {
            response.location = "/signin?notice=verified".to_owned();
            redirect_response(response)
        }
        Err(_error) => error_response(axum::http::StatusCode::BAD_REQUEST),
    }
}

#[cfg(feature = "ssr")]
async fn email_link_signin(
    State(state): axum::extract::State<harbor_demo::auth::DemoState>,
    Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    let query = match auth_link_query(query) {
        Ok(query) => query,
        Err(_error) => return error_response(axum::http::StatusCode::BAD_REQUEST),
    };
    match harbor_leptos::handle_email_link_signin(state.service(), state.harbor().config(), query)
        .await
    {
        Ok(response) => redirect_response(response),
        Err(_error) => error_response(axum::http::StatusCode::BAD_REQUEST),
    }
}

#[cfg(feature = "ssr")]
async fn reset_password_link(
    Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    match auth_link_query(query).and_then(harbor_leptos::handle_reset_password_link) {
        Ok(response) => redirect_response(response),
        Err(_error) => error_response(axum::http::StatusCode::BAD_REQUEST),
    }
}

#[cfg(feature = "ssr")]
fn auth_link_query(
    mut values: std::collections::HashMap<String, String>,
) -> Result<harbor_leptos::AuthLinkQuery, harbor_core::AuthError> {
    let challenge = values.remove("challenge").ok_or_else(|| {
        harbor_core::AuthError::new(harbor_core::AuthErrorCode::InvalidCredentials)
    })?;
    let token = values.remove("token").ok_or_else(|| {
        harbor_core::AuthError::new(harbor_core::AuthErrorCode::InvalidCredentials)
    })?;
    let redirect = values
        .remove("redirect")
        .map(harbor_core::RedirectPath::try_new)
        .transpose()
        .map_err(|_error| {
            harbor_core::AuthError::new(harbor_core::AuthErrorCode::InvalidCredentials)
        })?;
    Ok(harbor_leptos::AuthLinkQuery {
        challenge,
        token,
        redirect,
    })
}

#[cfg(feature = "ssr")]
fn redirect_response(response: harbor_leptos::LinkRouteResponse) -> axum::response::Response {
    let mut response_out = axum::response::Redirect::to(&response.location).into_response();
    if let Some(cookie) = response.set_cookie
        && let Ok(value) = axum::http::HeaderValue::from_str(&cookie)
    {
        response_out
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, value);
    }
    response_out
}

#[cfg(feature = "ssr")]
fn error_response(status: axum::http::StatusCode) -> axum::response::Response {
    (status, "Invalid or expired auth link.").into_response()
}
