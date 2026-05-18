use ::axum::http::{
    HeaderValue,
    header::{LOCATION, REFERRER_POLICY, SET_COOKIE},
};
use harbor_core::{
    Argon2Params, Argon2PasswordHasher, AuthError, AuthErrorCode, AuthService, ChallengeDelivery,
    ChallengePurpose, HmacSecretKey, PasswordPolicy, SystemClock, SystemSecretGenerator,
};
use harbor_email::RecordingMailer;
use harbor_sqlx::{SqliteAuthStore, SqliteStoreOptions};

use super::{
    HarborAxumState, auth_error_response, auth_link_router, confirm_email, email_link, parse_query,
    reset_password, route_response, see_other,
};
use crate::{CookieDefaults, Harbor, LinkRouteResponse};

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

#[tokio::test]
async fn state_router_and_route_response_are_wired() -> Result<(), Box<dyn std::error::Error>> {
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
    let harbor = Harbor::builder()
        .with_store(())
        .with_mailer(RecordingMailer::new())
        .with_public_base_url("http://localhost:3000")?
        .with_cookie_defaults(CookieDefaults::development())?
        .with_hmac_secret_key(vec![7; 32])?
        .finish()?;
    let state = HarborAxumState::new(service, harbor.config().clone());

    assert_eq!(
        state.config().public_base_url().as_str(),
        "http://localhost:3000"
    );
    let _service = state.service();
    let _router = auth_link_router(state.clone());
    let ok = route_response(Ok(LinkRouteResponse {
        location: "/account".to_owned(),
        set_cookie: None,
    }));
    let error = route_response(Err(AuthError::new(AuthErrorCode::Csrf)));
    let reset = reset_password(
        ::axum::extract::State(state),
        ::axum::extract::Query(std::collections::HashMap::from([
            ("challenge".to_owned(), "challenge00000001".to_owned()),
            ("token".to_owned(), "secret-token".to_owned()),
            ("redirect".to_owned(), "/account".to_owned()),
        ])),
    )
    .await;

    assert_eq!(ok.status(), 303);
    assert_eq!(error.status(), 400);
    assert_eq!(reset.status(), 303);
    Ok(())
}

#[tokio::test]
async fn axum_link_handlers_consume_valid_challenges() -> Result<(), Box<dyn std::error::Error>> {
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
    let harbor = Harbor::builder()
        .with_store(())
        .with_mailer(RecordingMailer::new())
        .with_public_base_url("http://localhost:3000")?
        .with_cookie_defaults(CookieDefaults::development())?
        .with_hmac_secret_key(vec![7; 32])?
        .finish()?;
    let state = HarborAxumState::new(service, harbor.config().clone());

    let signup = state
        .service()
        .sign_up_with_password(harbor_core::PasswordSignUpInput {
            email: "axum-confirm@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
        })
        .await?;
    let confirmation = state
        .service()
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::SignupConfirmation,
            delivery: ChallengeDelivery::MagicLink,
            email: signup.email.email_original,
            user_id: Some(signup.user.id),
            redirect_path: None,
        })
        .await?;
    let confirmed = confirm_email(
        ::axum::extract::State(state.clone()),
        ::axum::extract::Query(std::collections::HashMap::from([
            (
                "challenge".to_owned(),
                confirmation.challenge.id.as_str().to_owned(),
            ),
            (
                "token".to_owned(),
                confirmation.secret.expose_secret().to_owned(),
            ),
        ])),
    )
    .await;
    assert_eq!(confirmed.status(), 303);
    assert_eq!(
        confirmed.headers().get(LOCATION),
        Some(&HeaderValue::from_static("/signin"))
    );

    let signin_challenge = state
        .service()
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::MagicLink,
            email: "axum-link@example.com".to_owned(),
            user_id: None,
            redirect_path: Some(harbor_core::RedirectPath::try_new("/account")?),
        })
        .await?;
    let signed_in = email_link(
        ::axum::extract::State(state),
        ::axum::extract::Query(std::collections::HashMap::from([
            (
                "challenge".to_owned(),
                signin_challenge.challenge.id.as_str().to_owned(),
            ),
            (
                "token".to_owned(),
                signin_challenge.secret.expose_secret().to_owned(),
            ),
            ("redirect".to_owned(), "/account".to_owned()),
        ])),
    )
    .await;

    assert_eq!(signed_in.status(), 303);
    assert_eq!(
        signed_in.headers().get(LOCATION),
        Some(&HeaderValue::from_static("/account"))
    );
    assert!(signed_in.headers().get(SET_COOKIE).is_some());
    Ok(())
}
