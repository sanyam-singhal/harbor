//! Axum adapter integration tests for `harbor-leptos`.

#![cfg(feature = "axum")]

use harbor_core::{
    Argon2Params, Argon2PasswordHasher, AuthService, ChallengeDelivery, ChallengePurpose,
    HmacSecretKey, PasswordPolicy, RedirectPath, SystemClock, SystemSecretGenerator,
};
use harbor_email::RecordingMailer;
use harbor_leptos::axum::{HarborAxumState, auth_link_router};
use harbor_leptos::{
    AuthLinkQuery, CookieDefaults, Harbor, handle_confirm_email_link, handle_email_link_signin,
    handle_reset_password_link,
};
use harbor_sqlx::{SqliteAuthStore, SqliteStoreOptions};

type TestService = AuthService<SqliteAuthStore, SystemClock, SystemSecretGenerator>;

async fn test_service() -> Result<TestService, Box<dyn std::error::Error>> {
    let store =
        SqliteAuthStore::connect_and_migrate("sqlite::memory:", SqliteStoreOptions::in_memory())
            .await?;
    Ok(AuthService::new(
        store,
        SystemClock,
        SystemSecretGenerator,
        HmacSecretKey::try_new(vec![7; 32])?,
        Argon2PasswordHasher::new(
            PasswordPolicy::try_new(8, 128)?,
            Argon2Params::try_new(32, 1, 1)?,
        ),
    ))
}

fn test_harbor() -> Result<Harbor<(), RecordingMailer>, Box<dyn std::error::Error>> {
    Ok(Harbor::builder()
        .with_store(())
        .with_mailer(RecordingMailer::new())
        .with_public_base_url("http://localhost:3000")?
        .with_cookie_defaults(CookieDefaults::development())?
        .with_hmac_secret_key(vec![7; 32])?
        .with_default_email_renderer("TestAuth", "localhost")?
        .finish()?)
}

#[tokio::test]
async fn axum_state_and_router_are_publicly_wired() -> Result<(), Box<dyn std::error::Error>> {
    let service = test_service().await?;
    let harbor = test_harbor()?;
    let state = HarborAxumState::new(service, harbor.config().clone());

    assert_eq!(
        state.config().public_base_url().as_str(),
        "http://localhost:3000"
    );
    let _service = state.service();
    let _router = auth_link_router(state);

    let reset = handle_reset_password_link(AuthLinkQuery {
        challenge: "challenge00000001".to_owned(),
        token: "secret-token".to_owned(),
        redirect: Some(RedirectPath::try_new("/account")?),
    })?;
    assert_eq!(
        reset.location,
        "/reset-password?challenge=challenge00000001&token=secret-token&redirect=%2Faccount"
    );
    assert_eq!(reset.set_cookie, None);
    Ok(())
}

#[tokio::test]
async fn public_link_handlers_consume_valid_challenges() -> Result<(), Box<dyn std::error::Error>> {
    let service = test_service().await?;
    let harbor = test_harbor()?;

    let signup = service
        .sign_up_with_password(harbor_core::PasswordSignUpInput {
            email: "axum-confirm@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
        })
        .await?;
    let confirmation = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::SignupConfirmation,
            delivery: ChallengeDelivery::MagicLink,
            email: signup.email.email_original,
            user_id: Some(signup.user.id),
            redirect_path: None,
        })
        .await?;
    let confirmed = handle_confirm_email_link(
        &service,
        AuthLinkQuery {
            challenge: confirmation.challenge.id.as_str().to_owned(),
            token: confirmation.secret.expose_secret().to_owned(),
            redirect: None,
        },
    )
    .await?;
    assert_eq!(confirmed.location, "/signin");
    assert_eq!(confirmed.set_cookie, None);

    let signin_challenge = service
        .create_email_challenge(harbor_core::EmailChallengeInput {
            purpose: ChallengePurpose::EmailSignIn,
            delivery: ChallengeDelivery::MagicLink,
            email: "axum-link@example.com".to_owned(),
            user_id: None,
            redirect_path: Some(RedirectPath::try_new("/account")?),
        })
        .await?;
    let signed_in = handle_email_link_signin(
        &service,
        harbor.config(),
        AuthLinkQuery {
            challenge: signin_challenge.challenge.id.as_str().to_owned(),
            token: signin_challenge.secret.expose_secret().to_owned(),
            redirect: Some(RedirectPath::try_new("/account")?),
        },
    )
    .await?;

    assert_eq!(signed_in.location, "/account");
    assert!(signed_in.set_cookie.is_some());
    Ok(())
}
