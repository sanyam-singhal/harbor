//! Public API smoke tests for the Harbor facade crate.

use harbor::prelude::{
    AuthEmail, AuthEmailRenderer, ChallengeEmailInput, HarborSetupError, MailError,
    RecordingMailer, SqliteHarbor, SqliteStoreOptions,
};

#[derive(Debug, Clone)]
struct Renderer;

impl AuthEmailRenderer for Renderer {
    fn render_challenge_email(&self, input: ChallengeEmailInput) -> Result<AuthEmail, MailError> {
        harbor::email::DefaultAuthEmailRenderer::new("Harbor", "example.test")?
            .render_challenge_email(input)
    }
}

#[test]
fn sqlite_builder_is_available_from_facade() {
    let builder = SqliteHarbor::builder()
        .with_database_url("sqlite::memory:")
        .with_sqlite_options(SqliteStoreOptions::in_memory())
        .with_hmac_secret_key(vec![7; 32])
        .with_email_renderer(Renderer)
        .with_mailer(RecordingMailer::new());

    let _builder = builder;
}

#[test]
fn facade_setup_error_is_std_error() {
    fn accept_error(error: &(dyn std::error::Error + 'static)) -> String {
        error.to_string()
    }

    assert_eq!(
        accept_error(&HarborSetupError::Missing("mailer")),
        "missing Harbor setup value: mailer"
    );
}
