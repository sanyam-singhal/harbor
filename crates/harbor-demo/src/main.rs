//! Demonstration application for Harbor.

use std::env;

use harbor_email::RecordingMailer;
use harbor_leptos::{CookieDefaults, Harbor};
use harbor_sqlx::{SqliteAuthStore, SqliteStoreOptions};

const DEFAULT_DATABASE_URL: &str = "sqlite://harbor-demo.sqlite?mode=rwc";
const DEFAULT_PUBLIC_BASE_URL: &str = "http://localhost:3000";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = DemoSettings::from_env();
    let store =
        SqliteAuthStore::connect_and_migrate(&settings.database_url, SqliteStoreOptions::default())
            .await?;
    let harbor = Harbor::builder()
        .with_store(store)
        .with_mailer(RecordingMailer::new())
        .with_public_base_url(settings.public_base_url)?
        .with_cookie_defaults(CookieDefaults::development())?
        .with_hmac_secret_key(settings.hmac_key)?
        .finish()?;

    println!(
        "Harbor demo initialized: base_url={}, session_cookie={}",
        harbor.config().public_base_url(),
        harbor
            .config()
            .cookie_defaults()
            .session_cookie_name()
            .as_str()
    );
    println!("Demo mail mode: recording");
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DemoSettings {
    database_url: String,
    public_base_url: String,
    hmac_key: Vec<u8>,
}

impl DemoSettings {
    fn from_env() -> Self {
        Self {
            database_url: env::var("HARBOR_DATABASE_URL")
                .unwrap_or_else(|_error| DEFAULT_DATABASE_URL.to_owned()),
            public_base_url: env::var("HARBOR_PUBLIC_BASE_URL")
                .unwrap_or_else(|_error| DEFAULT_PUBLIC_BASE_URL.to_owned()),
            hmac_key: env::var("HARBOR_HMAC_KEY")
                .map(|value| value.into_bytes())
                .unwrap_or_else(|_error| vec![42; 32]),
        }
    }
}
