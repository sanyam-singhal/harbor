//! Filesystem-backed test fixtures.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::TestSupportError;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

/// Isolated temporary SQLite database location.
///
/// This helper intentionally returns only paths and URLs. Store crates remain
/// responsible for connecting and migrating with their own concrete database
/// adapters, which keeps `harbor-test-support` free of SQLx dependencies.
#[derive(Debug)]
pub struct TempSqliteDatabase {
    root: PathBuf,
    database_path: PathBuf,
    database_url: String,
}

impl TempSqliteDatabase {
    /// Creates a unique filesystem-backed SQLite database URL.
    ///
    /// # Errors
    ///
    /// Returns [`TestSupportError`] when the fixture directory cannot be
    /// created or the label cannot be represented as a SQLite file URL.
    pub fn new(label: &str) -> Result<Self, TestSupportError> {
        let root = unique_temp_dir(label);
        std::fs::create_dir_all(&root)?;
        let database_path = root.join("harbor.sqlite");
        let path = database_path
            .to_str()
            .ok_or_else(|| std::io::Error::other("sqlite path is not utf-8"))?;
        let database_url = format!("sqlite://{path}?mode=rwc");
        Ok(Self {
            root,
            database_path,
            database_url,
        })
    }

    /// Returns the directory owned by this fixture.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the SQLite database file path.
    #[must_use]
    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    /// Returns a SQLx-compatible SQLite URL.
    #[must_use]
    pub fn database_url(&self) -> &str {
        &self.database_url
    }
}

impl Drop for TempSqliteDatabase {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.root);
    }
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let safe_label = safe_label(label);
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("harbor-{safe_label}-{}-{id}", std::process::id()))
}

fn safe_label(label: &str) -> String {
    let mut safe = String::new();
    for character in label.chars().take(32) {
        if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
            safe.push(character);
        } else {
            safe.push('-');
        }
    }
    if safe.is_empty() {
        safe.push_str("test");
    }
    safe
}
