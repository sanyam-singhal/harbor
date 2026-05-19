CREATE TABLE harbor_users (
    id TEXT PRIMARY KEY,
    created_at_unix_micros INTEGER NOT NULL,
    updated_at_unix_micros INTEGER NOT NULL,
    disabled_at_unix_micros INTEGER
);

CREATE TABLE harbor_user_emails (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES harbor_users(id) ON DELETE CASCADE,
    email_original TEXT NOT NULL,
    email_canonical TEXT NOT NULL UNIQUE,
    verified_at_unix_micros INTEGER,
    is_primary INTEGER NOT NULL CHECK (is_primary IN (0, 1)),
    created_at_unix_micros INTEGER NOT NULL,
    updated_at_unix_micros INTEGER NOT NULL
);

CREATE INDEX harbor_user_emails_user_id_idx
    ON harbor_user_emails(user_id);

CREATE TABLE harbor_password_credentials (
    user_id TEXT PRIMARY KEY REFERENCES harbor_users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    password_set_at_unix_micros INTEGER NOT NULL,
    password_version INTEGER NOT NULL CHECK (password_version >= 1)
);

CREATE TABLE harbor_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES harbor_users(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    created_at_unix_micros INTEGER NOT NULL,
    last_seen_at_unix_micros INTEGER NOT NULL,
    idle_expires_at_unix_micros INTEGER NOT NULL,
    absolute_expires_at_unix_micros INTEGER NOT NULL,
    revoked_at_unix_micros INTEGER,
    ip_hash BLOB CHECK (ip_hash IS NULL OR length(ip_hash) = 32),
    user_agent_hash BLOB CHECK (user_agent_hash IS NULL OR length(user_agent_hash) = 32)
);

CREATE INDEX harbor_sessions_user_id_idx
    ON harbor_sessions(user_id);

CREATE INDEX harbor_sessions_expiry_idx
    ON harbor_sessions(idle_expires_at_unix_micros, absolute_expires_at_unix_micros);

CREATE TABLE harbor_challenges (
    id TEXT PRIMARY KEY,
    purpose TEXT NOT NULL CHECK (
        purpose IN ('signup_confirmation', 'email_sign_in', 'password_reset')
    ),
    user_id TEXT REFERENCES harbor_users(id) ON DELETE CASCADE,
    email_canonical TEXT NOT NULL,
    secret_hash BLOB NOT NULL CHECK (length(secret_hash) = 32),
    delivery TEXT NOT NULL CHECK (
        delivery IN ('magic_link', 'otp_code')
    ),
    redirect_path TEXT,
    expires_at_unix_micros INTEGER NOT NULL,
    consumed_at_unix_micros INTEGER,
    attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
    max_attempts INTEGER NOT NULL CHECK (max_attempts >= 1),
    resend_after_unix_micros INTEGER NOT NULL,
    created_at_unix_micros INTEGER NOT NULL,
    last_sent_at_unix_micros INTEGER
);

CREATE INDEX harbor_challenges_email_idx
    ON harbor_challenges(email_canonical, purpose);

CREATE INDEX harbor_challenges_expiry_idx
    ON harbor_challenges(expires_at_unix_micros);

CREATE TABLE harbor_email_deliveries (
    id TEXT PRIMARY KEY,
    challenge_id TEXT REFERENCES harbor_challenges(id) ON DELETE SET NULL,
    provider TEXT NOT NULL,
    provider_message_id TEXT,
    to_email_canonical TEXT NOT NULL,
    template TEXT NOT NULL,
    status TEXT NOT NULL,
    error_code TEXT,
    created_at_unix_micros INTEGER NOT NULL
);

CREATE INDEX harbor_email_deliveries_challenge_id_idx
    ON harbor_email_deliveries(challenge_id);

CREATE TABLE harbor_rate_limits (
    scope TEXT NOT NULL,
    key_hash BLOB NOT NULL CHECK (length(key_hash) = 32),
    window_start_unix_micros INTEGER NOT NULL,
    count INTEGER NOT NULL CHECK (count >= 0),
    PRIMARY KEY (scope, key_hash, window_start_unix_micros)
);

CREATE TABLE harbor_auth_events (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES harbor_users(id) ON DELETE SET NULL,
    email_canonical TEXT,
    kind TEXT NOT NULL CHECK (
        kind IN (
            'signup_requested',
            'email_verified',
            'sign_in_succeeded',
            'sign_in_failed',
            'password_reset_requested',
            'password_reset_completed',
            'session_revoked'
        )
    ),
    occurred_at_unix_micros INTEGER NOT NULL,
    ip_hash BLOB CHECK (ip_hash IS NULL OR length(ip_hash) = 32),
    user_agent_hash BLOB CHECK (user_agent_hash IS NULL OR length(user_agent_hash) = 32),
    detail_code TEXT
);

CREATE INDEX harbor_auth_events_user_id_idx
    ON harbor_auth_events(user_id);

CREATE INDEX harbor_auth_events_email_idx
    ON harbor_auth_events(email_canonical);
