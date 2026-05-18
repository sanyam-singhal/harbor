# Harbor v0.1 Email Auth Implementation Plan

Status: planning document  
Date: 2026-05-18  
Product name: Harbor  
Initial showcase domain: `issuecertificate.com`  
Initial email provider: Resend, using `RESEND_API_KEY` from `.env` or deployment secrets

## 1. Goal

Harbor v0.1 is a lean, standards-aware authentication framework for Leptos
0.8.x applications. It should feel like Better Auth in ergonomics, but be
native to Rust, Leptos, Axum, and SQLx.

The v0.1 scope is intentionally narrow:

- Email and password signup, signin, signout.
- Email signup confirmation.
- Email-based password reset.
- Email code and magic-link signup/signin.
- Server-side sessions in HttpOnly cookies.
- SQLx storage, with SQLite implemented first and PostgreSQL/MySQL prepared by
  trait boundaries and schema discipline.
- Resend integration for transactional auth email.
- Leptos 0.8.x integration across CSR, SSR, SSR plus hydrate, and islands.

The non-goal for v0.1 is broad provider coverage. OAuth, passkeys, MFA,
organizations, roles, invitations, account linking, WebAuthn, device management,
and admin consoles come later after the foundation has proved itself.

## 2. Current Source Truths

These references were checked on 2026-05-18 and should be rechecked before each
implementation phase that depends on them.

### Leptos and Axum

- `leptos` latest is `0.8.19` and declares `rust-version = 1.88`; its features
  include `csr`, `hydrate`, `ssr`, `islands`, `islands-router`, `rustls`, and
  `tracing`: https://crates.io/crates/leptos/0.8.19
- Leptos server functions default to POST form-compatible input and JSON output,
  and can use custom errors: https://book.leptos.dev/server/25_server_functions.html
- `leptos_axum` latest is `0.8.9`; `handle_server_fns` mounts server functions
  under routes such as `/api/*fn_name`: https://docs.rs/leptos_axum/latest/leptos_axum/fn.handle_server_fns.html
- Leptos Axum extractors can access headers, cookies, pools, and state inside
  server functions; generic server functions are not directly supported, so
  generic inner functions plus concrete wrappers are the path:
  https://book.leptos.dev/server/26_extractors.html
- `ResponseOptions` can set status and response headers, including
  `Set-Cookie`; `leptos_axum::redirect` works with progressively enhanced
  `<ActionForm/>`: https://book.leptos.dev/server/27_response.html
- `<ActionForm/>` turns a server action into a progressively enhanced HTML form
  and only works with default URL encoding: https://docs.rs/leptos/latest/leptos/form/fn.ActionForm.html
- Leptos islands make `#[component]` server-only by default under the `islands`
  feature and opt specific interactive surfaces into WASM with `#[island]`:
  https://book.leptos.dev/islands.html

### SQLx

- Stable SQLx is `0.8.6`; crates.io also lists `0.9.0-alpha.1`, but Harbor v0.1
  should use stable `0.8.6` unless the project intentionally opts into alpha:
  https://crates.io/crates/sqlx/0.8.6
- SQLx supports PostgreSQL, MySQL/MariaDB, and SQLite, plus pooling and
  migrations: https://docs.rs/crate/sqlx/0.8.6
- SQLx query macros bind a query to the database used at compile time; a query
  checked against PostgreSQL cannot simply run against MySQL or SQLite:
  https://docs.rs/sqlx/latest/sqlx/macro.query.html
- `sqlx::migrate!` embeds migrations; stable Rust needs a build script or
  equivalent rerun hint when migrations change:
  https://docs.rs/sqlx/latest/sqlx/macro.migrate.html

### Resend

- Resend REST API base URL is `https://api.resend.com`, authenticated by
  `Authorization: Bearer re_xxxxxxxxx`: https://www.resend.com/docs/api-reference/introduction
- Resend default API rate limit is 2 requests per second, with 429 on excess:
  https://www.resend.com/docs/api-reference/introduction
- Resend domain verification requires SPF and DKIM, with DMARC recommended:
  https://resend.com/docs/dashboard/domains/introduction
- Resend's official Rust SDK is `resend-rs 0.25.1`; default feature is
  `native-tls`, and `rustls-tls` is available:
  https://crates.io/crates/resend-rs/0.25.1

### Security Standards

- NIST SP 800-63B-4 requires single-factor passwords to be at least 15
  characters, recommends allowing at least 64 characters, disallows composition
  rules, disallows periodic password changes, and requires rate limiting:
  https://pages.nist.gov/800-63-4/sp800-63b.html
- NIST SP 800-63B-4 says email must not be used as out-of-band authentication;
  confirmation codes for validating email addresses and recovery codes are not
  affected by that prohibition:
  https://pages.nist.gov/800-63-4/sp800-63b.html
- OWASP Password Storage recommends Argon2id and lists equivalent minimum
  parameter sets, including `m=19456 KiB, t=2, p=1`:
  https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- OWASP Session Management requires secure transport, `Secure`, `HttpOnly`,
  explicit `SameSite=Strict` or `Lax`, and recommends `__Host-` cookie names for
  session identifiers:
  https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP Forgot Password requires consistent responses, uniform timing, safe
  random tokens, secure storage, single use, expiry, rate limiting, HTTPS reset
  URLs, no reliance on `Host`, `Referrer-Policy: no-referrer`, and no automatic
  login after password reset:
  https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
- OWASP CSRF guidance says SameSite should be defense-in-depth and should be
  combined with CSRF tokens or signed double-submit patterns when needed:
  https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

## 3. Product Positioning

Harbor should be:

- Leptos-first: forms, server functions, SSR context, and islands should feel
  native rather than bolted on.
- Server-session first: use opaque, server-side session IDs in HttpOnly cookies,
  not browser-local JWTs or localStorage.
- Database-portable by contract: SQLite first, PostgreSQL/MySQL later, with
  store traits and contract tests preventing driver-specific leakage.
- Dependency-light: every dependency needs an explicit reason and feature flags.
- Security-honest: email OTP and magic links are convenient email-possession
  signin mechanisms, not NIST out-of-band authenticators, not MFA, and not
  phishing-resistant.
- Extensible later: the core model should leave room for passkeys, OAuth,
  multiple emails per user, organizations, admin events, and account linking.

## 4. Dependency Posture

### Initial runtime dependencies

Use these only after confirming exact versions and feature flags during the
workspace setup commit.

- `leptos = 0.8.19`: required for Leptos integration crates and demo.
- `leptos_axum = 0.8.9`: required for Axum SSR/server functions.
- `axum = 0.8.9`: demo server and lower-level link routes.
- `tokio = 1.x`: Axum and SQLx runtime.
- `sqlx = 0.8.6`: database interface, migrations, SQLite first.
- `argon2 = 0.5.3`: stable Argon2id password hashing; avoid `0.6.0-rc.*` in
  v0.1 unless there is a documented reason.
- `thiserror = 2.x`: typed errors.
- `serde = 1.x`: Leptos server functions and config types.
- `time = 0.3.x`: explicit UTC timestamps and expiry math.
- `cookie = 0.18.1`: correct cookie construction and parsing.
- `getrandom = 0.3.x`: OS randomness for session tokens and challenge secrets.
- `hmac = 0.12.x`, `sha2 = 0.10.x`, `subtle = 2.x`: keyed challenge hashing,
  high-entropy token hashing, and constant-time comparisons.
- `resend-rs = 0.25.1`, optional feature `email-resend`, with
  `default-features = false` and `features = ["rustls-tls"]` if compatible.
- `tracing = 0.1.x`, optional or server-only: structured operational events
  without leaking secrets.

### Test and dev dependencies

- `proptest`: adversarial validation of email normalization, token parsing,
  callback path allowlisting, and rate-limit windows.
- `tempfile`: isolated SQLite test databases.
- `tower`/`tower-http` only if required by Axum test harnesses and static file
  serving.

### Dependencies to avoid in v0.1 unless justified

- Full ORM layers.
- JWT libraries.
- Generic email abstraction crates that pull multiple providers.
- `async-trait`, unless we need object-safe dynamic dispatch. Prefer public
  traits returning `impl Future<...> + Send` or concrete generic services.
- `uuid`, unless we decide ID readability is worth the extra dependency.
  Random 128-bit or 192-bit IDs can be generated and hex-encoded internally.
- `chrono`; prefer `time`.
- `validator` or large validation stacks; implement narrow validated newtypes.

## 5. Architecture

### Workspace layout

```text
Cargo.toml
Cargo.lock
crates/
  harbor-core/
  harbor-sqlx/
  harbor-email/
  harbor-leptos/
  harbor-demo/
  harbor-test-support/
docs/
  security/
  decisions/
scripts/
```

### Crate responsibilities

`harbor-core`

- Domain newtypes: `UserId`, `EmailAddress`, `CanonicalEmail`,
  `SessionId`, `ChallengeId`, `TokenHash`, `UnixTimestampMicros`,
  `RetryBudget`, `RedirectPath`.
- Typed errors and public result types.
- Password policy and password hashing contracts.
- Challenge and session service logic.
- Store traits.
- Email traits and message models.
- Rate-limit contracts.
- No Leptos, no Axum, no SQLx, no Resend.

`harbor-sqlx`

- SQLx-backed `AuthStore` implementations.
- SQLite implementation in v0.1.
- Portable migration design and SQLite migrations.
- Store contract test harnesses shared across future drivers.
- No Leptos UI.

`harbor-email`

- `Mailer` trait implementations.
- `ResendMailer` behind `email-resend`.
- Template rendering using plain Rust strings and HTML escaping helpers, not a
  templating dependency in v0.1.
- Test mailer and outbox recorder for local tests.

`harbor-leptos`

- Leptos components, actions, resources, and server function wrappers.
- Axum integration helpers.
- Cookie extraction/set helpers.
- CSRF form helpers.
- Route guards and session context.
- No SQL queries directly.

`harbor-demo`

- Leptos app showcasing Harbor on `issuecertificate.com`.
- SQLite local database.
- Resend configured by env.
- Minimal pages: home, signup, verify email, signin, email code, forgot
  password, reset password, account, signout.

`harbor-test-support`

- SQLite temp DB fixtures.
- Fake mailer.
- Test clock.
- Deterministic token generator for tests only.
- Contract test macros/functions.

## 6. Core Design

### IDs and tokens

- Use opaque random IDs, not sequential IDs.
- User IDs: random 128-bit hex string or 192-bit hex string.
- Session tokens: at least 256 bits from OS randomness.
- URL tokens: at least 256 bits from OS randomness.
- Numeric OTP codes: default 8 digits for v0.1. Six digits are common, but 8
  digits gives more margin while still being usable. Make it configurable with
  explicit lower bound and throttling.
- Store only hashes of presented secrets:
  - High-entropy URL/session tokens: SHA-256 is acceptable because tokens are
    random and large; HMAC-SHA256 with `HARBOR_SECRET_KEY` is better and should
    be the default for consistency.
  - Low-entropy OTP codes: HMAC-SHA256 with `HARBOR_SECRET_KEY` is required.
- Compare hashes with constant-time equality.

### Password policy

Default v0.1 policy:

- Minimum length: 15 Unicode scalar values for single-factor password signin.
- Maximum accepted length: 1024 bytes after normalization to avoid long password
  denial of service while exceeding NIST's recommended 64-character allowance.
- No composition rules.
- No periodic password rotation.
- Permit paste and password managers in demo UI.
- Apply Unicode NFC normalization if we add a small normalization dependency.
  If we avoid that dependency in v0.1, document that passwords are byte-exact
  UTF-8 and revisit before publishing as a library.
- Include a tiny local blocklist for obviously compromised/common values, then
  expose a `PasswordBlocklist` trait for applications to inject stronger checks.
- Hash with Argon2id, default parameters `m=19456 KiB, t=2, p=1`, configurable
  upward.
- Store PHC strings, not custom hash fields.
- On signin, detect old parameter sets and schedule rehash after successful
  verification.

### Email challenges

Use one challenge engine for:

- Signup confirmation.
- Email magic link signin.
- Email OTP code signin.
- Password reset.

Challenge fields:

- `challenge_id`
- `purpose`
- `user_id` nullable
- `email_canonical`
- `secret_hash`
- `secret_delivery` enum: `MagicLink`, `OtpCode`, or `Both`
- `expires_at`
- `consumed_at`
- `attempt_count`
- `max_attempts`
- `resend_after`
- `created_at`
- `last_sent_at`
- `redirect_path` nullable, validated relative path only

Default lifetimes:

- Signup confirmation: 30 minutes.
- Email signin code/link: 10 minutes.
- Password reset: 15 minutes.
- Resend cooldown: 60 seconds.
- Max verification attempts per challenge: 5 for OTP, 10 for URL token
  verification endpoint abuse.

Security behavior:

- All challenge request responses are enumeration-resistant.
- Password reset never creates a session automatically.
- Magic link verification creates a session only after consuming the challenge.
- Verification links redirect to clean URLs after use so tokens leave the
  address bar.
- Token pages set `Referrer-Policy: no-referrer`.
- All callback paths must be relative paths or match an explicit allowlist.
  Never build links from the request `Host` header.

### Sessions

Session model:

- Server-side session row plus opaque cookie.
- Cookie value is the raw random session token or a compact token containing a
  public session id plus secret. The database stores only a hash.
- Session row includes `user_id`, token hash, created time, last seen time,
  idle expiry, absolute expiry, revoked time, and hashed request metadata.

Cookie defaults:

- Production name: `__Host-harbor_session`.
- `Secure = true`.
- `HttpOnly = true`.
- `SameSite = Lax` by default for ergonomic top-level navigation, configurable
  to `Strict`.
- `Path = /`.
- No `Domain` attribute.
- No localStorage/sessionStorage token storage.
- Development mode may use a non-`__Host-` name only when explicitly configured
  for non-HTTPS localhost.

Default expiry:

- Idle timeout: 12 hours.
- Absolute timeout: 30 days.
- Rotate token on signin and after sensitive transitions.
- Revoke all existing sessions after password reset by default, with future
  config for user choice.

### CSRF

Because Harbor uses cookies and HTML forms, v0.1 should implement CSRF defense
instead of relying only on SameSite.

Default:

- State-changing forms include a hidden CSRF token.
- Token is bound to the current anonymous or authenticated browser session.
- Signed double-submit or synchronizer token pattern, chosen during
  implementation after checking how cleanly it fits Leptos SSR and ActionForm.
- CSRF failures are typed, logged without secrets, and return user-safe errors.

Special cases:

- Email verification GET routes may consume high-entropy one-time URL tokens,
  but must not perform arbitrary state changes beyond the token's purpose.
- Signout should support POST with CSRF. A GET signout link is not included in
  v0.1.

## 7. Database Schema Plan

SQLite v0.1 should use portable SQL types and constraints that can map cleanly
to PostgreSQL and MySQL.

### Tables

`harbor_users`

- `id TEXT PRIMARY KEY`
- `created_at_unix_micros INTEGER NOT NULL`
- `updated_at_unix_micros INTEGER NOT NULL`
- `disabled_at_unix_micros INTEGER NULL`

`harbor_user_emails`

- `id TEXT PRIMARY KEY`
- `user_id TEXT NOT NULL REFERENCES harbor_users(id)`
- `email_original TEXT NOT NULL`
- `email_canonical TEXT NOT NULL UNIQUE`
- `verified_at_unix_micros INTEGER NULL`
- `is_primary INTEGER NOT NULL`
- `created_at_unix_micros INTEGER NOT NULL`
- `updated_at_unix_micros INTEGER NOT NULL`

`harbor_password_credentials`

- `user_id TEXT PRIMARY KEY REFERENCES harbor_users(id)`
- `password_hash TEXT NOT NULL`
- `password_set_at_unix_micros INTEGER NOT NULL`
- `password_version INTEGER NOT NULL`

`harbor_sessions`

- `id TEXT PRIMARY KEY`
- `user_id TEXT NOT NULL REFERENCES harbor_users(id)`
- `token_hash BLOB NOT NULL UNIQUE`
- `created_at_unix_micros INTEGER NOT NULL`
- `last_seen_at_unix_micros INTEGER NOT NULL`
- `idle_expires_at_unix_micros INTEGER NOT NULL`
- `absolute_expires_at_unix_micros INTEGER NOT NULL`
- `revoked_at_unix_micros INTEGER NULL`
- `ip_hash BLOB NULL`
- `user_agent_hash BLOB NULL`

`harbor_challenges`

- `id TEXT PRIMARY KEY`
- `purpose TEXT NOT NULL`
- `user_id TEXT NULL REFERENCES harbor_users(id)`
- `email_canonical TEXT NOT NULL`
- `secret_hash BLOB NOT NULL`
- `delivery TEXT NOT NULL`
- `redirect_path TEXT NULL`
- `expires_at_unix_micros INTEGER NOT NULL`
- `consumed_at_unix_micros INTEGER NULL`
- `attempt_count INTEGER NOT NULL`
- `max_attempts INTEGER NOT NULL`
- `resend_after_unix_micros INTEGER NOT NULL`
- `created_at_unix_micros INTEGER NOT NULL`
- `last_sent_at_unix_micros INTEGER NULL`

`harbor_email_deliveries`

- `id TEXT PRIMARY KEY`
- `challenge_id TEXT NULL REFERENCES harbor_challenges(id)`
- `provider TEXT NOT NULL`
- `provider_message_id TEXT NULL`
- `to_email_canonical TEXT NOT NULL`
- `template TEXT NOT NULL`
- `status TEXT NOT NULL`
- `error_code TEXT NULL`
- `created_at_unix_micros INTEGER NOT NULL`

`harbor_rate_limits`

- `scope TEXT NOT NULL`
- `key_hash BLOB NOT NULL`
- `window_start_unix_micros INTEGER NOT NULL`
- `count INTEGER NOT NULL`
- `PRIMARY KEY(scope, key_hash, window_start_unix_micros)`

`harbor_auth_events`

- `id TEXT PRIMARY KEY`
- `user_id TEXT NULL REFERENCES harbor_users(id)`
- `email_canonical TEXT NULL`
- `kind TEXT NOT NULL`
- `occurred_at_unix_micros INTEGER NOT NULL`
- `ip_hash BLOB NULL`
- `user_agent_hash BLOB NULL`
- `detail_code TEXT NULL`

### SQLite settings

- Enable foreign keys on every connection.
- Use WAL for local dev if compatible with SQLx settings.
- Keep a bounded pool and document SQLite's single-writer behavior.
- Avoid SQLite-only behavior in core logic.

### Multi-database strategy

- Do not pretend SQLx macros are portable across all databases. SQLx documents
  that checked query macros bind to a database type.
- Define store traits in `harbor-core`.
- Implement `SqliteAuthStore` first.
- Add `PostgresAuthStore` and `MysqlAuthStore` later as separate modules with
  their own migrations and query tests.
- Shared store contract tests should exercise every implementation:
  signup, duplicate email, password verification, token consumption,
  session expiry, revocation, rate-limit boundaries, and transaction rollback.
- Keep public APIs insulated from SQLx types except in `harbor-sqlx`.

## 8. Store and Service Traits

Avoid object-safety pressure in v0.1. Use generic services:

```rust
pub struct Harbor<S, M, C> {
    store: S,
    mailer: M,
    clock: C,
    config: HarborConfig,
}
```

Public traits should avoid `async fn` if the lint makes public futures
ambiguous. Prefer:

```rust
use core::future::Future;

pub trait AuthStore: Clone + Send + Sync + 'static {
    fn create_user_with_email(
        &self,
        input: CreateUserInput,
    ) -> impl Future<Output = Result<CreateUserOutput, StoreError>> + Send;
}
```

Trait groups:

- `UserStore`
- `PasswordCredentialStore`
- `ChallengeStore`
- `SessionStore`
- `RateLimitStore`
- `AuthEventStore`
- Composite `AuthStore`

Service layer:

- `AuthService<S, M, C>`
- `PasswordService`
- `ChallengeService`
- `SessionService`
- `RateLimiter`
- `EmailVerificationService`

The service layer owns transaction boundaries. Store methods should expose
transactional helpers where needed, especially for:

- Create unverified user plus password credential plus signup challenge.
- Consume challenge plus verify email plus create session.
- Reset password plus revoke sessions plus audit event.

## 9. Email Integration

### Mailer trait

```rust
pub trait Mailer: Clone + Send + Sync + 'static {
    fn send_auth_email(
        &self,
        message: AuthEmail,
    ) -> impl Future<Output = Result<EmailDelivery, MailError>> + Send;
}
```

Email templates:

- Signup confirmation.
- Email signin code/link.
- Password reset.
- Password changed notification.

Template requirements:

- Plain text and HTML bodies.
- No secrets in logs.
- Links built from `HarborConfig.public_base_url`, never from request host.
- Default sender from env, for example
  `HARBOR_EMAIL_FROM="Harbor <auth@issuecertificate.com>"`.
- Resend API key from `RESEND_API_KEY`.
- Resend 429 is handled as retryable provider error, but v0.1 should not build
  a background retry queue unless needed. User-facing auth flows should fail
  closed if email cannot be sent.

Resend local/dev behavior:

- In tests, use `RecordingMailer`, not Resend.
- In demo dev, allow `HARBOR_EMAIL_MODE=log` or `HARBOR_EMAIL_MODE=resend`.
- Before live sending, verify Resend domain alignment with the configured From
  domain to avoid 403 domain mismatch.

## 10. Leptos Integration

### Server context

Harbor should provide a cloneable app context:

```rust
pub struct HarborLeptosContext<S, M, C> {
    pub harbor: Harbor<S, M, C>,
}
```

In Axum SSR:

- Provide context through `leptos_routes_with_context`.
- Provide the same concrete app state through Axum state where extractors need
  it.
- Server functions should be concrete wrappers that call generic inner service
  functions, because Leptos server functions do not support generic parameters.

### Session loading

Expose:

- `current_user() -> Result<Option<UserSession>, AuthError>`
- `require_user() -> Result<UserSession, AuthError>`
- `<Authenticated/>`
- `<Unauthenticated/>`
- `use_session_resource()`
- `SessionProvider` for hydrate/CSR mode.

SSR:

- Read cookie during render.
- Load session from store.
- Provide session context to components.

Hydrate:

- Serialize only non-secret session view: user id, canonical email, verification
  status.
- Never serialize session token or challenge tokens.

CSR:

- Fetch current session via server function/API.
- Mutations use server functions and cookies.
- No token in localStorage.

Islands:

- Keep most auth pages server-rendered.
- Use small islands only for pending state, password visibility toggles,
  resend countdown, and inline form validation.
- Avoid pulling `harbor-core` server-only code into WASM by splitting
  server-only modules behind `ssr`.

### Routes and server functions

Leptos pages:

- `/signup`
- `/signin`
- `/signin/email`
- `/verify-email`
- `/forgot-password`
- `/reset-password`
- `/account`

GET link routes handled by Axum or Leptos server route:

- `/auth/confirm-email?challenge=...&token=...`
- `/auth/email-link?challenge=...&token=...`
- `/auth/reset-password?challenge=...&token=...`

Server functions:

- `signup_with_password(email, password, redirect_path)`
- `signin_with_password(email, password, redirect_path)`
- `request_email_signin(email, redirect_path)`
- `verify_email_code(challenge_id, code)`
- `request_password_reset(email)`
- `reset_password(challenge_id, token_or_code, new_password)`
- `resend_challenge(challenge_id)`
- `sign_out()`
- `current_session()`

All state-changing server functions:

- Validate CSRF.
- Apply rate limits.
- Use typed inputs and validated newtypes.
- Return enumeration-resistant messages where appropriate.

## 11. Public API Ergonomics

Target server setup:

```rust
let harbor = Harbor::builder()
    .with_store(SqliteAuthStore::new(pool.clone()))
    .with_mailer(ResendMailer::from_env()?)
    .with_public_base_url("https://issuecertificate.com".parse()?)
    .with_cookie_defaults(CookieDefaults::production())
    .finish()?;
```

Target Leptos route usage:

```rust
view! {
    <HarborProvider>
        <Routes fallback=|| view! { <NotFound/> }>
            <Route path=path!("/signin") view=SignInPage/>
            <ProtectedRoute path=path!("/account") view=AccountPage/>
        </Routes>
    </HarborProvider>
}
```

Target form usage:

```rust
view! {
    <PasswordSignInForm
        redirect_path="/account"
        show_email_link_option=true
    />
}
```

Builder constraints:

- Invalid config fails at startup.
- Secrets are represented by redacted debug types.
- Durations, byte sizes, retry budgets, and URLs are typed.
- Defaults are documented in rustdoc.

## 12. Security Decisions for v0.1

1. Email OTP and magic link are single-factor email-possession signin methods,
   not MFA. Harbor docs must say this plainly.
2. Password signin requires verified email by default.
3. Signup with password creates an unverified user and sends confirmation.
4. Email link/code signin may create a user only after email challenge
   verification.
5. Password reset does not automatically sign in.
6. Sessions are server-side opaque tokens in HttpOnly cookies.
7. No JWTs in v0.1.
8. No localStorage/sessionStorage auth tokens.
9. All challenge and session secrets are hashed before storage.
10. All auth flows are rate limited by canonical email and request fingerprint.
11. Auth responses avoid account enumeration.
12. Redirects use relative paths or an explicit allowlist.
13. All public APIs document errors and panics.
14. No unsafe code in Harbor crates.

## 13. Testing Strategy

Unit tests:

- Newtype validation.
- Email canonicalization.
- Redirect path allowlisting.
- Password policy boundaries.
- Token generation length and parsing.
- Cookie construction.
- CSRF token validation.
- Error redaction.

Store contract tests:

- Duplicate canonical email rejection.
- Unverified password signup.
- Email verification token single use.
- OTP max attempts.
- Expired challenge rejection.
- Session create/load/revoke/expire.
- Password reset revokes sessions.
- Rate-limit windows.
- Transaction rollback on mid-flow failure.

Integration tests:

- Axum plus Leptos server function happy paths.
- `<ActionForm/>` no-WASM form submissions where practical.
- Cookie set/delete headers.
- Referrer policy on token pages.
- Resend fake mailer captures correct links and templates.

Property tests:

- Arbitrary email-ish strings normalize or reject consistently.
- Arbitrary callback strings cannot escape allowed origin.
- Token parser rejects malformed input.
- Rate limiter never permits above configured limit within a window.

Coverage/stress:

- Use `cargo llvm-cov` after meaningful implementation exists.
- Mutation testing later, at the v0.1 release candidate boundary.
- No Loom in v0.1 unless we introduce concurrency-critical shared state.

## 14. Commit-by-Commit Roadmap

Each step below should be one coherent commit. Every commit should leave the
repository shippable according to the local check level appropriate for that
stage.

### Commit 1: Add workspace skeleton

- Create workspace `Cargo.toml`.
- Add crates: `harbor-core`, `harbor-sqlx`, `harbor-email`,
  `harbor-leptos`, `harbor-demo`, `harbor-test-support`.
- Add workspace lints from `AGENTS.md`.
- Add `unsafe_code = "forbid"`.
- Add initial `README.md`.
- Check: `cargo fmt --all --check`, `cargo check --workspace`.

### Commit 2: Add scripts check ladder

- Add `scripts/check-dev.sh`.
- Add `scripts/check-test.sh`.
- Add `scripts/check.sh`.
- Add `scripts/coverage-report.sh`.
- Add `scripts/read-source-lines.sh`.
- Add `scripts/read-rust-slice.sh`.
- Add `scripts/count-lines.sh`.
- Keep scripts boring and POSIX-shell compatible.
- Check: run `scripts/check-dev.sh`.

### Commit 3: Document architectural decisions

- Add `docs/decisions/0001-v0-1-scope.md`.
- Add `docs/security/email-auth-assurance.md`, explicitly covering NIST's email
  out-of-band prohibition and Harbor's v0.1 assurance claims.
- Add `docs/security/session-cookie-policy.md`.
- Check: docs spell out source links and defaults.

### Commit 4: Add core domain newtypes

- Implement IDs, timestamps, retry budgets, redirect paths, email wrapper types.
- Keep constructors validating.
- Redact secrets in `Debug`.
- Add rustdoc for public APIs.
- Tests: valid/invalid constructors and display/debug behavior.

### Commit 5: Add clock and randomness ports

- Add `Clock` trait and `SystemClock`.
- Add `SecretGenerator` or narrow functions for random IDs, session tokens,
  URL tokens, and OTP codes.
- Add deterministic test generator in `harbor-test-support`.
- Tests: length, character set, OTP range, no modulo bias where applicable.

### Commit 6: Add password policy and hashing

- Add `PasswordPolicy`.
- Add Argon2id hasher with PHC output.
- Add parameter config and rehash detection.
- Add common-password blocklist trait with tiny default list.
- Tests: min length, max bytes, blocklist, verify, wrong password, rehash flag.

### Commit 7: Add secret hashing utilities

- Add HMAC-SHA256 token hashing with redacted secret key type.
- Add constant-time comparison wrappers.
- Add `HARBOR_SECRET_KEY` config validation requirements.
- Tests: stable hashes, different contexts differ, constant-time compare API.

### Commit 8: Add core error model

- Add `AuthError`, `StoreError`, `MailError`, `ConfigError`.
- Separate internal causes from user-facing messages.
- Add `# Errors` docs on fallible public APIs.
- Tests: redaction and conversions.

### Commit 9: Add store traits

- Define user, email, password, challenge, session, event, and rate-limit store
  traits.
- Use public trait methods returning `impl Future + Send`.
- Add input/output structs.
- Add docs for transaction expectations.
- Check: clippy with denied warnings.

### Commit 10: Add SQLite migrations

- Add `harbor-sqlx/migrations/sqlite`.
- Include all v0.1 tables and indexes.
- Add migration build rerun handling.
- Add docs for SQLite foreign keys and WAL settings.
- Check: migration applies to temp SQLite database.

### Commit 11: Implement SQLite connection setup

- Add `SqliteAuthStore`.
- Configure pool bounds, foreign keys, busy timeout, and WAL where appropriate.
- Add migration runner.
- Tests: open temp DB, migrate, close.

### Commit 12: Implement SQLite user/email/password stores

- Create user with email.
- Fetch by canonical email.
- Mark email verified.
- Store/update password credential.
- Enforce duplicate email.
- Tests: duplicate email and verification transitions.

### Commit 13: Implement SQLite challenge store

- Create challenge.
- Fetch active challenge.
- Increment attempts.
- Consume atomically.
- Enforce expiry and max attempts in service layer with store support.
- Tests: single use, expired, exhausted attempts.

### Commit 14: Implement SQLite session store

- Create session.
- Load by token hash.
- Update last seen with bounded frequency.
- Revoke one session.
- Revoke all sessions for user.
- Delete expired sessions.
- Tests: load, expiry, revocation.

### Commit 15: Implement SQLite rate limits and events

- Add fixed-window rate limiter store.
- Add auth event append.
- Hash IP/user-agent metadata before storing.
- Tests: window boundaries and no raw IP/user-agent persistence.

### Commit 16: Add store contract tests

- Move behavioral tests into shared contract functions.
- Run the full contract against `SqliteAuthStore`.
- This becomes the future acceptance suite for PostgreSQL/MySQL.

### Commit 17: Add core auth services

- Implement password signup.
- Implement password signin.
- Implement signout/session revocation.
- Implement current session loading.
- Tests: happy, invalid, unverified email, disabled user, rate limited.

### Commit 18: Add email challenge services

- Implement signup confirmation challenge.
- Implement email link/code signin challenge.
- Implement challenge resend.
- Implement consume challenge.
- Tests: enumeration-resistant request, single use, redirect validation.

### Commit 19: Add password reset service

- Request reset with consistent response.
- Reset password after valid challenge.
- Revoke existing sessions.
- Send password changed notification.
- Do not create a new session automatically.
- Tests: existing and non-existing email timing strategy, session revocation.

### Commit 20: Add mailer trait and recording mailer

- Add `AuthEmail` model.
- Add HTML/text templates.
- Add `RecordingMailer`.
- Tests: template contains expected link, no secret in debug/log values.

### Commit 21: Add Resend mailer

- Add `email-resend` feature.
- Implement `ResendMailer`.
- Configure API key, From address, provider timeout, and provider rate handling.
- Store provider message id when available.
- Tests: use mock/fake client boundary if possible; no live Resend in tests.
- Check: `cargo tree` and document dependency cost.

### Commit 22: Add Harbor config builder

- Add validated `HarborConfig`.
- Add `Harbor::builder`.
- Validate public base URL, secret key length, cookie policy, rate limits,
  challenge lifetimes, password policy, and Resend config.
- Tests: invalid config fails at startup.

### Commit 23: Add Leptos server context

- Add `HarborLeptosContext`.
- Add helpers to provide and expect context.
- Add current session extraction from cookies.
- Add response cookie setting/deletion.
- Tests: cookie parse/set/delete header values.

### Commit 24: Add CSRF integration

- Add CSRF token issue/verify helpers.
- Add hidden form token component.
- Validate in server functions.
- Tests: missing, malformed, wrong session, expired, valid.

### Commit 25: Add Leptos server functions

- Add concrete server function wrappers for signup, signin, email challenge,
  password reset, current session, and signout.
- Keep generic logic in inner functions.
- Use typed errors and user-safe messages.
- Check: `<ActionForm/>` compatibility with default URL encoding.

### Commit 26: Add Leptos components

- Add `PasswordSignUpForm`.
- Add `PasswordSignInForm`.
- Add `EmailCodeSignInForm`.
- Add `ForgotPasswordForm`.
- Add `ResetPasswordForm`.
- Add `SignOutForm`.
- Add `Authenticated` and `Unauthenticated`.
- Tests: component compile under `ssr`, `hydrate`, `csr`, and `islands` feature
  sets where feasible.

### Commit 27: Add Axum link routes

- Add GET handlers for confirm email, email link signin, and reset password
  landing.
- Consume only high-entropy URL tokens on GET.
- Redirect to clean relative path.
- Set `Referrer-Policy: no-referrer`.
- Tests: token not left in final redirect; invalid token is safe.

### Commit 28: Add demo app foundation

- Add `harbor-demo` Leptos app.
- Configure SQLite dev database.
- Configure env loading without logging secrets.
- Add base pages and navigation.
- Add HTTPS/proxy deployment notes for `issuecertificate.com`.
- Check: run locally.

### Commit 29: Wire demo auth flows

- Add signup, verify, signin, email code/link, forgot/reset, account, signout.
- Use Resend only when explicitly configured.
- Use recording/log mailer for local tests.
- Check: manual local flow with SQLite.

### Commit 30: Add integration tests for demo server

- Test password signup through verification.
- Test password signin.
- Test email link signin.
- Test OTP signin.
- Test forgot/reset.
- Test signout.
- Assert cookies and redirects.

### Commit 31: Add documentation for application developers

- Add quickstart for Leptos Axum.
- Add config reference.
- Add security model.
- Add email provider setup with Resend and `issuecertificate.com`.
- Add SQLite dev setup.
- Add "what v0.1 does not claim" section.

### Commit 32: Run closure gate and trim

- Run `cargo fmt --all --check`.
- Run `cargo check --workspace --all-targets --all-features`.
- Run `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- Run rustdoc with denied warnings.
- Run tests.
- Run coverage report.
- Inspect dependency tree.
- Inspect source line counts.
- Update docs for any changed defaults.

## 15. Future Extraction Targets

These are pattern sources to study, not dependencies to add by default.

- Better Auth: ergonomic API, email/password core, magic link plugin,
  callbacks, session access patterns. Source docs:
  https://better-auth.com/docs/basic-usage and
  https://better-auth.com/docs/plugins/magic-link
- `tower-sessions`: session architecture as cookie pointer plus server-side
  store, pluggable persistence, and cookie security language:
  https://docs.rs/tower-sessions
- `axum-login`: generic backend and user traits for Axum auth ergonomics:
  https://docs.rs/axum-login/latest/axum_login/
- `sqlx-sqlite-conn-mgr`: SQLite single-writer/WAL connection policy ideas,
  not a v0.1 dependency:
  https://docs.rs/crate/sqlx-sqlite-conn-mgr/0.8.6

Extraction rule:

- Copy concepts only after reading licenses.
- Do not copy code without preserving license obligations.
- Prefer writing narrow Harbor-native code that matches our invariants.

## 16. Open Questions Before Implementation

1. Should password Unicode normalization add a dependency in v0.1, or should
   Harbor document byte-exact UTF-8 password handling until v0.2?
2. Should session cookies default to `SameSite=Lax` for ergonomics or `Strict`
   for maximum default hardening? Current plan: Lax default, Strict configurable.
3. Should dev mode rely on Secure cookies on localhost or use an explicit
   non-`__Host-` dev cookie name? Current plan: support both with loud config.
4. Should v0.1 expose both magic link and numeric OTP in the public API, or use
   one "email challenge" API that applications render either way? Current plan:
   one challenge engine, both public components.
5. Should Resend be implemented through `resend-rs`, or through a tiny direct
   REST client if the SDK dependency tree is too large? Current plan: try
   official SDK behind a feature, inspect `cargo tree`, then decide.

## 17. Done Definition for v0.1

Harbor v0.1 is ready when:

- The demo runs on local SQLite.
- The demo can send real Resend auth emails from the configured
  `issuecertificate.com` sender.
- Password signup, email confirmation, password signin, email code/link signin,
  forgot password, reset password, current session, and signout all work.
- No auth token is stored in localStorage/sessionStorage.
- Session cookies are HttpOnly, Secure in production, SameSite explicit, and
  host-scoped.
- Password reset does not auto-login.
- Email OTP/magic link docs clearly state assurance limitations.
- Store contract tests pass for SQLite.
- Closure gates pass.
- Dependency tree has been inspected and documented.
- Public APIs have rustdoc, including `# Errors` where applicable.
