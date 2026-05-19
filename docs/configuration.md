# Harbor v0.1 Configuration

This document is the handoff map for the email-auth draft before live
dogfooding. It keeps configuration explicit so the demo can move from local
SQLite and recording email to any verified HTTPS domain plus Resend without
code changes or secret leakage.

## Feature Flags

- Workspace default features keep provider delivery off.
- `harbor-email/email-resend` enables `ResendMailer`.
- `harbor-headless-demo/email-resend` forwards to `harbor-email/email-resend`.
- `harbor-leptos/axum` enables Axum response helpers for auth link routes.

## Demo Environment

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `HARBOR_DATABASE_URL` | no | `sqlite://harbor-headless-demo.sqlite?mode=rwc` | Use `sqlite:///var/lib/harbor/harbor.sqlite?mode=rwc` on the VPS. |
| `HARBOR_PUBLIC_BASE_URL` | no | `http://localhost:3000` | Use the verified HTTPS origin for live links. |
| `HARBOR_PRODUCT_NAME` | yes | none | Product name passed explicitly to the demo's default Rust email renderer. |
| `HARBOR_EMAIL_SITE_NAME` | no | host from `HARBOR_PUBLIC_BASE_URL` | Site label used by the demo's default Rust email renderer. |
| `HARBOR_HMAC_KEY` | yes | none | Must be at least 32 bytes and stable across restarts. |
| `HARBOR_EMAIL_MODE` | no | `recording` | Accepts `recording`, `log`, or `resend`. |
| `RESEND_API_KEY` | resend yes | none | Read only by `ResendMailer::from_env`. |
| `HARBOR_EMAIL_FROM` | resend yes | none | Must be a verified Resend sender. |
| `HARBOR_HEADLESS_DEMO_SMOKE_EMAIL` | no | generated `@example.com` address | Use a real inbox when validating live Resend delivery. The smoke runner adds a unique `+harbor...` tag per run. |
| `HARBOR_HEADLESS_DEMO_SMOKE` | no | `false` | Runs deterministic end-to-end auth flow and exits. |
| `HARBOR_HEADLESS_DEMO_BROWSER_SMOKE` | no | `false` | Starts the local browser smoke server. |
| `HARBOR_HEADLESS_DEMO_ADDR` | no | `127.0.0.1:3000` | Bind address for the browser smoke server. |

The demo mailer records every message in memory for deterministic smoke flows.
When `HARBOR_EMAIL_MODE=resend` and the `email-resend` feature is enabled, it
also sends through Resend. Tests continue to use local recording or local HTTP
test servers only.

## Auth Email Rendering

Harbor renders auth email content in Rust before handing it to Resend as
explicit `subject`, `text`, and `html` fields. Resend also supports hosted
templates, but its send-email API does not allow mixing a provider template
with explicit `html`, `text`, or React content in the same request. Harbor v0.1
therefore keeps the portable path as app-owned Rust rendering.

For a Leptos app, put templates in a normal Rust module, for example
`src/auth_email.rs`:

```rust
use harbor_core::{ChallengePurpose, MailError};
use harbor_email::{
    AuthEmail, AuthEmailRenderer, ChallengeEmailInput, escape_html,
};

#[derive(Debug, Clone)]
pub struct AppAuthEmail;

impl AuthEmailRenderer for AppAuthEmail {
    fn render_challenge_email(&self, input: ChallengeEmailInput) -> Result<AuthEmail, MailError> {
        let product = "Your App";
        let subject = match input.purpose {
            ChallengePurpose::SignupConfirmation => format!("Confirm your {product} sign-up"),
            ChallengePurpose::EmailSignIn => format!("Sign in to {product}"),
            ChallengePurpose::PasswordReset => format!("Reset your {product} password"),
            _ => format!("{product} auth email"),
        };
        let mut text = subject.clone();
        if let Some(url) = input.action_url.as_ref() {
            text.push_str("\n\n");
            text.push_str(url.expose_secret());
        }
        if let Some(code) = input.otp_code.as_ref() {
            text.push_str("\n\nCode: ");
            text.push_str(code.expose_secret());
        }
        let html = format!("<p>{}</p>", escape_html(&text).replace('\n', "<br>"));
        Ok(AuthEmail::new(
            input.purpose,
            input.to,
            input.challenge_id,
            subject,
            text,
            Some(html),
        ))
    }
}
```

Then wire it into Harbor:

```rust
let harbor = Harbor::builder()
    .with_store(store)
    .with_mailer(mailer)
    .with_public_base_url(public_base_url)?
    .with_hmac_secret_key(hmac_key)?
    .with_email_renderer(AppAuthEmail)
    .finish()?;
```

## Leptos Integration Shape

`harbor-leptos` provides app-owned integration pieces rather than a hidden
global auth server:

- validated `Harbor` builder and Leptos context helpers;
- CSRF issue/validate helpers using HMAC-signed double-submit cookies;
- HttpOnly session cookie builders with production and development defaults;
- generic async workflow functions for signup, signin, email code/link signin,
  password reset, current session, and signout;
- Axum response helpers for email link routes;
- form components for the v0.1 flows.

Applications should wrap the generic workflow functions inside their own
Leptos `#[server]` functions when they want `<ActionForm/>` submissions. That
keeps Harbor independent of a concrete app state type while remaining
compatible with SSR, hydrate, CSR-mounted forms that call server functions, and
islands that render around server-owned auth state.

## Security Defaults

- Session tokens are only transported through cookies, not
  `localStorage`/`sessionStorage`.
- Production cookies use the `__Host-` prefix, `Secure`, `HttpOnly` for the
  session cookie, path `/`, and explicit `SameSite=Lax`.
- Development cookies disable `Secure` for `localhost` only.
- CSRF-protected state-changing workflows validate the configured CSRF header
  against the CSRF cookie and require a valid HMAC signature.
- Password reset revokes existing sessions and does not create a new session.
- Magic links and OTP codes prove inbox possession only; they are not phishing
  resistant and are documented as lower assurance than hardware-backed MFA.
- Rate limits are enforced before state-changing email/password workflows and
  are persisted through the store using HMAC-hashed keys. Canonical email is
  always used; applications can also provide a trusted request fingerprint on
  `CsrfRequest`.

## What v0.1 Does Not Claim

- No social login, passkeys, WebAuthn, SAML, SCIM, or OAuth provider flows.
- No MFA or phishing-resistant authentication claim.
- No production-grade account administration UI.
- No PostgreSQL or MySQL adapter yet, though the store traits and shared
  contract tests are written as the acceptance suite for future adapters.
- No dependency-free email provider abstraction for live delivery; Resend is
  the only live provider in v0.1 and remains behind an explicit feature.

## Dependency Posture

The dependency tree was inspected with:

```sh
cargo tree --workspace --all-features --depth 1
cargo tree -p harbor-email --features email-resend --depth 2
cargo tree -p harbor-leptos --all-features --depth 2
cargo tree -p harbor-sqlx --all-features --depth 2
```

Production dependencies are intentionally concentrated:

- `harbor-core`: `argon2`, `getrandom`, `hmac`, `sha2`, `subtle`.
- `harbor-sqlx`: `sqlx` with SQLite support.
- `harbor-leptos`: `leptos`; optional `axum`.
- `harbor-email`: no provider dependency by default; optional `resend-rs`
  behind `email-resend`.

The largest optional supply-chain expansion is Resend delivery because
`resend-rs` brings `reqwest`, `governor`, `serde`, and parser support. Keeping
that feature explicit preserves the minimal default path.

## Live Testing Checklist

1. Build the demo with `--features email-resend`.
2. Set `HARBOR_PUBLIC_BASE_URL` to the verified HTTPS origin.
3. Set a stable high-entropy `HARBOR_HMAC_KEY`.
4. Set `HARBOR_EMAIL_MODE=resend`, `RESEND_API_KEY`, and a verified
   `HARBOR_EMAIL_FROM`.
5. Use the VPS SQLite path in `HARBOR_DATABASE_URL`.
6. Run `HARBOR_HEADLESS_DEMO_SMOKE=1 cargo run -p harbor-headless-demo --features email-resend`
   to send live signup, signin, and reset messages.
7. Dogfood the browser flow after the smoke succeeds; live testing should only
   uncover provider, DNS, proxy, and copy bugs, not unfinished library work.
