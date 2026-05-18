# Harbor

Harbor is a Rust authentication framework designed for Leptos applications.

The first milestone, v0.1, focuses on email-based authentication:

- email and password signup/signin;
- email signup confirmation;
- email OTP and magic-link signin;
- email-based password reset;
- SQLx storage with SQLite first;
- Resend-backed transactional email behind an explicit integration.

The implementation roadmap lives in
[`HARBOR_V0_1_AUTH_PLAN.md`](HARBOR_V0_1_AUTH_PLAN.md).

## Current v0.1 Draft

The workspace is ready for local dogfood testing of the email-auth slice. The
library surface is split by responsibility:

- `harbor-core`: framework-free domain types, password hashing, session,
  challenge, and rate-limit orchestration.
- `harbor-sqlx`: SQLx-backed storage with SQLite migrations and store contract
  tests.
- `harbor-email`: recording mailer plus optional Resend delivery behind the
  `email-resend` feature.
- `harbor-leptos`: Leptos config, context, components, cookie/CSRF helpers,
  Axum link responses, and server-callable workflow helpers.
- `harbor-demo`: SQLite demo/smoke harness for local and VPS dogfooding.

`harbor-leptos` intentionally exposes generic async workflow functions instead
of hard-coding app-specific `#[server]` functions. A Leptos app can wrap those
helpers in its own server functions and use `<ActionForm/>` where its routing
and state model need progressive enhancement.

## Quickstart

Run the full local gate:

```sh
scripts/check.sh
```

Run the deterministic demo smoke without live email:

```sh
HARBOR_DEMO_SMOKE=1 cargo run -p harbor-demo
```

Run the browser smoke server with recording email shortcuts:

```sh
HARBOR_DEMO_BROWSER_SMOKE=1 cargo run -p harbor-demo
```

Enable live Resend delivery only when explicitly dogfooding against a verified
sender:

```sh
HARBOR_EMAIL_MODE=resend \
HARBOR_DEMO_SMOKE=1 \
RESEND_API_KEY="$RESEND_API_KEY" \
HARBOR_EMAIL_FROM="Harbor <auth@issuecertificate.com>" \
cargo run -p harbor-demo --features email-resend
```

See [`docs/configuration.md`](docs/configuration.md) for environment variables,
feature flags, dependency posture, and the live-testing checklist.
