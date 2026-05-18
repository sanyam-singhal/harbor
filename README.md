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
