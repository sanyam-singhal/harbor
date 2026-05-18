# issuecertificate.com Demo Deployment Notes

Harbor's demo defaults to local, non-delivering email. Use Resend only when
explicitly configured for the VPS.

Required production environment:

- `HARBOR_PUBLIC_BASE_URL=https://issuecertificate.com`
- `HARBOR_DATABASE_URL=sqlite:///var/lib/harbor/harbor.sqlite?mode=rwc`
- `HARBOR_HMAC_KEY` set to at least 32 bytes of secret material
- `HARBOR_EMAIL_MODE=resend`
- `RESEND_API_KEY` for live Resend delivery
- `HARBOR_EMAIL_FROM="Harbor <auth@issuecertificate.com>"`

Reverse proxy requirements:

- Terminate HTTPS before the demo service.
- Forward only trusted `Host` values for `issuecertificate.com`.
- Preserve `Set-Cookie` headers without folding them.
- Keep auth routes on HTTPS; local `http://localhost` is only for development.

Local smoke check:

```sh
HARBOR_DEMO_SMOKE=1 cargo run -p harbor-demo
```

Live Resend smoke check:

```sh
HARBOR_EMAIL_MODE=resend \
HARBOR_DEMO_SMOKE=1 \
cargo run -p harbor-demo --features email-resend
```

Keep `HARBOR_DEMO_BROWSER_SMOKE=1` for local browser automation. The live
Resend smoke mirrors messages into the in-memory recorder only so the
deterministic flow can continue without asking a human to paste every link.
