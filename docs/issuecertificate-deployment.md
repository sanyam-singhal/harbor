# issuecertificate.com Demo Deployment Notes

Harbor's demo defaults to local, non-delivering email. Use Resend only when
explicitly configured for the VPS.

Required production environment:

- `HARBOR_PUBLIC_BASE_URL=https://issuecertificate.com`
- `HARBOR_DATABASE_URL=sqlite:///var/lib/harbor/harbor.sqlite?mode=rwc`
- `HARBOR_HMAC_KEY` set to at least 32 bytes of secret material
- `RESEND_API_KEY` for live Resend delivery
- `HARBOR_EMAIL_FROM="Harbor <auth@issuecertificate.com>"`

Reverse proxy requirements:

- Terminate HTTPS before the demo service.
- Forward only trusted `Host` values for `issuecertificate.com`.
- Preserve `Set-Cookie` headers without folding them.
- Keep auth routes on HTTPS; local `http://localhost` is only for development.

Local smoke check:

```sh
cargo run -p harbor-demo
```
