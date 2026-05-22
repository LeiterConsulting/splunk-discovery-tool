# Account Function Testing

Use `npm run test:account-functions` to run the current DT4SMS account-function matrix end to end.

The command covers:

- `tests.test_security_access.SecurityManagerTests`
- auth-focused methods from `tests.test_security_access.WebAppLocalAuthTests`
- Browser validation for local-password sign-in, forced password reset, admin access to Security settings, logout, and OIDC authorization-code sign-in

The unit matrix is intentionally scoped to account and access behavior only. It does not run the unrelated discovery-runtime tests that live in the same `WebAppLocalAuthTests` class.

Useful variants:

- `node tools/run_account_function_tests.mjs --unit-only`
- `node tools/run_account_function_tests.mjs --browser-only`
- `npm run test:auth-browser`

The browser harness does not require an external identity provider. It starts a minimal in-process OIDC server that exposes discovery, authorization, token, userinfo, JWKS, and end-session endpoints so the real DT4SMS browser flow can execute end to end.

Optional external sandbox

- Recommended repo: `navikt/mock-oauth2-server`
- Recommended clone location: `.external-test-deps/mock-oauth2-server`
- Why it is the best fit here: it supports OIDC discovery, authorization-code flow, JWKS, userinfo, end-session metadata, Docker or standalone execution, and configurable claims for role or MCP assignment mapping tests.

The `.external-test-deps/` path is ignored so sandbox repos stay out of commits and release packages.