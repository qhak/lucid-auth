# Lucid Auth implementation plan

## Architecture

One Hono Worker serves the JSON API and Vite-built React console from a canonical origin. D1 holds user, membership, session and audit state. Drizzle supplies typed schema and reads. Prepared SQL expresses the atomic conditional writes. Google sign-in uses JOSE, and passkeys use SimpleWebAuthn.

1. Establish a strict TypeScript toolchain and D1 migration. Test routes under workerd against freshly migrated D1.
2. Implement credential and email flows, rate limits and hashed sessions. Verify expiry, replay, concurrent rotation and password reset revocation.
3. Authorize against current organization memberships. Keep permission checks and mutations inside atomic D1 batches. Verify cross-tenant boundaries, role changes and audit records.
4. Wire provider callbacks and passkey challenges. Verify browser binding, one-time use, canonical origin and RP ID.
5. Connect the console, SDK and Next.js example to real routes. Run a browser smoke test and capture the resulting console.
6. Document configuration, trade-offs and deployment. Run formatting, lint, type checks, full integration suite, build and dependency audit.
