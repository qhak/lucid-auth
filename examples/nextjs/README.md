# Next.js App Router example

With the Worker running at http://localhost:8787, create and verify a user in the Lucid Auth console. From this example directory:

```sh
pnpm --ignore-workspace install --frozen-lockfile
cp .env.example .env.local
pnpm --ignore-workspace dev
```

Open http://localhost:3000 and sign in using the verified account. Set `LUCID_ORG_ID` to a test organization ID to exercise the protected workspace check. The page forwards Lucid cookies to the Worker from a Server Component, checks identity and the organization grant, and renders protected content only when authorized.

The Route Handler proxies three password-session actions. It checks `APP_ORIGIN` before forwarding, denies upstream redirects, and relays both session cookie headers without exposing them to JavaScript. Use HTTPS for both deployed origins. The Next.js origin and Worker origin are trusted deployment configuration. Configure edge rate limiting if you deploy a proxy because the Worker can see the proxy's IP on forwarded login requests.

See the [main README](../../README.md) for verification, providers and the full REST API.
