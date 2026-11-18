import type { Hono } from "hono";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { base64url, createRemoteJWKSet, jwtVerify } from "jose";
import { z } from "zod";
import {
  body,
  digest,
  event,
  fail,
  issue,
  rate,
  readCookie,
  requireSession,
  secret,
  secureCookie,
  type App,
  type Ctx,
} from "./core";

const googleAuthorizationUrl = "https://accounts.google.com/o/oauth2/v2/auth";
const googleTokenUrl = "https://oauth2.googleapis.com/token";
const googleKeys = createRemoteJWKSet(
  new URL("https://www.googleapis.com/oauth2/v3/certs"),
);
const googleCookie = "lucid_google";
const passkeyCookie = "lucid_passkey";
const googleLifetime = 600;
const passkeyLifetime = 300;
const recentLoginMs = 15 * 60 * 1_000;
const passkeyAlgorithms = [-7, -257]; // ES256 and RS256
const encoder = new TextEncoder();
const hexSecret = z.string().regex(/^[0-9a-f]{64}$/);
const encoded = z
  .string()
  .min(1)
  .max(32_768)
  .regex(/^[a-zA-Z0-9_-]+$/);
const credentialFields = {
  id: encoded.max(2_048),
  rawId: encoded.max(2_048),
  type: z.literal("public-key"),
  clientExtensionResults: z.object({}),
};

const finishRegistration = z.object({
  id: hexSecret,
  response: z.object({
    ...credentialFields,
    response: z.object({
      clientDataJSON: encoded.max(4_096),
      attestationObject: encoded,
      transports: z.array(z.string().max(32)).max(12).optional(),
    }),
  }),
});

const finishAuthentication = z.object({
  id: hexSecret,
  response: z.object({
    ...credentialFields,
    response: z.object({
      clientDataJSON: encoded.max(4_096),
      authenticatorData: encoded.max(4_096),
      signature: encoded.max(4_096),
      userHandle: encoded.max(128),
    }),
  }),
});

type FlowKind = "google" | "passkey-register" | "passkey-login";

async function saveFlow(
  c: Ctx,
  kind: FlowKind,
  binding: string,
  data: string,
  maxAge: number,
  userId: string | null = null,
) {
  const id = secret();
  await c.env.DB.prepare(
    "INSERT INTO flows (id_hash, kind, binding_hash, user_id, data, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
  )
    .bind(
      await digest(id),
      kind,
      await digest(binding),
      userId,
      data,
      Date.now() + maxAge * 1_000,
    )
    .run();
  return id;
}

async function consumeFlow(
  c: Ctx,
  kind: FlowKind,
  id: string,
  binding: string,
  userId: string | null = null,
) {
  return c.env.DB.prepare(
    "DELETE FROM flows WHERE id_hash = ? AND kind = ? AND binding_hash = ? AND user_id IS ? AND expires_at > ? RETURNING data",
  )
    .bind(await digest(id), kind, await digest(binding), userId, Date.now())
    .first<{ data: string }>();
}

function googleRedirectUri(c: Ctx): string {
  return new URL("/api/auth/google/callback", c.env.APP_ORIGIN).href;
}

function googleVerifier(binding: string): Promise<string> {
  return digest("lucid-google-pkce:" + binding);
}

function callbackFailed(c: Ctx) {
  return c.redirect("/?auth=google_failed");
}

const googleClaims = z.object({
  sub: z.string().min(1).max(255),
  nonce: hexSecret,
  email: z.string().trim().toLowerCase().max(254).email(),
  email_verified: z.literal(true),
  hd: z.string().min(1).optional(),
  azp: z.string().optional(),
});

async function googleAccount(
  c: Ctx,
  claims: z.infer<typeof googleClaims>,
): Promise<string | undefined> {
  const lookup = c.env.DB.prepare(
    "SELECT user_id FROM oauth_identities WHERE provider = 'google' AND subject = ?",
  ).bind(claims.sub);

  const existing = await lookup.first<{ user_id: string }>();
  if (existing) return existing.user_id;

  // Google is authoritative over Gmail and addresses managed by Google Workspace.
  if (!claims.email.endsWith("@gmail.com") && !claims.hd) return undefined;

  const userId = crypto.randomUUID();
  const now = Date.now();
  await c.env.DB.batch([
    c.env.DB.prepare(
      "INSERT INTO users (id, email, verified_at, created_at) SELECT ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM oauth_identities WHERE provider = 'google' AND subject = ?) ON CONFLICT(email) DO NOTHING",
    ).bind(userId, claims.email, now, now, claims.sub),
    c.env.DB.prepare(
      "INSERT INTO oauth_identities (provider, subject, user_id) SELECT 'google', ?, id FROM users WHERE id = ?",
    ).bind(claims.sub, userId),
  ]);
  return (await lookup.first<{ user_id: string }>())?.user_id;
}

function rp(c: Ctx) {
  const origin = new URL(c.env.APP_ORIGIN);
  return { expectedOrigin: origin.origin, expectedRPID: origin.hostname };
}

function validateClientContext(value: string) {
  try {
    const decoded: unknown = JSON.parse(
      new TextDecoder().decode(base64url.decode(value)),
    );
    if (typeof decoded === "object" && decoded !== null) {
      const crossOrigin =
        "crossOrigin" in decoded ? decoded.crossOrigin : false;
      if (crossOrigin === false && !("topOrigin" in decoded)) return;
    }
  } catch {
    // Treat incorrectly encoded client data like every other invalid ceremony.
  }
  fail(401, "invalid_passkey", "The passkey could not be verified.");
}

async function verified<T>(callback: () => Promise<T>): Promise<T> {
  try {
    return await callback();
  } catch {
    fail(401, "invalid_passkey", "The passkey could not be verified.");
  }
}

async function enrollmentSession(c: Ctx) {
  const { user, session } = c.get("principal");
  const freshSession = await c.env.DB.prepare(
    "SELECT 1 AS valid FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.user_id = ? AND u.verified_at IS NOT NULL AND s.created_at > ? AND s.access_expires_at > ?",
  )
    .bind(session.id, user.id, Date.now() - recentLoginMs, Date.now())
    .first("valid");
  if (!freshSession) {
    fail(
      403,
      "recent_sign_in_required",
      "Sign in again before adding a passkey.",
    );
  }
  return { user, session };
}

export function registerProviders(app: Hono<App>) {
  app.get("/api/account/passkeys", requireSession, async (c) => {
    const { results } = await c.env.DB.prepare(
      "SELECT id, created_at AS createdAt FROM passkeys WHERE user_id = ? ORDER BY created_at DESC, id",
    )
      .bind(c.get("principal").user.id)
      .all();
    return c.json({ items: results });
  });

  app.delete("/api/account/passkeys/:id", requireSession, async (c) => {
    const { user, session } = await enrollmentSession(c);
    const db = c.env.DB;
    const now = Date.now();
    const [removed] = await db.batch([
      db
        .prepare(
          `DELETE FROM passkeys WHERE id = ? AND user_id = ?
        AND EXISTS (SELECT 1 FROM sessions WHERE id = ? AND user_id = ?
          AND created_at > ? AND access_expires_at > ?)`,
        )
        .bind(
          c.req.param("id"),
          user.id,
          session.id,
          user.id,
          now - recentLoginMs,
          now,
        ),
      db
        .prepare(
          `INSERT INTO audit_events (id, actor_id, action, kind, created_at)
        SELECT ?, ?, 'passkey.revoked', 'auth', ? WHERE changes() > 0`,
        )
        .bind(crypto.randomUUID(), user.id, now),
    ]);
    if (!removed?.meta.changes) fail(404, "NOT_FOUND", "Passkey not found.");
    return c.json({ ok: true });
  });

  app.post("/api/auth/google/start", async (c) => {
    await rate(c, "google-start", 20);
    if (!c.env.GOOGLE_CLIENT_ID || !c.env.GOOGLE_CLIENT_SECRET) {
      fail(503, "google_disabled", "Google sign-in is unavailable.");
    }

    const binding = secret();
    const nonce = secret();
    const state = await saveFlow(
      c,
      "google",
      binding,
      await digest(nonce),
      googleLifetime,
    );
    const verifier = await googleVerifier(binding);
    const challenge = base64url.encode(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", encoder.encode(verifier)),
      ),
    );
    const url = new URL(googleAuthorizationUrl);
    url.search = new URLSearchParams({
      client_id: c.env.GOOGLE_CLIENT_ID,
      redirect_uri: googleRedirectUri(c),
      response_type: "code",
      scope: "openid email",
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: "S256",
    }).toString();
    secureCookie(c, googleCookie, binding, googleLifetime);
    return c.json({ url: url.href });
  });

  app.get("/api/auth/google/callback", async (c) => {
    await rate(c, "google-callback", 30);
    const clientId = c.env.GOOGLE_CLIENT_ID;
    const clientSecret = c.env.GOOGLE_CLIENT_SECRET;
    if (!clientId || !clientSecret) return callbackFailed(c);

    const states = c.req.queries("state");
    const state = hexSecret.safeParse(
      states?.length === 1 ? states[0] : undefined,
    );
    const binding = hexSecret.safeParse(readCookie(c, googleCookie));
    if (!state.success || !binding.success) return callbackFailed(c);

    const flow = await consumeFlow(c, "google", state.data, binding.data);
    if (!flow) return callbackFailed(c);
    secureCookie(c, googleCookie, "", 0);
    const codes = c.req.queries("code");
    const code = codes?.length === 1 ? codes[0] : undefined;
    if (c.req.query("error") || !code || code.length > 2_048)
      return callbackFailed(c);

    let claims: z.infer<typeof googleClaims>;
    try {
      const response = await fetch(googleTokenUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          code,
          code_verifier: await googleVerifier(binding.data),
          grant_type: "authorization_code",
          redirect_uri: googleRedirectUri(c),
        }),
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) return callbackFailed(c);
      const { id_token } = z
        .object({ id_token: z.string().max(16_384) })
        .parse(await response.json());
      const { payload } = await jwtVerify(id_token, googleKeys, {
        algorithms: ["RS256"],
        issuer: ["https://accounts.google.com", "accounts.google.com"],
        audience: clientId,
        requiredClaims: ["sub", "iat", "exp", "nonce"],
        maxTokenAge: "10 minutes",
        clockTolerance: 10,
      });
      claims = googleClaims.parse(payload);
      if (
        (claims.azp && claims.azp !== clientId) ||
        (Array.isArray(payload.aud) &&
          payload.aud.length > 1 &&
          claims.azp !== clientId) ||
        (await digest(claims.nonce)) !== flow.data
      )
        return callbackFailed(c);
    } catch {
      // OAuth provider failures share a redirect. Never include codes, secrets or token contents.
      return callbackFailed(c);
    }

    const userId = await googleAccount(c, claims);
    if (!userId) return callbackFailed(c);
    await issue(c, userId, "login.google", {
      sql: "EXISTS (SELECT 1 FROM oauth_identities WHERE provider = 'google' AND subject = ? AND user_id = u.id)",
      args: [claims.sub],
    });
    return c.redirect("/");
  });

  app.post("/api/auth/passkeys/register/options", requireSession, async (c) => {
    await rate(c, "passkey-register-start", 20);
    const { user, session } = await enrollmentSession(c);
    const { results } = await c.env.DB.prepare(
      "SELECT id FROM passkeys WHERE user_id = ? LIMIT 20",
    )
      .bind(user.id)
      .all<{ id: string }>();
    if (results.length >= 20)
      fail(409, "passkey_limit", "The account already has 20 passkeys.");

    const options = await generateRegistrationOptions({
      rpName: "Lucid Auth",
      rpID: rp(c).expectedRPID,
      userID: encoder.encode(user.id),
      userName: user.email,
      attestationType: "none",
      timeout: 120_000,
      supportedAlgorithmIDs: passkeyAlgorithms,
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      excludeCredentials: results.map(({ id }) => ({ id })),
    });
    const id = await saveFlow(
      c,
      "passkey-register",
      session.id,
      options.challenge,
      passkeyLifetime,
      user.id,
    );
    return c.json({ id, options });
  });

  app.post("/api/auth/passkeys/register/verify", requireSession, async (c) => {
    await rate(c, "passkey-register-verify", 20);
    const { user, session } = await enrollmentSession(c);
    const { id, response } = await body(c, finishRegistration);
    const flow = await consumeFlow(
      c,
      "passkey-register",
      id,
      session.id,
      user.id,
    );
    if (!flow)
      fail(401, "invalid_passkey", "The passkey could not be verified.");

    validateClientContext(response.response.clientDataJSON);
    const result = await verified(() =>
      verifyRegistrationResponse({
        response,
        ...rp(c),
        expectedChallenge: flow.data,
        expectedType: "webauthn.create",
        requireUserVerification: true,
        supportedAlgorithmIDs: passkeyAlgorithms,
      }),
    );
    if (
      !result.verified ||
      result.registrationInfo.fmt !== "none" ||
      result.registrationInfo.credential.id !== response.id
    ) {
      fail(401, "invalid_passkey", "The passkey could not be verified.");
    }
    const credential = result.registrationInfo.credential;
    const now = Date.now();
    const [insert] = await c.env.DB.batch([
      c.env.DB.prepare(
        "INSERT INTO passkeys (id, user_id, public_key, counter, transports, created_at) SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.user_id = ? AND s.created_at > ? AND s.access_expires_at > ? AND u.verified_at IS NOT NULL) AND (SELECT count(*) FROM passkeys WHERE user_id = ?) < 20 ON CONFLICT(id) DO NOTHING",
      ).bind(
        credential.id,
        user.id,
        credential.publicKey.slice().buffer,
        credential.counter,
        JSON.stringify(credential.transports ?? []),
        now,
        session.id,
        user.id,
        now - recentLoginMs,
        now,
        user.id,
      ),
      event(c, "passkey.registered", user.id, user.id),
    ]);
    if (insert?.meta.changes !== 1)
      fail(409, "passkey_unavailable", "The passkey could not be added.");
    return c.json({ ok: true });
  });

  app.post("/api/auth/passkeys/login/options", async (c) => {
    await rate(c, "passkey-login-start", 30);
    const options = await generateAuthenticationOptions({
      rpID: rp(c).expectedRPID,
      userVerification: "required",
      timeout: 120_000,
    });
    const binding = secret();
    const id = await saveFlow(
      c,
      "passkey-login",
      binding,
      options.challenge,
      passkeyLifetime,
    );
    secureCookie(c, passkeyCookie, binding, passkeyLifetime);
    return c.json({ id, options });
  });

  app.post("/api/auth/passkeys/login/verify", async (c) => {
    await rate(c, "passkey-login-verify", 30);
    const { id, response } = await body(c, finishAuthentication);
    const binding = hexSecret.safeParse(readCookie(c, passkeyCookie));
    if (!binding.success)
      fail(401, "invalid_passkey", "The passkey could not be verified.");
    const flow = await consumeFlow(c, "passkey-login", id, binding.data);
    if (!flow)
      fail(401, "invalid_passkey", "The passkey could not be verified.");
    secureCookie(c, passkeyCookie, "", 0);

    const row = await c.env.DB.prepare(
      "SELECT p.user_id, p.public_key, p.counter FROM passkeys p JOIN users u ON p.user_id = u.id WHERE p.id = ? AND u.verified_at IS NOT NULL",
    )
      .bind(response.id)
      .first<{ user_id: string; public_key: number[]; counter: number }>();
    if (
      !row ||
      response.response.userHandle !== base64url.encode(row.user_id)
    ) {
      fail(401, "invalid_passkey", "The passkey could not be verified.");
    }

    validateClientContext(response.response.clientDataJSON);
    const result = await verified(() =>
      verifyAuthenticationResponse({
        response,
        ...rp(c),
        expectedChallenge: flow.data,
        expectedType: "webauthn.get",
        requireUserVerification: true,
        credential: {
          id: response.id,
          counter: row.counter,
          publicKey: Uint8Array.from(row.public_key),
        },
      }),
    );
    if (!result.verified)
      fail(401, "invalid_passkey", "The passkey could not be verified.");
    const counter = result.authenticationInfo.newCounter;
    const updated = await c.env.DB.prepare(
      "UPDATE passkeys SET counter = ? WHERE id = ? AND user_id = ? AND counter = ?",
    )
      .bind(counter, response.id, row.user_id, row.counter)
      .run();
    if (updated.meta.changes !== 1)
      fail(401, "invalid_passkey", "The passkey could not be verified.");
    await issue(c, row.user_id, "login.passkey", {
      sql: "EXISTS (SELECT 1 FROM passkeys WHERE id = ? AND user_id = u.id AND counter = ?)",
      args: [response.id, counter],
    });
    return c.json({ ok: true });
  });
}
