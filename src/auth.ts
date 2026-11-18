import { Buffer } from "node:buffer";
import { scrypt, timingSafeEqual } from "node:crypto";
import type { Hono } from "hono";
import { z } from "zod";
import {
  ACCESS_MS,
  body,
  clearSession,
  digest,
  event,
  fail,
  isToken,
  issue,
  local,
  rate,
  readCookie,
  requireSession,
  secret,
  secureCookie,
  sessionSecrets,
  toHex,
  writeSession,
} from "./core";
import type { App, Ctx } from "./core";

export const emailField = z
  .string()
  .trim()
  .toLowerCase()
  .max(254)
  .pipe(z.email());
const newPassword = z.string().min(15).max(128);
const loginPassword = z.string().min(1).max(128);
const tokenField = z.string().refine(isToken);
const credentials = z
  .object({ email: emailField, password: newPassword })
  .strict();
const passwordEncoder = new TextEncoder();
const zeroSalt = "0".repeat(64);

async function hashPassword(password: string, salt = secret()) {
  const bytes = Uint8Array.from(salt.match(/../g) ?? [], (byte) =>
    Number.parseInt(byte, 16),
  );
  // OWASP scrypt work factor N=2^15, r=8, p=3 fits the Worker memory budget.
  const derived = await new Promise<Buffer>((resolve, reject) => {
    scrypt(
      passwordEncoder.encode(password),
      bytes,
      32,
      { N: 32768, r: 8, p: 3, maxmem: 40 * 1024 * 1024 },
      (error, key) => {
        if (error) reject(error);
        else resolve(key);
      },
    );
  });
  return `${salt}.${toHex(derived)}`;
}

async function checkPassword(password: string, encoded: string | undefined) {
  const candidate = await hashPassword(
    password,
    encoded?.split(".")[0] ?? zeroSalt,
  );
  if (!encoded || encoded.length !== candidate.length) return false;
  // Compare equal-length digests without early exit on mismatched bytes.
  return timingSafeEqual(
    passwordEncoder.encode(candidate),
    passwordEncoder.encode(encoded),
  );
}

export const devMailEnabled = (c: Ctx) =>
  local(c.env) && c.env.DEV_MAIL === "1";
const localInbox: {
  email: string;
  kind: "verify" | "reset";
  token: string;
  createdAt: number;
}[] = [];

async function mail(
  c: Ctx,
  email: string,
  kind: "verify" | "reset",
  token: string,
) {
  const url = new URL("/", c.env.APP_ORIGIN);
  url.searchParams.set("mode", kind);
  url.hash = new URLSearchParams({ token }).toString();
  try {
    if (devMailEnabled(c)) {
      localInbox.unshift({ email, kind, token, createdAt: Date.now() });
      if (localInbox.length > 100) localInbox.length = 100;
      return;
    }
    if (!c.env.MAIL_API_KEY || !c.env.MAIL_FROM)
      throw new Error("Mail disabled");
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      redirect: "error",
      headers: {
        Authorization: `Bearer ${c.env.MAIL_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: c.env.MAIL_FROM,
        to: [email],
        subject:
          kind === "verify"
            ? "Verify your Lucid Auth email"
            : "Reset your Lucid Auth password",
        text: `Open this link to continue: ${url.href}\n\nIf you did not request this, you can ignore this message.`,
      }),
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) throw new Error("Mail delivery failed");
  } catch {
    console.error("Authentication mail delivery failed");
  }
}

function scheduleMail(
  c: Ctx,
  email: string,
  kind: "verify" | "reset",
  token: string,
) {
  const task = mail(c, email, kind, token);
  c.executionCtx.waitUntil(task);
  // Local inbox is immediately readable, while production responses avoid delivery-dependent timing.
  return devMailEnabled(c) ? task : Promise.resolve();
}

const accepted = (c: Ctx) => c.json({ ok: true }, 202);

export function registerAuth(app: Hono<App>) {
  app.get("/api/settings", (c) =>
    c.json({
      google: Boolean(c.env.GOOGLE_CLIENT_ID && c.env.GOOGLE_CLIENT_SECRET),
      passkeys: true,
      devMail: devMailEnabled(c),
      email: Boolean(
        devMailEnabled(c) || (c.env.MAIL_API_KEY && c.env.MAIL_FROM),
      ),
    }),
  );
  app.get("/api/dev/mail", async (c) => {
    if (!devMailEnabled(c)) fail(404, "NOT_FOUND", "Resource not found.");
    const email = emailField.safeParse(c.req.query("email"));
    if (!email.success) fail(400, "INVALID_INPUT", "Enter a valid email.");
    const cutoff = Date.now() - 60 * 60_000;
    const items = localInbox
      .filter((item) => item.email === email.data && item.createdAt > cutoff)
      .slice(0, 10)
      .map(({ token, kind, createdAt }) => ({ token, kind, createdAt }));
    return c.json({ items });
  });

  app.post("/api/auth/register", async (c) => {
    if (!devMailEnabled(c) && (!c.env.MAIL_API_KEY || !c.env.MAIL_FROM)) {
      fail(503, "MAIL_UNAVAILABLE", "Email registration is unavailable.");
    }
    await rate(c, "register", 10);
    const { email, password } = await body(c, credentials);
    await rate(c, "register-email", 4, email);
    const id = crypto.randomUUID();
    const now = Date.now();
    const token = secret();
    const previousBinding = readCookie(c, "lucid_verify");
    const binding = isToken(previousBinding) ? previousBinding : secret();
    const [passwordHash, tokenHash, bindingHash] = await Promise.all([
      hashPassword(password),
      digest(token),
      digest(binding),
    ]);
    const db = c.env.DB;
    const [result] = await db.batch([
      db
        .prepare(
          "INSERT INTO users (id, email, created_at) VALUES (?, ?, ?) ON CONFLICT(email) DO NOTHING",
        )
        .bind(id, email, now),
      db
        .prepare("INSERT INTO credentials SELECT ?, ? WHERE changes() > 0")
        .bind(id, passwordHash),
      db
        .prepare(
          "INSERT INTO verification_tokens SELECT ?, ?, 'verify', ?, ? WHERE changes() > 0",
        )
        .bind(tokenHash, id, bindingHash, now + 60 * 60_000),
      event(c, "account.registered", id),
    ]);
    // Make the response shape and cookie behavior identical for duplicates.
    secureCookie(c, "lucid_verify", binding, 3600);
    if (result?.meta.changes) await scheduleMail(c, email, "verify", token);
    return accepted(c);
  });

  app.post("/api/auth/verify", async (c) => {
    await rate(c, "verify", 25);
    const { token } = await body(c, z.object({ token: tokenField }).strict());
    const binding = readCookie(c, "lucid_verify");
    if (!isToken(binding))
      fail(
        400,
        "INVALID_TOKEN",
        "Open the link in the browser where you signed up.",
      );
    const [tokenHash, bindingHash] = await Promise.all([
      digest(token),
      digest(binding),
    ]);
    const db = c.env.DB;
    const now = Date.now();
    const filter =
      "token_hash = ? AND kind = 'verify' AND binding_hash = ? AND expires_at > ?";
    const [result] = await db.batch([
      db
        .prepare(
          `UPDATE users SET verified_at = ? WHERE verified_at IS NULL
        AND id = (SELECT user_id FROM verification_tokens WHERE ${filter})`,
        )
        .bind(now, tokenHash, bindingHash, now),
      db
        .prepare(`DELETE FROM verification_tokens WHERE ${filter}`)
        .bind(tokenHash, bindingHash, now),
    ]);
    if (!result?.meta.changes)
      fail(
        400,
        "INVALID_TOKEN",
        "The verification link is invalid or expired.",
      );
    secureCookie(c, "lucid_verify", "", 0);
    return c.json({ ok: true });
  });

  app.post("/api/auth/login", async (c) => {
    await rate(c, "login", 30);
    const { email, password } = await body(
      c,
      z.object({ email: emailField, password: loginPassword }).strict(),
    );
    await rate(c, "login-email", 8, email);
    const user = await c.env.DB.prepare(
      `
      SELECT u.id, u.verified_at, p.password_hash FROM users u
      JOIN credentials p ON p.user_id = u.id WHERE u.email = ?
    `,
    )
      .bind(email)
      .first<{
        id: string;
        verified_at: number | null;
        password_hash: string;
      }>();
    const valid = await checkPassword(password, user?.password_hash);
    if (!valid || !user?.verified_at)
      fail(
        401,
        "INVALID_CREDENTIALS",
        "Email or password is incorrect, or verification is pending.",
      );
    await issue(c, user.id, "login.password", {
      sql: "EXISTS (SELECT 1 FROM credentials WHERE user_id = u.id AND password_hash = ?)",
      args: [user.password_hash],
    });
    return c.json({ ok: true });
  });

  app.post("/api/auth/forgot-password", async (c) => {
    if (!devMailEnabled(c) && (!c.env.MAIL_API_KEY || !c.env.MAIL_FROM)) {
      fail(503, "MAIL_UNAVAILABLE", "Password recovery is unavailable.");
    }
    await rate(c, "forgot", 10);
    const { email } = await body(c, z.object({ email: emailField }).strict());
    await rate(c, "forgot-email", 4, email);
    const token = secret();
    const hash = await digest(token);
    const db = c.env.DB;
    const [, inserted] = await db.batch([
      db
        .prepare(
          `DELETE FROM verification_tokens WHERE kind = 'reset' AND user_id = (
        SELECT p.user_id FROM credentials p JOIN users u ON u.id = p.user_id WHERE u.email = ?
      )`,
        )
        .bind(email),
      db
        .prepare(
          `INSERT INTO verification_tokens
        SELECT ?, p.user_id, 'reset', NULL, ? FROM credentials p
        JOIN users u ON u.id = p.user_id WHERE u.email = ?`,
        )
        .bind(hash, Date.now() + 20 * 60_000, email),
    ]);
    if (inserted?.meta.changes) await scheduleMail(c, email, "reset", token);
    return accepted(c);
  });

  app.post("/api/auth/reset-password", async (c) => {
    await rate(c, "reset", 15);
    const { token, password } = await body(
      c,
      z.object({ token: tokenField, password: newPassword }).strict(),
    );
    const db = c.env.DB;
    const hash = await digest(token);
    const valid = await db
      .prepare(
        "SELECT 1 FROM verification_tokens WHERE token_hash = ? AND kind = 'reset' AND expires_at > ?",
      )
      .bind(hash, Date.now())
      .first();
    if (!valid)
      fail(400, "INVALID_TOKEN", "The reset link is invalid or expired.");
    const next = await hashPassword(password);
    const now = Date.now();
    const owner =
      "(SELECT user_id FROM verification_tokens WHERE token_hash = ? AND kind = 'reset' AND expires_at > ?)";
    const [result] = await db.batch([
      db
        .prepare(
          `UPDATE credentials SET password_hash = ? WHERE user_id = ${owner}`,
        )
        .bind(next, hash, now),
      db
        .prepare(
          `UPDATE users SET verified_at = COALESCE(verified_at, ?) WHERE id = ${owner}`,
        )
        .bind(now, hash, now),
      db
        .prepare(`DELETE FROM sessions WHERE user_id = ${owner}`)
        .bind(hash, now),
      db
        .prepare(`DELETE FROM passkeys WHERE user_id = ${owner}`)
        .bind(hash, now),
      db.prepare(`DELETE FROM flows WHERE user_id = ${owner}`).bind(hash, now),
      db
        .prepare(
          `INSERT INTO audit_events (id, actor_id, action, kind, created_at)
        SELECT ?, user_id, 'password.reset', 'auth', ? FROM verification_tokens
        WHERE token_hash = ? AND kind = 'reset' AND expires_at > ?`,
        )
        .bind(crypto.randomUUID(), now, hash, now),
      db
        .prepare(`DELETE FROM verification_tokens WHERE user_id = ${owner}`)
        .bind(hash, now),
    ]);
    if (!result?.meta.changes)
      fail(400, "INVALID_TOKEN", "The reset link is invalid or expired.");
    clearSession(c);
    return c.json({ ok: true });
  });

  app.get("/api/session", requireSession, (c) => c.json(c.get("principal")));

  app.post("/api/auth/refresh", async (c) => {
    await rate(c, "refresh", 120);
    const token = readCookie(c, "lucid_refresh");
    if (!isToken(token)) fail(401, "AUTH_REQUIRED", "Sign in to continue.");
    const [pair, oldHash] = await Promise.all([
      sessionSecrets(),
      digest(token),
    ]);
    const now = Date.now();
    const changed = await c.env.DB.prepare(
      `
      UPDATE sessions SET access_hash = ?, previous_refresh_hash = refresh_hash,
        refresh_hash = ?, access_expires_at = MIN(?, refresh_expires_at)
      WHERE refresh_hash = ? AND refresh_expires_at > ?
      RETURNING refresh_expires_at
    `,
    )
      .bind(pair.accessHash, pair.refreshHash, now + ACCESS_MS, oldHash, now)
      .first<{ refresh_expires_at: number }>();
    if (!changed) fail(401, "AUTH_REQUIRED", "Sign in to continue.");
    writeSession(c, pair, changed.refresh_expires_at);
    return c.json({ ok: true });
  });

  app.post("/api/auth/logout", async (c) => {
    const refresh = readCookie(c, "lucid_refresh");
    const access = readCookie(c, "lucid_access");
    if (isToken(refresh) || isToken(access)) {
      const [rh, ah] = await Promise.all([
        isToken(refresh) ? digest(refresh) : Promise.resolve(null),
        isToken(access) ? digest(access) : Promise.resolve(null),
      ]);
      await c.env.DB.prepare(
        "DELETE FROM sessions WHERE refresh_hash = ? OR previous_refresh_hash = ? OR access_hash = ?",
      )
        .bind(rh, rh, ah)
        .run();
    }
    clearSession(c);
    return c.json({ ok: true });
  });

  app.post("/api/auth/logout-all", requireSession, async (c) => {
    const db = c.env.DB;
    const { user } = c.get("principal");
    await db.batch([
      db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(user.id),
      event(c, "session.revoke_all", user.id),
    ]);
    clearSession(c);
    return c.json({ ok: true });
  });

  app.get("/api/account/sessions", requireSession, async (c) => {
    const { results } = await c.env.DB.prepare(
      `
      SELECT id, created_at AS createdAt, refresh_expires_at AS expiresAt
      FROM sessions WHERE user_id = ? AND refresh_expires_at > ? ORDER BY created_at DESC LIMIT 100
    `,
    )
      .bind(c.get("principal").user.id, Date.now())
      .all();
    return c.json({ items: results });
  });

  app.delete("/api/account/sessions/:id", requireSession, async (c) => {
    const { user, session } = c.get("principal");
    const id = c.req.param("id");
    const db = c.env.DB;
    const [result] = await db.batch([
      db
        .prepare("DELETE FROM sessions WHERE id = ? AND user_id = ?")
        .bind(id, user.id),
      event(c, "session.revoked", user.id),
    ]);
    if (!result?.meta.changes) fail(404, "NOT_FOUND", "Session not found.");
    if (id === session.id) clearSession(c);
    return c.json({ ok: true });
  });

  app.delete("/api/account", requireSession, async (c) => {
    await body(c, z.object({ confirm: z.literal(true) }).strict());
    const { user } = c.get("principal");
    const result = await c.env.DB.prepare(
      `
      DELETE FROM users WHERE id = ? AND NOT EXISTS (
        SELECT 1 FROM memberships mine WHERE mine.user_id = users.id AND mine.role_id = 'owner'
        AND NOT EXISTS (
          SELECT 1 FROM memberships other
          WHERE other.org_id = mine.org_id AND other.role_id = 'owner' AND other.user_id <> users.id
        )
      )
    `,
    )
      .bind(user.id)
      .run();
    if (!result.meta.changes)
      fail(
        409,
        "LAST_OWNER",
        "Assign another owner before deleting your account.",
      );
    clearSession(c);
    return c.json({ ok: true });
  });
}
