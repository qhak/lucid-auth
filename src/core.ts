import { and, eq, gt } from "drizzle-orm";
import { drizzle } from "drizzle-orm/d1";
import type { Context, MiddlewareHandler } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import type { z } from "zod";
import { sessions, users } from "./schema";

export type Env = {
  DB: D1Database;
  ASSETS?: Fetcher;
  APP_ORIGIN: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  DEV_MAIL?: string;
  MAIL_API_KEY?: string;
  MAIL_FROM?: string;
};

export type Principal = {
  user: { id: string; email: string };
  session: { id: string; expiresAt: number };
};
export type App = { Bindings: Env; Variables: { principal: Principal } };
export type Ctx = Context<App>;
export type SqlValue = string | number | null | ArrayBuffer;
type Status = 400 | 401 | 403 | 404 | 409 | 413 | 429 | 500 | 503;

class ApiError extends Error {
  constructor(
    public status: Status,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

export function fail(status: Status, code: string, message: string): never {
  throw new ApiError(status, code, message);
}

export function errorResponse(error: Error, c: Ctx) {
  if (error instanceof ApiError) {
    return c.json(
      { error: { code: error.code, message: error.message } },
      error.status,
    );
  }
  // Never log exception messages or request URLs, which can contain secrets.
  console.error("Unhandled API error", c.req.method);
  return c.json(
    { error: { code: "INTERNAL_ERROR", message: "Something went wrong." } },
    500,
  );
}

const encoder = new TextEncoder();
export function toHex(buffer: ArrayBuffer | Uint8Array) {
  return Array.from(new Uint8Array(buffer), (value) =>
    value.toString(16).padStart(2, "0"),
  ).join("");
}
export const secret = () => toHex(crypto.getRandomValues(new Uint8Array(32)));
export const digest = async (value: string) =>
  toHex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
export const isToken = (value: unknown): value is string =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);

export function local(env: Env) {
  const url = new URL(env.APP_ORIGIN);
  return url.hostname === "localhost" || url.hostname === "127.0.0.1";
}

export function canonical(env: Env) {
  try {
    const url = new URL(env.APP_ORIGIN);
    if (
      url.origin === env.APP_ORIGIN &&
      (url.protocol === "https:" || (local(env) && url.protocol === "http:"))
    ) {
      return url;
    }
  } catch {
    // Invalid deployment configuration.
  }
  fail(503, "CONFIGURATION_ERROR", "Authentication origin is misconfigured.");
}

function cookieName(c: Ctx, key: string) {
  return canonical(c.env).protocol === "https:" ? `__Host-${key}` : key;
}

export function secureCookie(
  c: Ctx,
  key: string,
  value: string,
  maxAge: number,
) {
  setCookie(c, cookieName(c, key), value, {
    path: "/",
    httpOnly: true,
    secure: canonical(c.env).protocol === "https:",
    sameSite: "Lax",
    maxAge,
  });
}

export const readCookie = (c: Ctx, key: string) =>
  getCookie(c, cookieName(c, key));
export const clearSession = (c: Ctx) => {
  secureCookie(c, "lucid_access", "", 0);
  secureCookie(c, "lucid_refresh", "", 0);
};

export async function body<T extends z.ZodType>(
  c: Ctx,
  schema: T,
): Promise<z.infer<T>> {
  if (
    c.req.header("Content-Type")?.split(";")[0]?.trim().toLowerCase() !==
    "application/json"
  ) {
    fail(400, "INVALID_INPUT", "Send an application/json request.");
  }
  const reader = c.req.raw.body?.getReader();
  if (!reader) fail(400, "INVALID_INPUT", "A request body is required.");
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let value: unknown;
  try {
    let contents = "";
    let size = 0;
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > 24_576) {
        await reader.cancel().catch(() => {});
        fail(413, "BODY_TOO_LARGE", "Request exceeds the payload limit.");
      }
      contents += decoder.decode(part.value, { stream: true });
    }
    value = JSON.parse(contents + decoder.decode());
  } catch (error) {
    if (error instanceof ApiError) throw error;
    fail(400, "INVALID_INPUT", "Malformed JSON.");
  } finally {
    reader.releaseLock();
  }
  const parsed = schema.safeParse(value);
  if (!parsed.success)
    fail(400, "INVALID_INPUT", "Check the supplied fields and try again.");
  return parsed.data;
}

const rateWindow = 15 * 60_000;
export async function rate(
  c: Ctx,
  bucket: string,
  limit: number,
  identity?: string,
) {
  const now = Date.now();
  const key = await digest(
    `${bucket}\n${identity ?? c.req.header("CF-Connecting-IP") ?? "unknown"}`,
  );
  const result = await c.env.DB.prepare(
    `
    INSERT INTO rate_limits (key, requests, expires_at) VALUES (?, 1, ?)
    ON CONFLICT (key) DO UPDATE SET
      requests = CASE WHEN expires_at <= ? THEN 1 ELSE MIN(requests + 1, ?) END,
      expires_at = CASE WHEN expires_at <= ? THEN excluded.expires_at ELSE expires_at END
    RETURNING requests, expires_at
  `,
  )
    .bind(key, now + rateWindow, now, limit + 1, now)
    .first<{ requests: number; expires_at: number }>();
  if (!result || result.requests > limit) {
    c.header(
      "Retry-After",
      String(
        Math.max(
          1,
          Math.ceil(((result?.expires_at ?? now + rateWindow) - now) / 1000),
        ),
      ),
    );
    fail(429, "RATE_LIMITED", "Too many requests. Try again later.");
  }
}

export const ACCESS_MS = 15 * 60_000;
export const SESSION_MS = 30 * 24 * 60 * 60_000;
export async function sessionSecrets() {
  const access = secret();
  const refresh = secret();
  const [accessHash, refreshHash] = await Promise.all([
    digest(access),
    digest(refresh),
  ]);
  return { access, refresh, accessHash, refreshHash };
}

export function writeSession(
  c: Ctx,
  pair: { access: string; refresh: string },
  expiresAt: number,
) {
  const remaining = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
  secureCookie(
    c,
    "lucid_access",
    pair.access,
    Math.min(ACCESS_MS / 1000, remaining),
  );
  secureCookie(c, "lucid_refresh", pair.refresh, remaining);
}

export function event(
  c: Ctx,
  action: string,
  actor: string,
  subjectId: string | null = null,
) {
  return c.env.DB.prepare(
    `
    INSERT INTO audit_events (id, actor_id, subject_id, action, kind, created_at)
    SELECT ?, ?, ?, ?, 'auth', ? WHERE changes() > 0
  `,
  ).bind(crypto.randomUUID(), actor, subjectId, action, Date.now());
}

export async function issue(
  c: Ctx,
  userId: string,
  action: string,
  guard?: { sql: string; args: SqlValue[] },
) {
  const now = Date.now();
  const pair = await sessionSecrets();
  const previous = readCookie(c, "lucid_refresh");
  const sql = c.env.DB;
  const insert = sql
    .prepare(
      `
    INSERT INTO sessions (id, user_id, access_hash, refresh_hash, access_expires_at, refresh_expires_at, created_at)
    SELECT ?, u.id, ?, ?, ?, ?, ? FROM users u
    WHERE u.id = ? AND u.verified_at IS NOT NULL ${guard ? `AND (${guard.sql})` : ""}
  `,
    )
    .bind(
      crypto.randomUUID(),
      pair.accessHash,
      pair.refreshHash,
      now + ACCESS_MS,
      now + SESSION_MS,
      now,
      userId,
      ...(guard?.args ?? []),
    );
  const statements = [insert, event(c, action, userId)];
  if (isToken(previous)) {
    const previousHash = await digest(previous);
    statements.push(
      sql
        .prepare(
          "DELETE FROM sessions WHERE (refresh_hash = ? OR previous_refresh_hash = ?) AND changes() > 0",
        )
        .bind(previousHash, previousHash),
    );
  }
  const [result] = await sql.batch(statements);
  if (!result?.meta.changes)
    fail(401, "AUTH_REQUIRED", "Sign-in could not be completed.");
  writeSession(c, pair, now + SESSION_MS);
}

export const requireSession: MiddlewareHandler<App> = async (c, next) => {
  const token = readCookie(c, "lucid_access");
  if (!isToken(token)) fail(401, "AUTH_REQUIRED", "Sign in to continue.");
  const now = Date.now();
  const result = await drizzle(c.env.DB)
    .select({
      user: { id: users.id, email: users.email },
      session: { id: sessions.id, expiresAt: sessions.accessExpiresAt },
    })
    .from(sessions)
    .innerJoin(users, eq(sessions.userId, users.id))
    .where(
      and(
        eq(sessions.accessHash, await digest(token)),
        gt(sessions.accessExpiresAt, now),
        gt(sessions.refreshExpiresAt, now),
      ),
    )
    .get();
  if (!result) fail(401, "AUTH_REQUIRED", "Sign in to continue.");
  c.set("principal", result);
  await next();
};
