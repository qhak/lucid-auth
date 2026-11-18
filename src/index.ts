import { Hono } from "hono";
import { registerAuth } from "./auth";
import { canonical, errorResponse, fail } from "./core";
import type { App, Env } from "./core";
import { registerOrganizations } from "./organizations";
import { registerProviders } from "./providers";

const app = new Hono<App>();
app.onError(errorResponse);
app.use("*", async (c, next) => {
  c.header(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'",
  );
  c.header("X-Content-Type-Options", "nosniff");
  c.header("Referrer-Policy", "no-referrer");
  c.header("X-Frame-Options", "DENY");
  c.header(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self), publickey-credentials-create=(self)",
  );
  const origin = canonical(c.env);
  if (new URL(c.req.url).origin !== origin.origin) {
    fail(403, "ORIGIN_MISMATCH", "Use the configured application origin.");
  }
  if (origin.protocol === "https:")
    c.header("Strict-Transport-Security", "max-age=31536000");
  if (c.req.path.startsWith("/assets/")) return next();
  c.header("Cache-Control", "no-store");
  if (
    !["GET", "HEAD", "OPTIONS"].includes(c.req.method) &&
    c.req.header("Origin") !== origin.origin
  ) {
    fail(403, "CSRF_REJECTED", "Request origin was rejected.");
  }
  await next();
});

registerAuth(app);
registerProviders(app);
registerOrganizations(app);

app.all("/api/*", (c) =>
  c.json({ error: { code: "NOT_FOUND", message: "Resource not found." } }, 404),
);
app.get("*", async (c) => {
  if (!c.env.ASSETS) return c.text("Console assets unavailable.", 503);
  const response = await c.env.ASSETS.fetch(c.req.raw);
  return c.newResponse(response.body, response);
});

async function scheduled(_controller: ScheduledController, env: Env) {
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions WHERE refresh_expires_at <= ?").bind(
      now,
    ),
    env.DB.prepare("DELETE FROM flows WHERE expires_at <= ?").bind(now),
    env.DB.prepare(
      "DELETE FROM verification_tokens WHERE expires_at <= ?",
    ).bind(now),
    env.DB.prepare("DELETE FROM rate_limits WHERE expires_at <= ?").bind(now),
    env.DB.prepare("DELETE FROM audit_events WHERE created_at <= ?").bind(
      now - 90 * 24 * 60 * 60_000,
    ),
    env.DB.prepare(
      `DELETE FROM users WHERE verified_at IS NULL AND created_at <= ?
      AND NOT EXISTS (SELECT 1 FROM verification_tokens t WHERE t.user_id = users.id)`,
    ).bind(now - 7 * 24 * 60 * 60_000),
  ]);
}

export default { fetch: app.fetch, scheduled };
