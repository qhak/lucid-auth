import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
  account,
  client,
  json,
  login,
  mailToken,
  password,
  setCookies,
  signup,
  successful,
  type Session,
} from "./http";

describe("email authentication", () => {
  it("requires verified registration and rejects verification token replay", async () => {
    const request = client();
    const { email, verificationCookie } = await signup(request);
    const unverified = await request("/api/auth/login", {
      json: { email, password },
    });
    expect(unverified.status).toBe(401);
    expect(setCookies(unverified)).not.toContain("lucid_access=");

    const token = await mailToken(request, email);
    const { verificationCookie: otherBrowserCookie } = await signup(
      request,
      "other-browser",
    );
    const differentBrowser = await request("/api/auth/verify", {
      json: { token },
      cookie: otherBrowserCookie,
    });
    expect(differentBrowser.ok).toBe(false);
    await successful(
      await request("/api/auth/verify", {
        json: { token },
        cookie: verificationCookie,
      }),
    );
    const replay = await request("/api/auth/verify", {
      json: { token },
      cookie: verificationCookie,
    });
    expect(replay.status).toBeGreaterThanOrEqual(400);
    expect(replay.status).toBeLessThan(500);

    const response = await request("/api/auth/login", {
      json: { email: email.toUpperCase(), password },
    });
    expect(response.ok, await response.clone().text()).toBe(true);
    for (const cookie of response.headers.getSetCookie()) {
      expect(cookie).toMatch(/; HttpOnly\b/i);
      expect(cookie).toMatch(/; SameSite=Lax\b/i);
    }
    const signedIn = await json<Session>(
      await request("/api/session", { cookie: setCookies(response) }),
    );
    expect(signedIn.user.email).toBe(email);
    expect(signedIn.session.expiresAt).toBeGreaterThan(Date.now());
  });

  it("returns the same registration, login, and reset-request responses for account probes", async () => {
    const request = client();
    const { email, verificationCookie } = await signup(request, "known");
    const duplicate = await request("/api/auth/register", {
      json: { email, password },
      cookie: verificationCookie,
    });
    const fresh = await request("/api/auth/register", {
      json: { email: "new-probe@example.test", password },
      cookie: verificationCookie,
    });
    expect(duplicate.headers.getSetCookie().length).toBe(
      fresh.headers.getSetCookie().length,
    );
    expect([duplicate.status, await duplicate.json()]).toEqual([
      fresh.status,
      await fresh.json(),
    ]);

    const unknown = "absent@example.test";
    const wrongPassword = "a-different-password-for-testing";
    const rejected = await request("/api/auth/login", {
      json: { email, password: wrongPassword },
    });
    const missing = await request("/api/auth/login", {
      json: { email: unknown, password: wrongPassword },
    });
    expect(rejected.status).toBe(401);
    expect([missing.status, await missing.json()]).toEqual([
      rejected.status,
      await rejected.json(),
    ]);

    const resetKnown = await request("/api/auth/forgot-password", {
      json: { email },
    });
    const resetUnknown = await request("/api/auth/forgot-password", {
      json: { email: unknown },
    });
    expect([resetKnown.status, await resetKnown.json()]).toEqual([
      resetUnknown.status,
      await resetUnknown.json(),
    ]);
  });

  it("accepts one concurrent password reset and revokes existing sessions", async () => {
    const request = client();
    const { email, cookie } = await account(request);
    await successful(
      await request("/api/auth/forgot-password", { json: { email } }),
    );
    const token = await mailToken(request, email);
    const candidates = [
      "first-reset-candidate-strong",
      "second-reset-candidate-strong",
    ];
    const responses = await Promise.all(
      candidates.map((candidate) =>
        request("/api/auth/reset-password", {
          json: { token, password: candidate },
        }),
      ),
    );
    expect(responses.filter((response) => response.ok)).toHaveLength(1);
    const winningPassword =
      candidates[responses.findIndex((response) => response.ok)];
    if (!winningPassword) throw new Error("No password reset succeeded.");
    expect((await request("/api/session", { cookie })).status).toBe(401);
    expect(
      (await request("/api/auth/refresh", { method: "POST", cookie })).status,
    ).toBe(401);
    expect(
      (await request("/api/auth/login", { json: { email, password } })).status,
    ).toBe(401);
    await login(request, email, winningPassword);
  });

  it("refuses a reset token after issuing its replacement", async () => {
    const request = client();
    const { email, cookie } = await account(request);
    await successful(
      await request("/api/auth/forgot-password", { json: { email } }),
    );
    const token = await mailToken(request, email);
    await successful(
      await request("/api/auth/forgot-password", { json: { email } }),
    );
    const replacement = await mailToken(request, email);
    expect(replacement).not.toBe(token);
    const stale = await request("/api/auth/reset-password", {
      json: { token, password: "a-fresh-and-strong-password" },
    });
    expect(stale.ok).toBe(false);
    expect((await request("/api/session", { cookie })).status).toBe(200);
  });

  it("refuses a reset token at or after expiration", async () => {
    const request = client();
    const { email, cookie, user } = await account(request);
    await successful(
      await request("/api/auth/forgot-password", { json: { email } }),
    );
    const token = await mailToken(request, email);
    await env.DB.prepare(
      "UPDATE verification_tokens SET expires_at = 0 WHERE user_id = ? AND kind = 'reset'",
    )
      .bind(user.id)
      .run();
    const expired = await request("/api/auth/reset-password", {
      json: { token, password: "an-expired-password-reset-candidate" },
    });
    expect(expired.ok).toBe(false);
    expect((await request("/api/session", { cookie })).status).toBe(200);
    await login(request, email);
  });
});

describe("sessions", () => {
  it("rotates same-cookie refresh requests with one winner and disables old credentials", async () => {
    const request = client();
    const { cookie } = await account(request);
    const responses = await Promise.all([
      request("/api/auth/refresh", { method: "POST", cookie }),
      request("/api/auth/refresh", { method: "POST", cookie }),
    ]);
    expect(responses.filter((response) => response.ok)).toHaveLength(1);
    expect(
      responses.filter((response) => response.status === 401),
    ).toHaveLength(1);
    const winner = responses.find((response) => response.ok)!;
    const rotated = setCookies(winner);
    expect(rotated).not.toBe(cookie);
    expect((await request("/api/session", { cookie })).status).toBe(401);
    expect(
      (await request("/api/auth/refresh", { method: "POST", cookie })).status,
    ).toBe(401);
    expect((await request("/api/session", { cookie: rotated })).status).toBe(
      200,
    );
  });

  it("can sign out with the previous refresh cookie after an in-flight rotation", async () => {
    const request = client();
    const { cookie } = await account(request);
    const rotated = await request("/api/auth/refresh", {
      method: "POST",
      cookie,
    });
    await successful(rotated.clone());
    await successful(
      await request("/api/auth/logout", { method: "POST", cookie }),
    );
    expect(
      (await request("/api/session", { cookie: setCookies(rotated) })).status,
    ).toBe(401);
    expect(
      (
        await request("/api/auth/refresh", {
          method: "POST",
          cookie: setCookies(rotated),
        })
      ).status,
    ).toBe(401);
  });

  it("refreshes an expired access cookie only before the absolute session deadline", async () => {
    const request = client();
    const { cookie, session } = await account(request);
    await env.DB.prepare(
      "UPDATE sessions SET access_expires_at = 0 WHERE id = ?",
    )
      .bind(session.id)
      .run();
    expect((await request("/api/session", { cookie })).status).toBe(401);
    const refreshed = await request("/api/auth/refresh", {
      method: "POST",
      cookie,
    });
    await successful(refreshed.clone());
    const refreshedCookie = setCookies(refreshed);
    expect(
      (await request("/api/session", { cookie: refreshedCookie })).status,
    ).toBe(200);
    await env.DB.prepare(
      "UPDATE sessions SET refresh_expires_at = 0 WHERE id = ?",
    )
      .bind(session.id)
      .run();
    expect(
      (await request("/api/session", { cookie: refreshedCookie })).status,
    ).toBe(401);
    expect(
      (
        await request("/api/auth/refresh", {
          method: "POST",
          cookie: refreshedCookie,
        })
      ).status,
    ).toBe(401);
  });

  it("revokes only the signing-out device and supports revoking all remaining devices", async () => {
    const request = client();
    const first = await account(request);
    const second = await login(request, first.email);
    const third = await login(request, first.email);
    await successful(
      await request("/api/auth/logout", {
        method: "POST",
        cookie: first.cookie,
      }),
    );
    expect(
      (await request("/api/session", { cookie: first.cookie })).status,
    ).toBe(401);
    expect((await request("/api/session", { cookie: second })).status).toBe(
      200,
    );
    await successful(
      await request("/api/auth/logout-all", { method: "POST", cookie: second }),
    );
    expect((await request("/api/session", { cookie: second })).status).toBe(
      401,
    );
    expect((await request("/api/session", { cookie: third })).status).toBe(401);
  });

  it("limits explicit device revocation to the signed-in account", async () => {
    const request = client();
    const alice = await account(request, "alice");
    const bob = await account(request, "bob");
    const otherDevice = await login(request, alice.email);
    const other = await json<Session>(
      await request("/api/session", { cookie: otherDevice }),
    );

    const foreign = await request(`/api/account/sessions/${bob.session.id}`, {
      method: "DELETE",
      cookie: alice.cookie,
    });
    expect(foreign.status).toBe(404);
    expect((await request("/api/session", { cookie: bob.cookie })).status).toBe(
      200,
    );

    await successful(
      await request(`/api/account/sessions/${other.session.id}`, {
        method: "DELETE",
        cookie: alice.cookie,
      }),
    );
    expect(
      (await request("/api/session", { cookie: otherDevice })).status,
    ).toBe(401);
    expect(
      (await request("/api/session", { cookie: alice.cookie })).status,
    ).toBe(200);
  });
  it("deletes the account and revokes previously issued credentials", async () => {
    const request = client();
    const { email, cookie, user } = await account(request);
    const otherDevice = await login(request, email);
    await successful(
      await request("/api/account", {
        method: "DELETE",
        cookie,
        json: { confirm: true },
      }),
    );
    expect((await request("/api/session", { cookie })).status).toBe(401);
    expect(
      (
        await request("/api/auth/refresh", {
          method: "POST",
          cookie: otherDevice,
        })
      ).status,
    ).toBe(401);
    expect(
      (await request("/api/auth/login", { json: { email, password } })).status,
    ).toBe(401);
    expect(
      await env.DB.prepare("SELECT id FROM users WHERE id = ?")
        .bind(user.id)
        .first(),
    ).toBeNull();
  });
});

describe("request boundaries", () => {
  it("sets host-only Secure cookies and disables the dev mailbox over the production origin", async () => {
    const request = client();
    const { email } = await account(request);
    const productionOrigin = "https://auth.example.test";
    const bindings = { APP_ORIGIN: productionOrigin };
    const response = await request("/api/auth/login", {
      json: { email, password },
      origin: productionOrigin,
      bindings,
    });
    await successful(response.clone());
    const cookies = response.headers.getSetCookie();
    expect(cookies).toEqual([
      expect.stringMatching(/^__Host-lucid_(access|refresh)=/),
      expect.stringMatching(/^__Host-lucid_(access|refresh)=/),
    ]);
    expect(setCookies(response)).toContain("__Host-lucid_access=");
    expect(setCookies(response)).toContain("__Host-lucid_refresh=");
    for (const cookie of cookies) {
      expect(cookie).toMatch(/; Secure\b/i);
      expect(cookie).toMatch(/; HttpOnly\b/i);
      expect(cookie).toMatch(/; SameSite=Lax\b/i);
      expect(cookie).toMatch(/; Path=\/(?:;|$)/i);
      expect(cookie).not.toMatch(/; Domain=/i);
    }
    const devMailbox = await request(
      `/api/dev/mail?email=${encodeURIComponent(email)}`,
      { bindings },
    );
    expect(devMailbox.status).toBe(404);
  });

  it("rejects cross-origin and origin-less mutations before they alter a session", async () => {
    const request = client();
    const { cookie } = await account(request);
    for (const suppliedOrigin of [
      null,
      "null",
      "http://localhost:8787.other.test",
      "https://attacker.example",
    ]) {
      const response = await request("/api/auth/logout-all", {
        method: "POST",
        cookie,
        origin: suppliedOrigin,
      });
      expect(response.status).toBe(403);
    }
    expect((await request("/api/session", { cookie })).status).toBe(200);
  });

  it("rejects malformed bodies with a safe structured error", async () => {
    const request = client();
    for (const rawBody of [
      "{",
      "null",
      '{"email":{"$ne":null},"password":[]}',
      '{"email":"a@example.test","password":"short"}',
    ]) {
      const response = await request("/api/auth/register", { rawBody });
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({
        error: { code: expect.any(String), message: expect.any(String) },
      });
    }
  });

  it("rejects oversized JSON before parsing it", async () => {
    const request = client();
    const response = await request("/api/auth/register", {
      json: { email: "large-body@example.test", password: "A".repeat(25_000) },
    });
    expect(response.status).toBe(413);
    expect(await response.json()).toMatchObject({
      error: { code: "BODY_TOO_LARGE" },
    });
  });

  it("enforces one per-account login limit across multiple IPs", async () => {
    const request = client();
    const email = `throttle-${crypto.randomUUID()}@example.test`;
    const responses = await Promise.all(
      Array.from({ length: 10 }, (_, index) =>
        request("/api/auth/login", {
          json: { email: index % 2 ? email.toUpperCase() : email, password },
          ip: `198.51.100.${index + 1}`,
        }),
      ),
    );
    expect(
      responses.filter((response) => response.status === 401),
    ).toHaveLength(8);
    expect(
      responses.filter((response) => response.status === 429),
    ).toHaveLength(2);
  });
});
