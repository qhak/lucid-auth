import {
  createExecutionContext,
  waitOnExecutionContext,
} from "cloudflare:test";
import { env } from "cloudflare:workers";
import { expect } from "vitest";
import type { Env } from "../src/core";
import worker from "../src/index";

export const origin = "http://localhost:8787";
export const password = "ocean-wind-canoe-galaxies";
let nextIp = 0;

export type RequestOptions = {
  method?: string;
  json?: unknown;
  rawBody?: string;
  cookie?: string;
  origin?: string | null;
  ip?: string;
  bindings?: Partial<Env>;
};

export function client() {
  const defaultIp = `192.0.2.${++nextIp}`;
  return async function request(
    path: string,
    options: RequestOptions = {},
  ): Promise<Response> {
    const headers = new Headers({
      "CF-Connecting-IP": options.ip ?? defaultIp,
    });
    const body =
      options.json === undefined
        ? options.rawBody
        : JSON.stringify(options.json);
    const method = options.method ?? (body === undefined ? "GET" : "POST");
    if (options.origin !== null && method !== "GET") {
      headers.set("Origin", options.origin ?? origin);
    }
    if (body !== undefined) headers.set("Content-Type", "application/json");
    if (options.cookie) headers.set("Cookie", options.cookie);
    const ctx = createExecutionContext();
    const response = await worker.fetch(
      new Request(new URL(path, options.bindings?.APP_ORIGIN ?? origin), {
        method,
        headers,
        body,
      }),
      { ...env, ...options.bindings },
      ctx,
    );
    await waitOnExecutionContext(ctx);
    return response;
  };
}

export type Client = ReturnType<typeof client>;
export type Session = {
  user: { id: string; email: string };
  session: { id: string; expiresAt: number };
};

export async function json<T>(response: Response): Promise<T> {
  expect(response.ok, await response.clone().text()).toBe(true);
  return (await response.json()) as T;
}

export async function successful(response: Response): Promise<void> {
  expect(response.ok, await response.text()).toBe(true);
}

export function setCookies(response: Response): string {
  return response.headers
    .getSetCookie()
    .map((value) => value.split(";")[0])
    .join("; ");
}

export async function mailToken(request: Client, email: string) {
  const { items } = await json<{ items: Array<{ token: string }> }>(
    await request(`/api/dev/mail?email=${encodeURIComponent(email)}`),
  );
  const token = items[0]?.token;
  if (!token)
    throw new Error("Expected a message in the local development mailbox.");
  return token;
}

export async function signup(request: Client, prefix = "user") {
  const email = `${prefix}-${crypto.randomUUID()}@example.test`;
  const response = await request("/api/auth/register", {
    json: { email, password },
  });
  await successful(response.clone());
  const verificationCookie = setCookies(response);
  expect(verificationCookie).toContain("lucid_verify=");
  return { email, verificationCookie };
}

export async function activate(
  request: Client,
  email: string,
  verificationCookie: string,
) {
  const token = await mailToken(request, email);
  await successful(
    await request("/api/auth/verify", {
      json: { token },
      cookie: verificationCookie,
    }),
  );
}

export async function login(
  request: Client,
  email: string,
  candidate = password,
) {
  const response = await request("/api/auth/login", {
    json: { email, password: candidate },
  });
  await successful(response.clone());
  const cookie = setCookies(response);
  expect(cookie).toContain("lucid_access=");
  expect(cookie).toContain("lucid_refresh=");
  return cookie;
}

export async function account(request: Client, prefix?: string) {
  const { email, verificationCookie } = await signup(request, prefix);
  await activate(request, email, verificationCookie);
  const cookie = await login(request, email);
  const { user, session } = await json<Session>(
    await request("/api/session", { cookie }),
  );
  expect(user.email).toBe(email);
  return { email, cookie, user, session };
}
