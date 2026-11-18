import { useEffect, useState } from "react";

export type Session = {
  user: { id: string; email: string };
  session: { id: string; expiresAt: number };
};
export type Settings = {
  google: boolean;
  passkeys: boolean;
  devMail?: boolean;
};
export type Role = "owner" | "admin" | "member" | "viewer";
export type Organization = { id: string; name: string; role: Role };
export type Member = { id: string; email: string; role: Role };
export type Team = { id: string; name: string };
export type Device = { id: string; createdAt: number; expiresAt: number };
export type OrgDevice = Device & { email: string };
export type AuditEvent = {
  id: string;
  action: string;
  actorEmail: string | null;
  subject: string | null;
  createdAt: number;
};
export type Overview = {
  users: number;
  sessions: number;
  events: number;
  teams: number;
};
export type Items<T> = { items: T[] };
export type Page<T> = Items<T> & { total: number };
export type SecurityOptions = {
  method?: string;
  body?: unknown;
  renew?: boolean;
};

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

const renewed = { pending: undefined as Promise<boolean> | undefined };

async function transport(
  path: string,
  { method = "GET", body }: SecurityOptions = {},
) {
  const headers = new Headers({ Accept: "application/json" });
  if (body !== undefined) headers.set("Content-Type", "application/json");
  return fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
    cache: "no-store",
  });
}

async function refresh(): Promise<boolean> {
  async function exchange() {
    if ((await transport("/api/session")).ok) return true;
    return (await transport("/api/auth/refresh", { method: "POST" })).ok;
  }

  renewed.pending ??= (
    navigator.locks
      ? navigator.locks.request("lucid-session-refresh", exchange)
      : exchange()
  ).finally(() => {
    renewed.pending = undefined;
  });
  return renewed.pending;
}

export async function api<T = void>(
  path: string,
  options: SecurityOptions = {},
): Promise<T> {
  let response = await transport(path, options);
  if (response.status === 401 && options.renew !== false && (await refresh())) {
    response = await transport(path, options);
  }
  if (!response.ok) {
    const data = (await response.json().catch(() => null)) as {
      error?: { message?: string };
    } | null;
    if (
      response.status === 401 &&
      options.renew !== false &&
      path !== "/api/session"
    ) {
      window.dispatchEvent(new Event("lucid-session-expired"));
    }
    throw new ApiError(
      response.status,
      data?.error?.message ?? `Request failed (${response.status}).`,
    );
  }
  if (
    response.status === 204 ||
    !response.headers.get("Content-Type")?.includes("json")
  )
    return undefined as T;
  return response.json() as Promise<T>;
}

export function message(error: unknown): string {
  return error instanceof ApiError
    ? error.message
    : "The request could not be completed. Check your connection and try again.";
}

type Remote<T> = { data: T; error?: never } | { error: unknown; data?: never };

export function useRemote<T>(
  path: string,
  revision = 0,
  retain = true,
): Remote<T> | undefined {
  const key = `${path}:${revision}`;
  const [result, setResult] = useState<{
    path: string;
    key: string;
    value: Remote<T>;
  }>();
  useEffect(() => {
    if (path.length === 0) return;
    let current = true;
    api<T>(path).then(
      (data) => {
        if (current) setResult({ path, key, value: { data } });
      },
      (error: unknown) => {
        if (current) setResult({ path, key, value: { error } });
      },
    );
    return () => {
      current = false;
    };
  }, [path, key]);
  if (
    result?.key === key ||
    (retain && result?.path === path && "data" in result.value)
  )
    return result.value;
  return undefined;
}

export function useOperation(onSuccess?: () => void) {
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<{
    tone: "error" | "success";
    text: string;
  }>();
  async function run(work: () => Promise<unknown>, success?: string) {
    setBusy(true);
    setStatus(undefined);
    try {
      await work();
      if (success) setStatus({ tone: "success", text: success });
      onSuccess?.();
    } catch (error) {
      setStatus({ tone: "error", text: message(error) });
    } finally {
      setBusy(false);
    }
  }
  return { busy, run, status, clear: () => setStatus(undefined) };
}

export function time(value: number): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(value);
}

export const orgApi = (id: string) => `/api/orgs/${encodeURIComponent(id)}`;
