export type Role = "owner" | "admin" | "member" | "viewer";
export type Permission =
  | "org:read"
  | "org:write"
  | "members:write"
  | "teams:write"
  | "sessions:write"
  | "audit:read";

export type Session = {
  user: { id: string; email: string };
  session: { id: string; expiresAt: number };
};

export type ErrorResponse = { error: { code: string; message: string } };
type Credentials = { email: string; password: string };
type Fetcher = typeof fetch;

export class LucidError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
    this.name = "LucidError";
  }
}

async function result<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const payload = (await response.json().catch(() => undefined)) as
      Partial<ErrorResponse> | undefined;
    throw new LucidError(
      response.status,
      payload?.error?.code ?? "HTTP_ERROR",
      payload?.error?.message ?? "Lucid Auth request failed.",
    );
  }
  return (await response.json()) as T;
}

export function createLucidClient(
  options: { basePath?: string; fetcher?: Fetcher } = {},
) {
  const base = options.basePath ?? "/api";
  const send = options.fetcher ?? fetch;
  let refreshing: Promise<{ ok: true }> | undefined;

  async function request<T>(path: string, method = "GET", data?: object) {
    return result<T>(
      await send(`${base}${path}`, {
        method,
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        ...(data
          ? {
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(data),
            }
          : {}),
      }),
    );
  }

  return {
    register: (credentials: Credentials) =>
      request<{ ok: true }>("/auth/register", "POST", credentials),
    login: (credentials: Credentials) =>
      request<{ ok: true }>("/auth/login", "POST", credentials),
    verifyEmail: (token: string) =>
      request<{ ok: true }>("/auth/verify", "POST", { token }),
    requestPasswordReset: (email: string) =>
      request<{ ok: true }>("/auth/forgot-password", "POST", { email }),
    resetPassword: (token: string, password: string) =>
      request<{ ok: true }>("/auth/reset-password", "POST", {
        token,
        password,
      }),
    logout: () => request<{ ok: true }>("/auth/logout", "POST"),
    logoutAll: () => request<{ ok: true }>("/auth/logout-all", "POST"),
    session: () => request<Session>("/session"),
    refresh: () => {
      refreshing ??= request<{ ok: true }>("/auth/refresh", "POST").finally(
        () => {
          refreshing = undefined;
        },
      );
      return refreshing;
    },
    organizations: () =>
      request<{ items: { id: string; name: string; role: Role }[] }>("/orgs"),
    permissions: (organization: string) =>
      request<{ permissions: Permission[] }>(
        `/orgs/${encodeURIComponent(organization)}/permissions`,
      ),
  };
}

export function createLucidServer(origin: string, send: Fetcher = fetch) {
  const canonical = new URL(origin).origin;
  async function request<T>(path: string, cookie: string) {
    return result<T>(
      await send(new URL(path, canonical), {
        headers: { Cookie: lucidCookies(cookie) },
        cache: "no-store",
        redirect: "error",
      }),
    );
  }
  return {
    async verifySession(cookie: string): Promise<Session | null> {
      try {
        return await request<Session>("/api/session", cookie);
      } catch (error) {
        if (error instanceof LucidError && error.status === 401) return null;
        throw error;
      }
    },
    async hasPermission(
      cookie: string,
      organization: string,
      permission: Permission,
    ): Promise<boolean> {
      try {
        const { permissions } = await request<{ permissions: Permission[] }>(
          `/api/orgs/${encodeURIComponent(organization)}/permissions`,
          cookie,
        );
        return permissions.includes(permission);
      } catch (error) {
        if (
          error instanceof LucidError &&
          [401, 403, 404].includes(error.status)
        )
          return false;
        throw error;
      }
    },
  };
}

export function lucidCookies(header: string) {
  return header
    .split(";")
    .map((pair) => pair.trim())
    .filter((pair) =>
      /^(?:__Host-)?lucid_(?:access|refresh)=[a-f0-9]{64}$/.test(pair),
    )
    .join("; ");
}
