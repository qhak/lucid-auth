import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import { useState } from "react";
import type { FormEvent } from "react";
import { api, ApiError, type Items, type Settings, useOperation } from "./api";
import { Brand, Icon, Notice } from "./components";

export type AuthMode = "login" | "register" | "forgot" | "verify" | "reset";

export type AuthLink = { mode: "verify" | "reset"; token: string };

const modes = {
  login: {
    title: "Sign in to Lucid Auth",
    detail: "Access your organizations and security activity.",
    action: "Sign in",
  },
  register: {
    title: "Create your account",
    detail: "Register with your email to get started.",
    action: "Create account",
  },
  forgot: {
    title: "Reset your password",
    detail: "Request a password reset link by email.",
    action: "Send reset link",
  },
  verify: {
    title: "Verify your email",
    detail: "Confirm your email address to activate your account.",
    action: "Verify email",
  },
  reset: {
    title: "Set a new password",
    detail: "Changing your password will revoke your active sessions.",
    action: "Set password",
  },
};

export async function passkey(mode: "register" | "login") {
  try {
    const path = `/api/auth/passkeys/${mode}`;
    const optionsRequest = { method: "POST", renew: mode === "register" };
    if (mode === "register") {
      const { id, options } = await api<{
        id: string;
        options: PublicKeyCredentialCreationOptionsJSON;
      }>(`${path}/options`, optionsRequest);
      const response = await startRegistration({ optionsJSON: options });
      await api(`${path}/verify`, { method: "POST", body: { id, response } });
    } else {
      const { id, options } = await api<{
        id: string;
        options: PublicKeyCredentialRequestOptionsJSON;
      }>(`${path}/options`, optionsRequest);
      const response = await startAuthentication({ optionsJSON: options });
      await api(`${path}/verify`, {
        method: "POST",
        body: { id, response },
        renew: false,
      });
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      0,
      "The passkey operation did not complete. Try again or use your password.",
    );
  }
}

type DevMessage = { token: string; kind: string; createdAt: number };

function LocalInbox({
  email,
  open,
}: {
  email: string;
  open: (link: AuthLink) => void;
}) {
  const [mail, setMail] = useState<DevMessage[]>();
  const operation = useOperation();
  return (
    <details className="local-mail">
      <summary>Local development inbox</summary>
      <button
        className="button secondary"
        type="button"
        disabled={!email || operation.busy}
        onClick={() =>
          void operation.run(async () => {
            const result = await api<Items<DevMessage>>(
              `/api/dev/mail?email=${encodeURIComponent(email)}`,
              { renew: false },
            );
            setMail(result.items);
          })
        }
      >
        Load messages for this email
      </button>
      <Notice status={operation.status} />
      {mail?.length === 0 && <p>No messages for this address.</p>}
      {mail && mail.length > 0 && (
        <ul>
          {mail.map((item) => {
            const mode = item.kind.includes("reset") ? "reset" : "verify";
            return (
              <li key={item.token}>
                <button
                  className="text-button"
                  type="button"
                  onClick={() => open({ mode, token: item.token })}
                >
                  {mode === "reset"
                    ? "Open reset link"
                    : "Open verification link"}
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </details>
  );
}

export function AuthScreen({
  link,
  settings,
  oauthError,
  onSession,
}: {
  link?: AuthLink;
  settings?: Settings;
  oauthError: boolean;
  onSession: () => void;
}) {
  const [mode, setMode] = useState<AuthMode>(link?.mode ?? "login");
  const [token, setToken] = useState(link?.token ?? "");
  const [email, setEmail] = useState("");
  const [notice, setNotice] = useState<
    { tone: "error" | "success"; text: string } | undefined
  >(
    oauthError
      ? {
          tone: "error",
          text: "Google sign-in could not be completed. Try again.",
        }
      : undefined,
  );
  const operation = useOperation();
  const copy = modes[mode];

  function choose(next: AuthMode, nextToken = "") {
    setMode(next);
    setToken(nextToken);
    setNotice(undefined);
    operation.clear();
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const password = data.get("password");
    const action =
      mode === "forgot"
        ? "forgot-password"
        : mode === "reset"
          ? "reset-password"
          : mode;
    const body =
      mode === "verify"
        ? { token }
        : mode === "reset"
          ? { token, password }
          : mode === "forgot"
            ? { email }
            : { email, password };
    await operation.run(async () => {
      setNotice(undefined);
      await api(`/api/auth/${action}`, { method: "POST", body, renew: false });
      form.reset();
      if (mode === "login") return onSession();
      if (mode === "verify" || mode === "reset") {
        choose("login");
        setNotice({
          tone: "success",
          text:
            mode === "verify"
              ? "Email verified. You can sign in now."
              : "Password updated. Sign in again.",
        });
        return;
      }
      setNotice({
        tone: "success",
        text:
          mode === "register"
            ? "If this address can be registered, we’ll send verification instructions."
            : "If this address has an eligible account, we’ll send a reset link.",
      });
    });
  }

  const hasEmail = mode === "login" || mode === "register" || mode === "forgot";
  const hasPassword =
    mode === "login" || mode === "register" || mode === "reset";
  return (
    <main className="auth-shell">
      <section className="auth-story" aria-label="Lucid Auth">
        <Brand />
        <div className="auth-art" aria-hidden="true">
          <div className="art-orb" />
          <div className="art-ring" />
          <span className="brand-mark art-mark">
            <i />
          </span>
        </div>
        <div className="auth-story-copy">
          <p className="eyebrow">
            <i /> Identity console
          </p>
          <h2>
            Identity, under
            <br />
            your control.
          </h2>
          <p>
            Self-hosted authentication and access management for Cloudflare
            Workers.
          </p>
        </div>
      </section>
      <section className="auth-content">
        <div className="auth-card">
          <div className="mobile-brand">
            <Brand />
          </div>
          <h1>{copy.title}</h1>
          <p className="lede">{copy.detail}</p>
          <Notice status={operation.status ?? notice} />
          <form
            className="stack-form"
            key={mode}
            onSubmit={(event) => void submit(event)}
          >
            {hasEmail && (
              <label>
                Email address
                <input
                  type="email"
                  autoComplete="email"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  required
                  maxLength={254}
                />
              </label>
            )}
            {hasPassword && (
              <label>
                Password
                <input
                  name="password"
                  type="password"
                  autoComplete={
                    mode === "login" ? "current-password" : "new-password"
                  }
                  required
                  maxLength={128}
                  minLength={mode === "login" ? undefined : 15}
                />
                {mode !== "login" && <small>Use at least 15 characters.</small>}
              </label>
            )}
            {mode === "login" && (
              <button
                className="text-button forgot"
                type="button"
                disabled={operation.busy}
                onClick={() => choose("forgot")}
              >
                Forgot password?
              </button>
            )}
            <button
              className="button primary"
              type="submit"
              disabled={operation.busy}
            >
              {operation.busy ? "Working…" : copy.action}
              <Icon name="arrow" />
            </button>
          </form>
          {mode === "login" &&
            (settings?.google ||
              (settings?.passkeys && browserSupportsWebAuthn())) && (
              <div className="alternate-auth">
                <div className="divider-label">or</div>
                {settings.google && (
                  <button
                    className="button secondary"
                    disabled={operation.busy}
                    onClick={() =>
                      void operation.run(async () => {
                        const { url } = await api<{ url: string }>(
                          "/api/auth/google/start",
                          { method: "POST", renew: false },
                        );
                        location.assign(url);
                      })
                    }
                  >
                    <Icon name="google" /> Continue with Google
                  </button>
                )}
                {settings.passkeys && browserSupportsWebAuthn() && (
                  <button
                    className="button secondary"
                    disabled={operation.busy}
                    onClick={() =>
                      void operation.run(async () => {
                        await passkey("login");
                        onSession();
                      })
                    }
                  >
                    <Icon name="key" /> Sign in with a passkey
                  </button>
                )}
              </div>
            )}
          <p className="auth-switch">
            {mode === "login" ? "New to Lucid Auth? " : ""}
            <button
              className="text-button"
              type="button"
              disabled={operation.busy}
              onClick={() => choose(mode === "login" ? "register" : "login")}
            >
              {mode === "login" ? "Create an account" : "Back to sign in"}
            </button>
          </p>
          {settings?.devMail && hasEmail && (
            <LocalInbox
              key={email}
              email={email}
              open={(entry) => choose(entry.mode, entry.token)}
            />
          )}
        </div>
      </section>
    </main>
  );
}
