"use client";

import { useState } from "react";
import type { FormEvent } from "react";
import { useRouter } from "next/navigation";
import { createLucidClient } from "../../../sdk";

const lucid = createLucidClient({ basePath: "/api/lucid" });

export function Login() {
  const router = useRouter();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setBusy(true);
    setError("");
    try {
      await lucid.login({
        email: String(data.get("email")),
        password: String(data.get("password")),
      });
      router.refresh();
    } catch (error) {
      setError(error instanceof Error ? error.message : "Could not sign in.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <form onSubmit={submit}>
        <label>
          Email{" "}
          <input name="email" type="email" autoComplete="username" required />
        </label>
        <label>
          Password{" "}
          <input
            name="password"
            type="password"
            autoComplete="current-password"
            required
          />
        </label>
        <button disabled={busy}>Sign in</button>
      </form>
      <button
        disabled={busy}
        onClick={async () => {
          try {
            await lucid.refresh();
            router.refresh();
          } catch {
            setError("Your session has expired. Sign in to continue.");
          }
        }}
      >
        Resume session
      </button>
      {error && <p role="alert">{error}</p>}
    </>
  );
}

export function Logout() {
  const router = useRouter();
  const [error, setError] = useState("");
  return (
    <>
      <button
        onClick={async () => {
          try {
            await lucid.logout();
            router.refresh();
          } catch {
            setError("Sign-out failed. Try again.");
          }
        }}
      >
        Sign out
      </button>
      {error && <p role="alert">{error}</p>}
    </>
  );
}
