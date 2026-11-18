import { env } from "cloudflare:workers";
import { base64url, exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { account, client, json, origin, setCookies } from "./http";

const encoder = new TextEncoder();
const googleConfig = {
  GOOGLE_CLIENT_ID: "test-client",
  GOOGLE_CLIENT_SECRET: "test-secret",
};

describe("Google OIDC", () => {
  it("binds state to a browser and consumes it exactly once", async () => {
    const request = client();
    const start = await request("/api/auth/google/start", {
      json: {},
      bindings: googleConfig,
    });
    const { url } = await json<{ url: string }>(start);
    const query = new URL(url).searchParams;
    const state = query.get("state");
    expect(query.get("redirect_uri")).toBe(
      origin + "/api/auth/google/callback",
    );
    expect(query.get("code_challenge_method")).toBe("S256");
    expect(query.get("code_challenge")).toMatch(/^[\w-]{43}$/);
    expect(query.get("nonce")).toMatch(/^[a-f0-9]{64}$/);
    expect(state).toMatch(/^[a-f0-9]{64}$/);
    const route = "/api/auth/google/callback?error=access_denied&state=";
    for (const [candidate, cookie] of [
      ["f".repeat(64), setCookies(start)],
      [state, ""],
    ]) {
      const rejected = await request(route + candidate, {
        cookie: cookie ?? "",
        bindings: googleConfig,
      });
      expect(rejected.status).toBe(302);
      expect(rejected.headers.get("Location")).toBe("/?auth=google_failed");
    }
    expect(
      await env.DB.prepare(
        "SELECT count(*) AS count FROM flows WHERE kind = 'google'",
      ).first("count"),
    ).toBe(1);
    const valid = await request(route + state, {
      cookie: setCookies(start),
      bindings: googleConfig,
    });
    expect(valid.headers.get("Location")).toBe("/?auth=google_failed");
    expect(
      await env.DB.prepare(
        "SELECT count(*) AS count FROM flows WHERE kind = 'google'",
      ).first("count"),
    ).toBe(0);
    const replay = await request(route + state, {
      cookie: setCookies(start),
      bindings: googleConfig,
    });
    expect(replay.headers.get("Location")).toBe("/?auth=google_failed");
  });

  it("checks signed claims and PKCE and rejects linking by email", async () => {
    const request = client();
    const { publicKey, privateKey } = await generateKeyPair("RS256", {
      extractable: true,
    });
    const key = {
      ...(await exportJWK(publicKey)),
      kid: "google-test",
      alg: "RS256",
      use: "sig",
    };
    const sign = (nonce: string, sub: string, email: string) =>
      new SignJWT({ nonce, email, email_verified: true })
        .setProtectedHeader({ alg: "RS256", kid: key.kid })
        .setIssuer("https://accounts.google.com")
        .setAudience(googleConfig.GOOGLE_CLIENT_ID)
        .setIssuedAt()
        .setExpirationTime("5m")
        .setSubject(sub)
        .sign(privateKey);
    let token = "";
    let tokenRequest: URLSearchParams | undefined;
    vi.stubGlobal(
      "fetch",
      async (input: string | URL | Request, init?: RequestInit) => {
        if (String(input) === "https://oauth2.googleapis.com/token") {
          tokenRequest = new URLSearchParams(String(init?.body));
          return Response.json({ id_token: token });
        }
        if (String(input) === "https://www.googleapis.com/oauth2/v3/certs") {
          return Response.json({ keys: [key] });
        }
        throw new Error("Unexpected outbound request");
      },
    );
    const complete = async (sub: string, email: string, wrongNonce = false) => {
      const start = await request("/api/auth/google/start", {
        json: {},
        bindings: googleConfig,
      });
      const { url } = await json<{ url: string }>(start);
      const query = new URL(url).searchParams;
      token = await sign(
        wrongNonce ? "f".repeat(64) : (query.get("nonce") ?? ""),
        sub,
        email,
      );
      const result = await request(
        "/api/auth/google/callback?code=fixture&state=" + query.get("state"),
        {
          cookie: setCookies(start),
          bindings: googleConfig,
        },
      );
      expect(tokenRequest?.get("redirect_uri")).toBe(
        origin + "/api/auth/google/callback",
      );
      expect(tokenRequest?.get("code")).toBe("fixture");
      const challenge = base64url.encode(
        await hash(encoder.encode(tokenRequest?.get("code_verifier") ?? "")),
      );
      expect(challenge).toBe(query.get("code_challenge"));
      return result;
    };
    try {
      const email = "oauth-fixture@gmail.com";
      expect(
        (await complete("first-subject", email, true)).headers.get("Location"),
      ).toBe("/?auth=google_failed");
      const signedIn = await complete("first-subject", email);
      expect(signedIn.headers.get("Location")).toBe("/");
      const session = await request("/api/session", {
        cookie: setCookies(signedIn),
      });
      expect(
        (await json<{ user: { email: string } }>(session)).user.email,
      ).toBe(email);
      expect(
        (await complete("second-subject", email)).headers.get("Location"),
      ).toBe("/?auth=google_failed");
      const count = await env.DB.prepare(
        "SELECT count(*) AS count FROM oauth_identities",
      ).first("count");
      expect(count).toBe(1);
    } finally {
      vi.unstubAllGlobals();
    }
  }, 20_000);
});

function concat(...chunks: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(
    chunks.reduce((size, chunk) => size + chunk.length, 0),
  );
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

// The fixture encodes only the CBOR types used by a none-attestation RSA credential.
function cborBytes(data: Uint8Array) {
  const prefix =
    data.length < 24
      ? Uint8Array.of(0x40 + data.length)
      : data.length < 256
        ? Uint8Array.of(0x58, data.length)
        : Uint8Array.of(0x59, data.length >> 8, data.length & 255);
  return concat(prefix, data);
}

function cborText(text: string) {
  return concat(Uint8Array.of(0x60 + text.length), encoder.encode(text));
}

async function hash(value: Uint8Array<ArrayBuffer>) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", value));
}

describe("WebAuthn", () => {
  it("registers and verifies a signed discoverable credential, then rejects bad origins, RP IDs and replay", async () => {
    const request = client();
    const { cookie: session } = await account(request, "passkey");
    const registration = await request("/api/auth/passkeys/register/options", {
      cookie: session,
      json: {},
    });
    const { id: registrationId, options: create } = await json<{
      id: string;
      options: { challenge: string; rp: { id: string }; user: { id: string } };
    }>(registration);
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const encodedId = base64url.encode(credentialId);
    const key = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: Uint8Array.of(1, 0, 1),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );
    const jwk = await crypto.subtle.exportKey("jwk", key.publicKey);
    // COSE RSA public key: {1: 3, 3: -257, -1: n, -2: e}.
    if (!jwk.n || !jwk.e)
      throw new Error("RSA fixture missing modulus or exponent");
    const coseKey = concat(
      Uint8Array.of(0xa4, 1, 3, 3, 0x39, 1, 0, 0x20),
      cborBytes(base64url.decode(jwk.n)),
      Uint8Array.of(0x21),
      cborBytes(base64url.decode(jwk.e)),
    );
    const rpHash = await hash(encoder.encode(create.rp.id));
    const registrationAuthData = concat(
      rpHash,
      Uint8Array.of(0x45, 0, 0, 0, 0),
      new Uint8Array(16),
      Uint8Array.of(0, credentialId.length),
      credentialId,
      coseKey,
    );
    const attestation = concat(
      Uint8Array.of(0xa3),
      cborText("fmt"),
      cborText("none"),
      cborText("attStmt"),
      Uint8Array.of(0xa0),
      cborText("authData"),
      cborBytes(registrationAuthData),
    );
    const registrationClient = base64url.encode(
      JSON.stringify({
        type: "webauthn.create",
        challenge: create.challenge,
        origin,
        crossOrigin: false,
      }),
    );
    const finishRegistration = await request(
      "/api/auth/passkeys/register/verify",
      {
        cookie: session,
        json: {
          id: registrationId,
          response: {
            id: encodedId,
            rawId: encodedId,
            type: "public-key",
            clientExtensionResults: {},
            response: {
              clientDataJSON: registrationClient,
              attestationObject: base64url.encode(attestation),
            },
          },
        },
      },
    );
    expect(finishRegistration.status).toBe(200);

    const authenticate = async (
      clientOrigin: string,
      rpIdHash: Uint8Array,
      flags: number,
      counter: number,
    ) => {
      const begin = await request("/api/auth/passkeys/login/options", {
        json: {},
      });
      const { id, options } = await json<{
        id: string;
        options: { challenge: string };
      }>(begin);
      const client = encoder.encode(
        JSON.stringify({
          type: "webauthn.get",
          challenge: options.challenge,
          origin: clientOrigin,
          crossOrigin: false,
        }),
      );
      const authData = concat(rpIdHash, Uint8Array.of(flags, 0, 0, 0, counter));
      const signature = await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        key.privateKey,
        concat(authData, await hash(client)),
      );
      const data = {
        id,
        response: {
          id: encodedId,
          rawId: encodedId,
          type: "public-key",
          clientExtensionResults: {},
          response: {
            clientDataJSON: base64url.encode(client),
            authenticatorData: base64url.encode(authData),
            signature: base64url.encode(new Uint8Array(signature)),
            userHandle: create.user.id,
          },
        },
      };
      const verify = () =>
        request("/api/auth/passkeys/login/verify", {
          cookie: setCookies(begin),
          json: data,
        });
      return { result: await verify(), verify };
    };

    expect(
      (await authenticate("https://invalid.example", rpHash, 0x05, 1)).result
        .status,
    ).toBe(401);
    expect(
      (await authenticate(origin, new Uint8Array(32), 0x05, 1)).result.status,
    ).toBe(401);
    expect((await authenticate(origin, rpHash, 0x01, 1)).result.status).toBe(
      401,
    );
    const counterless = await authenticate(origin, rpHash, 0x05, 0);
    expect(counterless.result.status).toBe(200);
    expect((await counterless.verify()).status).toBe(401);
    const signedIn = await authenticate(origin, rpHash, 0x05, 1);
    expect(signedIn.result.status).toBe(200);
    expect(
      (await request("/api/session", { cookie: setCookies(signedIn.result) }))
        .status,
    ).toBe(200);
    expect((await signedIn.verify()).status).toBe(401);
    expect((await authenticate(origin, rpHash, 0x05, 1)).result.status).toBe(
      401,
    );
    const activeCookie = setCookies(signedIn.result);
    expect(
      await json<{ items: { id: string }[] }>(
        await request("/api/account/passkeys", { cookie: activeCookie }),
      ),
    ).toMatchObject({ items: [{ id: encodedId }] });
    expect(
      (
        await request(`/api/account/passkeys/${encodedId}`, {
          method: "DELETE",
          cookie: activeCookie,
        })
      ).status,
    ).toBe(200);
    expect((await authenticate(origin, rpHash, 0x05, 2)).result.status).toBe(
      401,
    );
  }, 20_000);
});
