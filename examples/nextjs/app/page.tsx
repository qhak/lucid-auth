import { headers } from "next/headers";
import { createLucidServer } from "../../../sdk";
import { Login, Logout } from "./login";

export default async function Home() {
  const cookie = (await headers()).get("cookie") ?? "";
  const origin = process.env.LUCID_ORIGIN;
  if (!origin) return <p>Set LUCID_ORIGIN in .env.local.</p>;
  const lucid = createLucidServer(origin);
  const session = await lucid.verifySession(cookie);
  if (!session)
    return (
      <>
        <h1>Lucid Auth integration</h1>
        <Login />
      </>
    );
  const org = process.env.LUCID_ORG_ID;
  const canRead = org
    ? await lucid.hasPermission(cookie, org, "org:read")
    : false;
  return (
    <>
      <h1>Lucid Auth integration</h1>
      <p>Signed in as {session.user.email}</p>
      {org &&
        (canRead ? (
          <section>
            <h2>Protected workspace</h2>
            <p>You can read this organization.</p>
          </section>
        ) : (
          <p>Your session has no access to the configured organization.</p>
        ))}
      <Logout />
    </>
  );
}
