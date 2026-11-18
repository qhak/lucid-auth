import { describe, expect, it } from "vitest";
import { account, client, json, successful, type Client } from "./http";

type Organization = { id: string; name: string; role: string };
type Member = { id: string; email: string; role: string };
type Event = {
  id: string;
  action: string;
  actorEmail: string | null;
  subject: string | null;
};
type Items<T> = { items: T[]; total: number };

async function createOrg(
  request: Client,
  cookie: string,
  name = "North Studio",
) {
  const { id } = await json<{ id: string }>(
    await request("/api/orgs", { cookie, json: { name } }),
  );
  return `/api/orgs/${id}`;
}

describe("organization authorization", () => {
  it("enforces membership and current role on each operation", async () => {
    const request = client();
    const owner = await account(request, "owner");
    const viewer = await account(request, "viewer");
    const outsider = await account(request, "outsider");
    const org = await createOrg(request, owner.cookie);

    await successful(
      await request(`${org}/members`, {
        method: "PUT",
        cookie: owner.cookie,
        json: { email: viewer.email, role: "viewer" },
      }),
    );
    const { items } = await json<Items<Member>>(
      await request(`${org}/members`, { cookie: viewer.cookie }),
    );
    expect(items).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: owner.user.id,
          email: owner.email,
          role: "owner",
        }),
        expect.objectContaining({
          id: viewer.user.id,
          email: viewer.email,
          role: "viewer",
        }),
      ]),
    );

    const promotion = await request(`${org}/members`, {
      method: "PUT",
      cookie: viewer.cookie,
      json: { email: viewer.email, role: "admin" },
    });
    expect(promotion.status).toBe(403);
    expect(
      (await request(`${org}/overview`, { cookie: outsider.cookie })).status,
    ).toBe(404);
    expect(
      (
        await json<{ items: Organization[] }>(
          await request("/api/orgs", { cookie: outsider.cookie }),
        )
      ).items,
    ).toEqual([]);

    await successful(
      await request(`${org}/members/${viewer.user.id}`, {
        method: "DELETE",
        cookie: owner.cookie,
      }),
    );
    expect(
      (await request(`${org}/members`, { cookie: viewer.cookie })).status,
    ).toBe(404);
    expect(
      (await request("/api/session", { cookie: viewer.cookie })).status,
    ).toBe(200);
  });

  it("prevents administrators from changing the sole owner and audits actual role changes", async () => {
    const request = client();
    const owner = await account(request, "owner");
    const admin = await account(request, "admin");
    const org = await createOrg(request, owner.cookie);
    await successful(
      await request(`${org}/members`, {
        method: "PUT",
        cookie: owner.cookie,
        json: { email: admin.email, role: "admin" },
      }),
    );
    const before = await json<Items<Event>>(
      await request(`${org}/events?kind=audit`, { cookie: owner.cookie }),
    );
    expect(before.items.some((event) => event.actorEmail === owner.email)).toBe(
      true,
    );

    const demoteOwner = await request(`${org}/members`, {
      method: "PUT",
      cookie: admin.cookie,
      json: { email: owner.email, role: "viewer" },
    });
    expect(demoteOwner.status).toBe(403);
    const deleteOwner = await request(`${org}/members/${owner.user.id}`, {
      method: "DELETE",
      cookie: owner.cookie,
    });
    expect(deleteOwner.ok).toBe(false);
    const deleteAccount = await request("/api/account", {
      method: "DELETE",
      cookie: owner.cookie,
      json: { confirm: true },
    });
    expect(deleteAccount.status).toBe(409);
    expect(await deleteAccount.json()).toMatchObject({
      error: { code: "LAST_OWNER" },
    });

    const after = await json<Items<Event>>(
      await request(`${org}/events?kind=audit`, { cookie: owner.cookie }),
    );
    expect(after.items.map(({ id }) => id).sort()).toEqual(
      before.items.map(({ id }) => id).sort(),
    );
    const { items } = await json<{ items: Organization[] }>(
      await request("/api/orgs", { cookie: owner.cookie }),
    );
    expect(items).toContainEqual(
      expect.objectContaining({ name: "North Studio", role: "owner" }),
    );
  });

  it("scopes nested team and session identifiers to the requested organization", async () => {
    const request = client();
    const north = await account(request, "north");
    const south = await account(request, "south");
    const northOrg = await createOrg(request, north.cookie);
    const southOrg = await createOrg(request, south.cookie, "South Studio");
    const team = await json<{ id: string }>(
      await request(`${southOrg}/teams`, {
        cookie: south.cookie,
        json: { name: "Research" },
      }),
    );

    const crossTenantTeam = await request(
      `${northOrg}/teams/${team.id}/members`,
      {
        method: "PUT",
        cookie: north.cookie,
        json: { email: north.email },
      },
    );
    expect(crossTenantTeam.status).toBe(404);
    const crossTenantSession = await request(
      `${northOrg}/sessions/${south.session.id}`,
      {
        method: "DELETE",
        cookie: north.cookie,
      },
    );
    expect(crossTenantSession.status).toBe(404);
    expect(
      (await request("/api/session", { cookie: south.cookie })).status,
    ).toBe(200);

    await successful(
      await request(`${southOrg}/teams/${team.id}/members`, {
        method: "PUT",
        cookie: south.cookie,
        json: { email: south.email },
      }),
    );
    const { items } = await json<Items<Member>>(
      await request(`${southOrg}/teams/${team.id}/members`, {
        cookie: south.cookie,
      }),
    );
    expect(items).toEqual([
      expect.objectContaining({ id: south.user.id, email: south.email }),
    ]);
  });

  it("removes team membership when organization access is revoked", async () => {
    const request = client();
    const owner = await account(request, "owner");
    const member = await account(request, "member");
    const org = await createOrg(request, owner.cookie);
    const team = await json<{ id: string }>(
      await request(`${org}/teams`, {
        cookie: owner.cookie,
        json: { name: "Engineering" },
      }),
    );
    const membership = { email: member.email, role: "member" };
    await successful(
      await request(`${org}/members`, {
        method: "PUT",
        cookie: owner.cookie,
        json: membership,
      }),
    );
    await successful(
      await request(`${org}/teams/${team.id}/members`, {
        method: "PUT",
        cookie: owner.cookie,
        json: { email: member.email },
      }),
    );
    await successful(
      await request(`${org}/members/${member.user.id}`, {
        method: "DELETE",
        cookie: owner.cookie,
      }),
    );
    await successful(
      await request(`${org}/members`, {
        method: "PUT",
        cookie: owner.cookie,
        json: membership,
      }),
    );
    const { items } = await json<Items<Member>>(
      await request(`${org}/teams/${team.id}/members`, {
        cookie: owner.cookie,
      }),
    );
    expect(items).toEqual([]);
  });

  it("scopes session revocation to one organization for shared accounts", async () => {
    const request = client();
    const northOwner = await account(request, "north-owner");
    const shared = await account(request, "shared");
    const northOrg = await createOrg(request, northOwner.cookie);
    const southOrg = await createOrg(request, shared.cookie, "South Studio");
    await successful(
      await request(`${northOrg}/members`, {
        method: "PUT",
        cookie: northOwner.cookie,
        json: { email: shared.email, role: "member" },
      }),
    );
    expect(
      (await request(`${northOrg}/overview`, { cookie: shared.cookie })).status,
    ).toBe(200);

    await successful(
      await request(`${northOrg}/sessions/${shared.session.id}`, {
        method: "DELETE",
        cookie: northOwner.cookie,
      }),
    );
    expect(
      (await request(`${northOrg}/overview`, { cookie: shared.cookie })).ok,
    ).toBe(false);
    expect(
      (await request(`${southOrg}/overview`, { cookie: shared.cookie })).status,
    ).toBe(200);
    expect(
      (await request("/api/session", { cookie: shared.cookie })).status,
    ).toBe(200);
  });
});
