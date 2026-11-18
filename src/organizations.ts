import type { Hono, MiddlewareHandler } from "hono";
import { z } from "zod";
import { emailField } from "./auth";
import { body, fail, requireSession } from "./core";
import type { App, Ctx, SqlValue } from "./core";

type Permission =
  | "org:read"
  | "org:write"
  | "members:write"
  | "teams:write"
  | "sessions:write"
  | "audit:read";
const named = z.object({ name: z.string().trim().min(2).max(80) }).strict();
const roles = z.enum(["owner", "admin", "member", "viewer"]);
const invite = z.object({ email: emailField, role: roles }).strict();
const memberEmail = z.object({ email: emailField }).strict();
const pageSize = 20;

function org(c: Ctx) {
  const id = c.req.param("org");
  if (!id) fail(404, "NOT_FOUND", "Organization not found.");
  return id;
}

function permission(c: Ctx, capability: Permission) {
  const { user, session } = c.get("principal");
  return {
    sql: `SELECT m.role_id FROM memberships m JOIN role_permissions p ON p.role_id = m.role_id
      JOIN sessions s ON s.user_id = m.user_id
      WHERE m.org_id = ? AND m.user_id = ? AND p.permission = ? AND s.id = ?
      AND s.access_expires_at > ? AND s.refresh_expires_at > ?
      AND NOT EXISTS (SELECT 1 FROM org_session_revocations r WHERE r.org_id = m.org_id AND r.session_id = s.id)`,
    args: [
      org(c),
      user.id,
      capability,
      session.id,
      Date.now(),
      Date.now(),
    ] satisfies SqlValue[],
  };
}

export function requirePermission(
  capability: Permission,
): MiddlewareHandler<App> {
  return async (c, next) => {
    const read = permission(c, "org:read");
    const member = await c.env.DB.prepare(read.sql)
      .bind(...read.args)
      .first<{ role_id: string }>();
    if (!member) fail(404, "NOT_FOUND", "Organization not found.");
    if (capability !== "org:read") {
      const statement = permission(c, capability);
      const allowed = await c.env.DB.prepare(statement.sql)
        .bind(...statement.args)
        .first();
      if (!allowed)
        fail(403, "FORBIDDEN", "Your role does not allow this operation.");
    }
    await next();
  };
}

function audit(c: Ctx, action: string, subject: string | null = null) {
  return c.env.DB.prepare(
    `INSERT INTO audit_events (id, org_id, actor_id, action, subject, kind, created_at)
    SELECT ?, ?, ?, ?, ?, 'audit', ? WHERE changes() > 0`,
  ).bind(
    crypto.randomUUID(),
    org(c),
    c.get("principal").user.id,
    action,
    subject,
    Date.now(),
  );
}

async function mutate(
  c: Ctx,
  statement: D1PreparedStatement,
  action: string,
  subject?: string,
  missing = false,
) {
  const [result] = await c.env.DB.batch([statement, audit(c, action, subject)]);
  if (!result?.meta.changes) {
    if (missing)
      fail(404, "NOT_FOUND", "The organization resource was not found.");
    fail(
      409,
      "CHANGE_REJECTED",
      "The change conflicts with current membership, permissions, or existing data.",
    );
  }
}

async function page(c: Ctx, select: string, args: SqlValue[], sort: string) {
  const index = Math.max(
    1,
    Math.min(10000, Number.parseInt(c.req.query("page") ?? "1", 10) || 1),
  );
  const db = c.env.DB;
  const [items, totals] = await db.batch<{ total?: number }>([
    db
      .prepare(`${select} ORDER BY ${sort} LIMIT ? OFFSET ?`)
      .bind(...args, pageSize, (index - 1) * pageSize),
    db.prepare(`SELECT COUNT(*) AS total FROM (${select})`).bind(...args),
  ]);
  return c.json({
    items: items?.results ?? [],
    total: totals?.results[0]?.total ?? 0,
  });
}

const search = (c: Ctx) =>
  `%${(c.req.query("q") ?? "")
    .trim()
    .slice(0, 120)
    .replace(/[\\%_]/g, "\\$&")}%`;
const useLike = "LIKE ? ESCAPE '\\'";

export function registerOrganizations(app: Hono<App>) {
  app.use("/api/orgs", requireSession);
  app.use("/api/orgs/*", requireSession);
  app.get("/api/orgs", async (c) => {
    const { user, session } = c.get("principal");
    const { results } = await c.env.DB.prepare(
      `
      SELECT o.id, o.name, m.role_id AS role FROM organizations o JOIN memberships m ON m.org_id = o.id
      WHERE m.user_id = ? AND NOT EXISTS (
        SELECT 1 FROM org_session_revocations r WHERE r.org_id = o.id AND r.session_id = ?
      ) ORDER BY o.name, o.id
    `,
    )
      .bind(user.id, session.id)
      .all();
    return c.json({ items: results });
  });

  app.post("/api/orgs", async (c) => {
    const { name } = await body(c, named);
    const { user, session } = c.get("principal");
    const id = crypto.randomUUID();
    const now = Date.now();
    const db = c.env.DB;
    const [created] = await db.batch([
      db
        .prepare(
          `INSERT INTO organizations
        SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM sessions WHERE id = ? AND user_id = ? AND access_expires_at > ?)
        AND (SELECT COUNT(*) FROM memberships WHERE user_id = ? AND role_id = 'owner') < 50`,
        )
        .bind(id, name, now, session.id, user.id, now, user.id),
      db
        .prepare(
          "INSERT INTO memberships SELECT ?, ?, 'owner' WHERE changes() > 0",
        )
        .bind(id, user.id),
      db
        .prepare(
          `INSERT INTO audit_events (id, org_id, actor_id, action, subject, kind, created_at)
        SELECT ?, ?, ?, 'organization.created', ?, 'audit', ? WHERE changes() > 0`,
        )
        .bind(crypto.randomUUID(), id, user.id, name, now),
    ]);
    if (!created?.meta.changes)
      fail(
        409,
        "CHANGE_REJECTED",
        "Organization creation limit reached or session expired.",
      );
    return c.json({ id }, 201);
  });

  app.get(
    "/api/orgs/:org/permissions",
    requirePermission("org:read"),
    async (c) => {
      const guard = permission(c, "org:read");
      const { results } = await c.env.DB.prepare(
        `SELECT permission FROM role_permissions WHERE role_id = (${guard.sql}) ORDER BY permission`,
      )
        .bind(...guard.args)
        .all<{ permission: Permission }>();
      return c.json({ permissions: results.map((row) => row.permission) });
    },
  );

  app.patch("/api/orgs/:org", requirePermission("org:write"), async (c) => {
    const { name } = await body(c, named);
    const guard = permission(c, "org:write");
    await mutate(
      c,
      c.env.DB.prepare(
        `UPDATE organizations SET name = ? WHERE id = ? AND EXISTS (${guard.sql})`,
      ).bind(name, org(c), ...guard.args),
      "organization.updated",
      name,
    );
    return c.json({ ok: true });
  });

  app.get(
    "/api/orgs/:org/overview",
    requirePermission("org:read"),
    async (c) => {
      const id = org(c);
      const metrics = await c.env.DB.prepare(
        `SELECT
      (SELECT COUNT(*) FROM memberships WHERE org_id = ?) AS users,
      (SELECT COUNT(*) FROM sessions s JOIN memberships m ON m.user_id = s.user_id
        WHERE m.org_id = ? AND s.refresh_expires_at > ?
        AND NOT EXISTS (SELECT 1 FROM org_session_revocations r WHERE r.org_id = m.org_id AND r.session_id = s.id)) AS sessions,
      (SELECT COUNT(*) FROM audit_events a WHERE a.org_id = ?
        OR (a.org_id IS NULL AND a.kind = 'auth' AND EXISTS (SELECT 1 FROM memberships m WHERE m.org_id = ? AND m.user_id = a.actor_id))) AS events,
      (SELECT COUNT(*) FROM teams WHERE org_id = ?) AS teams`,
      )
        .bind(id, id, Date.now(), id, id, id)
        .first();
      return c.json(metrics ?? { users: 0, sessions: 0, events: 0, teams: 0 });
    },
  );

  app.get("/api/orgs/:org/members", requirePermission("org:read"), (c) =>
    page(
      c,
      `SELECT u.id, u.email, m.role_id AS role FROM memberships m JOIN users u ON u.id = m.user_id
      WHERE m.org_id = ? AND u.email ${useLike}`,
      [org(c), search(c)],
      "u.email, u.id",
    ),
  );

  app.put(
    "/api/orgs/:org/members",
    requirePermission("members:write"),
    async (c) => {
      const { email, role } = await body(c, invite);
      const id = org(c);
      const guard = permission(c, "members:write");
      const actor = await c.env.DB.prepare(guard.sql)
        .bind(...guard.args)
        .first<{ role_id: string }>();
      if (actor?.role_id === "admin") {
        const target = await c.env.DB.prepare(
          `
        SELECT m.role_id FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND u.email = ?
      `,
        )
          .bind(id, email)
          .first<{ role_id: string }>();
        if (
          role === "owner" ||
          role === "admin" ||
          target?.role_id === "owner" ||
          target?.role_id === "admin"
        ) {
          fail(
            403,
            "FORBIDDEN",
            "Only owners can manage owner or administrator roles.",
          );
        }
      }
      await mutate(
        c,
        c.env.DB.prepare(
          `
      INSERT INTO memberships (org_id, user_id, role_id)
      SELECT ?, u.id, ? FROM users u WHERE u.email = ? AND u.verified_at IS NOT NULL
      AND EXISTS (SELECT 1 FROM (${guard.sql}) actor WHERE actor.role_id = 'owner' OR ? IN ('member', 'viewer'))
      ON CONFLICT (org_id, user_id) DO UPDATE SET role_id = excluded.role_id
      WHERE memberships.role_id <> excluded.role_id
      AND ((${guard.sql}) = 'owner' OR memberships.role_id IN ('member', 'viewer'))
      AND (memberships.role_id <> 'owner' OR EXISTS (
        SELECT 1 FROM memberships other WHERE other.org_id = memberships.org_id
        AND other.role_id = 'owner' AND other.user_id <> memberships.user_id
      ))
    `,
        ).bind(id, role, email, ...guard.args, role, ...guard.args),
        "membership.role_set",
        `${email} · ${role}`,
      );
      return c.json({ ok: true });
    },
  );

  app.delete(
    "/api/orgs/:org/members/:id",
    requirePermission("members:write"),
    async (c) => {
      const target = c.req.param("id");
      const guard = permission(c, "members:write");
      await mutate(
        c,
        c.env.DB.prepare(
          `
      DELETE FROM memberships WHERE org_id = ? AND user_id = ?
      AND ('owner' = (${guard.sql}) OR (role_id IN ('member','viewer') AND EXISTS (${guard.sql})))
      AND (role_id <> 'owner' OR EXISTS (
        SELECT 1 FROM memberships other WHERE other.org_id = memberships.org_id
        AND other.role_id = 'owner' AND other.user_id <> memberships.user_id
      ))
    `,
        ).bind(org(c), target, ...guard.args, ...guard.args),
        "membership.revoked",
        target,
      );
      return c.json({ ok: true });
    },
  );

  app.get("/api/orgs/:org/sessions", requirePermission("sessions:write"), (c) =>
    page(
      c,
      `SELECT s.id, u.email, s.created_at AS createdAt, s.refresh_expires_at AS expiresAt
      FROM sessions s JOIN users u ON u.id = s.user_id JOIN memberships m ON m.user_id = s.user_id
      WHERE m.org_id = ? AND s.refresh_expires_at > ? AND u.email ${useLike}
      AND NOT EXISTS (SELECT 1 FROM org_session_revocations r WHERE r.org_id = m.org_id AND r.session_id = s.id)`,
      [org(c), Date.now(), search(c)],
      "s.created_at DESC, s.id",
    ),
  );

  app.delete(
    "/api/orgs/:org/sessions/:id",
    requirePermission("sessions:write"),
    async (c) => {
      const target = c.req.param("id");
      const guard = permission(c, "sessions:write");
      await mutate(
        c,
        c.env.DB.prepare(
          `
      INSERT INTO org_session_revocations (org_id, session_id)
      SELECT m.org_id, s.id FROM sessions s JOIN memberships m ON m.user_id = s.user_id
      WHERE m.org_id = ? AND s.id = ? AND s.refresh_expires_at > ?
      AND EXISTS (SELECT 1 FROM (${guard.sql}) actor WHERE actor.role_id = 'owner' OR m.role_id IN ('member','viewer'))
      ON CONFLICT DO NOTHING
    `,
        ).bind(org(c), target, Date.now(), ...guard.args),
        "organization.session_revoked",
        target,
        true,
      );
      return c.json({ ok: true });
    },
  );

  app.get("/api/orgs/:org/events", requirePermission("audit:read"), (c) => {
    const kind = c.req.query("kind");
    if (kind && kind !== "auth" && kind !== "audit")
      fail(400, "INVALID_INPUT", "Unknown event filter.");
    return page(
      c,
      `SELECT a.id, a.action, u.email AS actorEmail, a.subject, a.created_at AS createdAt
      FROM audit_events a LEFT JOIN users u ON u.id = a.actor_id
      WHERE (a.org_id = ? OR (a.org_id IS NULL AND a.kind = 'auth'
        AND EXISTS (SELECT 1 FROM memberships m WHERE m.org_id = ? AND m.user_id = a.actor_id)))
      AND (? IS NULL OR a.kind = ?)
      AND (a.action ${useLike} OR u.email ${useLike} OR a.subject ${useLike})`,
      [
        org(c),
        org(c),
        kind ?? null,
        kind ?? null,
        search(c),
        search(c),
        search(c),
      ],
      "a.created_at DESC, a.id",
    );
  });

  app.get("/api/orgs/:org/teams", requirePermission("org:read"), (c) =>
    page(
      c,
      `SELECT id, name FROM teams WHERE org_id = ? AND name ${useLike}`,
      [org(c), search(c)],
      "name, id",
    ),
  );

  app.post(
    "/api/orgs/:org/teams",
    requirePermission("teams:write"),
    async (c) => {
      const { name } = await body(c, named);
      const id = crypto.randomUUID();
      const guard = permission(c, "teams:write");
      await mutate(
        c,
        c.env.DB.prepare(
          `INSERT INTO teams (id, org_id, name)
      SELECT ?, ?, ? WHERE EXISTS (${guard.sql}) ON CONFLICT(org_id, name) DO NOTHING`,
        ).bind(id, org(c), name, ...guard.args),
        "team.created",
        name,
      );
      return c.json({ id }, 201);
    },
  );

  app.delete(
    "/api/orgs/:org/teams/:id",
    requirePermission("teams:write"),
    async (c) => {
      const id = c.req.param("id");
      const guard = permission(c, "teams:write");
      await mutate(
        c,
        c.env.DB.prepare(
          `DELETE FROM teams WHERE org_id = ? AND id = ? AND EXISTS (${guard.sql})`,
        ).bind(org(c), id, ...guard.args),
        "team.deleted",
        id,
        true,
      );
      return c.json({ ok: true });
    },
  );

  app.get(
    "/api/orgs/:org/teams/:id/members",
    requirePermission("org:read"),
    async (c) => {
      if (
        !(await c.env.DB.prepare(
          "SELECT 1 FROM teams WHERE org_id = ? AND id = ?",
        )
          .bind(org(c), c.req.param("id"))
          .first())
      ) {
        fail(404, "NOT_FOUND", "Team not found.");
      }
      const { results } = await c.env.DB.prepare(
        `
      SELECT u.id, u.email, m.role_id AS role FROM team_members t
      JOIN users u ON u.id = t.user_id JOIN memberships m ON m.user_id = t.user_id AND m.org_id = t.org_id
      WHERE t.org_id = ? AND t.team_id = ? ORDER BY u.email LIMIT 100
    `,
      )
        .bind(org(c), c.req.param("id"))
        .all();
      return c.json({ items: results });
    },
  );

  app.put(
    "/api/orgs/:org/teams/:id/members",
    requirePermission("teams:write"),
    async (c) => {
      const { email } = await body(c, memberEmail);
      const id = c.req.param("id");
      const guard = permission(c, "teams:write");
      await mutate(
        c,
        c.env.DB.prepare(
          `INSERT INTO team_members (org_id, team_id, user_id)
      SELECT t.org_id, t.id, u.id FROM teams t JOIN memberships m ON m.org_id = t.org_id JOIN users u ON u.id = m.user_id
      WHERE t.org_id = ? AND t.id = ? AND u.email = ? AND EXISTS (${guard.sql}) ON CONFLICT DO NOTHING`,
        ).bind(org(c), id, email, ...guard.args),
        "team.member_added",
        `${id} · ${email}`,
        true,
      );
      return c.json({ ok: true });
    },
  );

  app.delete(
    "/api/orgs/:org/teams/:id/members/:user",
    requirePermission("teams:write"),
    async (c) => {
      const target = c.req.param("user");
      const guard = permission(c, "teams:write");
      await mutate(
        c,
        c.env.DB.prepare(
          `DELETE FROM team_members WHERE org_id = ? AND team_id = ?
      AND user_id = ? AND EXISTS (${guard.sql})`,
        ).bind(org(c), c.req.param("id"), target, ...guard.args),
        "team.member_removed",
        target,
        true,
      );
      return c.json({ ok: true });
    },
  );
}
