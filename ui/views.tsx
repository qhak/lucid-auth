import { useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { api, orgApi, time, useOperation, useRemote } from "./api";
import type {
  AuditEvent,
  Items,
  Member,
  Organization,
  OrgDevice,
  Overview,
  Page,
  Session,
  Settings,
  Team,
} from "./api";
import {
  Empty,
  Failure,
  Icon,
  Loading,
  Notice,
  Panel,
  RoleTag,
  StateTag,
} from "./components";
import type { IconName } from "./components";

export const canManage = (org: Organization) =>
  org.role === "owner" || org.role === "admin";

export const canManageMember = (
  org: Organization,
  member: Member,
  session: Session,
) =>
  member.id !== session.user.id &&
  (org.role === "owner" ||
    (org.role === "admin" &&
      (member.role === "member" || member.role === "viewer")));

export function ProviderStatus({ settings }: { settings?: Settings }) {
  return settings ? (
    <div className="provider-list">
      <div>
        <span className="icon-tile">
          <Icon name="key" />
        </span>
        <span>
          <strong>Passkeys</strong>
          <small>WebAuthn</small>
        </span>
        <StateTag enabled={settings.passkeys} />
      </div>
      <div>
        <span className="icon-tile">
          <Icon name="google" />
        </span>
        <span>
          <strong>Google</strong>
          <small>OpenID Connect</small>
        </span>
        <StateTag
          enabled={settings.google}
          on="Configured"
          off="Unconfigured"
        />
      </div>
    </div>
  ) : (
    <p className="panel-copy muted">
      Provider configuration is currently unavailable.
    </p>
  );
}

function ActionName({ value }: { value: string }) {
  return <code className="event-name">{value}</code>;
}

const metrics: {
  key: keyof Overview;
  label: string;
  icon: IconName;
  hint: string;
}[] = [
  {
    key: "users",
    label: "Members",
    icon: "users",
    hint: "Organization members",
  },
  {
    key: "sessions",
    label: "Active sessions",
    icon: "sessions",
    hint: "Unexpired sessions",
  },
  {
    key: "events",
    label: "Recorded events",
    icon: "activity",
    hint: "Authentication and audit",
  },
  {
    key: "teams",
    label: "Teams",
    icon: "teams",
    hint: "Within this organization",
  },
];

function RecentActivity({
  org,
  openEvents,
}: {
  org: Organization;
  openEvents: () => void;
}) {
  const [revision, setRevision] = useState(0);
  const result = useRemote<Page<AuditEvent>>(
    `${orgApi(org.id)}/events?page=1`,
    revision,
  );
  return (
    <Panel
      title="Recent activity"
      description="The latest events in this organization"
      action={
        <button className="button secondary" onClick={openEvents}>
          View events <Icon name="right" size={15} />
        </button>
      }
    >
      {!result && <Loading />}
      {result && "error" in result && (
        <Failure
          error={result.error}
          onRetry={() => setRevision((value) => value + 1)}
        />
      )}
      {result?.data &&
        (result.data.items.length > 0 ? (
          <ol className="timeline">
            {result.data.items.slice(0, 5).map((entry) => (
              <li key={entry.id}>
                <span className="timeline-icon">
                  <Icon name="activity" size={16} />
                </span>
                <div>
                  <ActionName value={entry.action} />
                  <p>{entry.actorEmail ?? "System"}</p>
                </div>
                <time dateTime={new Date(entry.createdAt).toISOString()}>
                  {time(entry.createdAt)}
                </time>
              </li>
            ))}
          </ol>
        ) : (
          <Empty title="No events recorded yet">
            Authentication and security events will appear here.
          </Empty>
        ))}
    </Panel>
  );
}

export function OverviewScreen({
  org,
  settings,
  openEvents,
}: {
  org: Organization;
  settings?: Settings;
  openEvents: () => void;
}) {
  const [revision, setRevision] = useState(0);
  const result = useRemote<Overview>(`${orgApi(org.id)}/overview`, revision);
  const data = result?.data;
  return (
    <>
      <section className="overview-hero">
        <p className="eyebrow">
          <i /> Organization overview
        </p>
        <h1>{org.name}</h1>
        <p>
          Monitor identity, access, and security activity across your
          organization.
        </p>
        <div className="hero-art" aria-hidden="true">
          <span className="hero-grid" />
          <span className="brand-mark hero-mark">
            <i />
          </span>
        </div>
      </section>
      {!result && (
        <div className="panel">
          <Loading />
        </div>
      )}
      {result && "error" in result && (
        <div className="panel">
          <Failure
            error={result.error}
            onRetry={() => setRevision((value) => value + 1)}
          />
        </div>
      )}
      {data && (
        <div className="metric-grid">
          {metrics.map((metric) => (
            <article className={`metric metric-${metric.key}`} key={metric.key}>
              <div>
                <span className="icon-tile">
                  <Icon name={metric.icon} />
                </span>
                <h2>{metric.label}</h2>
              </div>
              <p>{data[metric.key].toLocaleString()}</p>
              <small>{metric.hint}</small>
            </article>
          ))}
        </div>
      )}
      <div className={canManage(org) ? "overview-columns" : ""}>
        {canManage(org) && <RecentActivity org={org} openEvents={openEvents} />}
        <Panel
          title="Identity providers"
          description="Deployment configuration"
        >
          <ProviderStatus settings={settings} />
        </Panel>
      </div>
    </>
  );
}

function DataTable({
  columns,
  children,
}: {
  columns: string[];
  children: ReactNode;
}) {
  return (
    <div className="table-wrap" tabIndex={0} role="region" aria-label="Results">
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column} scope="col">
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

function usePage() {
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState("");
  function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setQuery(String(new FormData(event.currentTarget).get("q")).trim());
    setPage(1);
  }
  return {
    page,
    setPage,
    query,
    search,
    params: new URLSearchParams({ page: String(page), q: query }),
  };
}

function Search({
  label,
  onSubmit,
}: {
  label: string;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <form
      className="search-form"
      role="search"
      aria-label={label}
      onSubmit={onSubmit}
    >
      <label className="search-input">
        <Icon name="search" />
        <span className="sr-only">{label}</span>
        <input type="search" name="q" placeholder={label} maxLength={100} />
      </label>
      <button className="button secondary">Search</button>
    </form>
  );
}

function Pagination({
  page,
  total,
  setPage,
}: {
  page: number;
  total: number;
  setPage: (value: number) => void;
}) {
  const last = Math.max(1, Math.ceil(total / 20));
  return (
    <div className="pagination">
      <small>
        {total.toLocaleString()} {total === 1 ? "result" : "results"}
      </small>
      <div>
        <button
          className="button secondary small"
          aria-label="Previous page"
          disabled={page <= 1}
          onClick={() => setPage(page - 1)}
        >
          <Icon name="left" size={15} />
        </button>
        <span role="status">
          Page {page} of {Math.max(page, last)}
        </span>
        <button
          className="button secondary small"
          aria-label="Next page"
          disabled={page >= last}
          onClick={() => setPage(page + 1)}
        >
          <Icon name="right" size={15} />
        </button>
      </div>
    </div>
  );
}

export function MemberScreen({
  org,
  session,
  onUpdate,
}: {
  org: Organization;
  session: Session;
  onUpdate: () => void;
}) {
  const [revision, setRevision] = useState(0);
  const pager = usePage();
  const base = `${orgApi(org.id)}/members`;
  const result = useRemote<Page<Member>>(`${base}?${pager.params}`, revision);
  const retry = () => setRevision((value) => value + 1);
  const action = useOperation(() => {
    retry();
    onUpdate();
  });
  const manager = canManage(org);
  const columns = manager
    ? ["Email address", "Role", "Actions"]
    : ["Email address", "Role"];

  return (
    <>
      {manager && (
        <Panel
          title="Assign a role"
          description="Use the email of an existing Lucid Auth account."
        >
          <form
            className="inline-form"
            onSubmit={(event) => {
              event.preventDefault();
              const form = event.currentTarget;
              const { email, role } = Object.fromEntries(new FormData(form));
              void action.run(async () => {
                await api(base, { method: "PUT", body: { email, role } });
                form.reset();
              }, "Membership saved.");
            }}
          >
            <label>
              Email address
              <input
                name="email"
                type="email"
                placeholder="teammate@example.com"
                required
                maxLength={254}
              />
            </label>
            <label>
              Role
              <select name="role">
                <option value="viewer">Viewer</option>
                <option value="member">Member</option>
                {org.role === "owner" && (
                  <>
                    <option value="admin">Admin</option>
                    <option value="owner">Owner</option>
                  </>
                )}
              </select>
            </label>
            <button className="button primary" disabled={action.busy}>
              <Icon name="plus" /> Save membership
            </button>
          </form>
          <div className="panel-notice">
            <Notice status={action.status} />
          </div>
        </Panel>
      )}
      <Panel
        title="Organization members"
        action={<Search label="Search members" onSubmit={pager.search} />}
      >
        {!result && <Loading />}
        {result && "error" in result && (
          <Failure error={result.error} onRetry={retry} />
        )}
        {result?.data && (
          <>
            {result.data.items.length === 0 ? (
              <Empty icon="users" title="No members match this search" />
            ) : (
              <DataTable columns={columns}>
                {result.data.items.map((member) => (
                  <tr key={member.id}>
                    <td>
                      <strong>{member.email}</strong>
                      {member.id === session.user.id && (
                        <span className="tag you-tag">You</span>
                      )}
                    </td>
                    <td>
                      <RoleTag role={member.role} />
                    </td>
                    {manager && (
                      <td>
                        {canManageMember(org, member, session) && (
                          <button
                            className="button danger-quiet small"
                            disabled={action.busy}
                            aria-label={`Remove ${member.email}`}
                            onClick={() => {
                              if (
                                window.confirm(
                                  `Remove ${member.email} from ${org.name}?`,
                                )
                              ) {
                                void action.run(
                                  () =>
                                    api(
                                      `${base}/${encodeURIComponent(member.id)}`,
                                      { method: "DELETE" },
                                    ),
                                  "Membership removed.",
                                );
                              }
                            }}
                          >
                            Remove
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </DataTable>
            )}
            <Pagination
              page={pager.page}
              total={result.data.total}
              setPage={pager.setPage}
            />
          </>
        )}
      </Panel>
    </>
  );
}

export function SessionScreen({
  org,
  session,
  onOrgRevoked,
}: {
  org: Organization;
  session: Session;
  onOrgRevoked: () => void;
}) {
  const [revision, setRevision] = useState(0);
  const pager = usePage();
  const base = `${orgApi(org.id)}/sessions`;
  const result = useRemote<Page<OrgDevice>>(
    `${base}?${pager.params}`,
    revision,
  );
  const retry = () => setRevision((value) => value + 1);
  const action = useOperation(retry);
  const columns = ["Account", "Created", "Session expires", "Actions"];

  return (
    <Panel
      title="Active sessions"
      description="Revoking access here affects this organization only."
      action={<Search label="Search by email" onSubmit={pager.search} />}
    >
      <div className="panel-notice">
        <Notice status={action.status} />
      </div>
      {!result && <Loading />}
      {result && "error" in result && (
        <Failure error={result.error} onRetry={retry} />
      )}
      {result?.data && (
        <>
          {result.data.items.length === 0 ? (
            <Empty icon="sessions" title="No sessions match this search" />
          ) : (
            <DataTable columns={columns}>
              {result.data.items.map((device) => (
                <tr key={device.id}>
                  <td>
                    <strong>{device.email}</strong>
                    {device.id === session.session.id && (
                      <span className="tag you-tag">This device</span>
                    )}
                  </td>
                  <td>{time(device.createdAt)}</td>
                  <td>{time(device.expiresAt)}</td>
                  <td>
                    <button
                      className="button danger-quiet small"
                      disabled={action.busy}
                      aria-label={`Revoke session for ${device.email} created ${time(device.createdAt)}`}
                      onClick={() => {
                        if (
                          window.confirm(
                            `Revoke this session’s access to ${org.name}?`,
                          )
                        ) {
                          void action.run(async () => {
                            await api(
                              `${base}/${encodeURIComponent(device.id)}`,
                              { method: "DELETE" },
                            );
                            if (device.id === session.session.id)
                              onOrgRevoked();
                          }, "Session revoked.");
                        }
                      }}
                    >
                      Revoke access
                    </button>
                  </td>
                </tr>
              ))}
            </DataTable>
          )}
          <Pagination
            page={pager.page}
            total={result.data.total}
            setPage={pager.setPage}
          />
        </>
      )}
    </Panel>
  );
}

export function EventScreen({
  org,
  kind,
}: {
  org: Organization;
  kind: "auth" | "audit";
}) {
  const [revision, setRevision] = useState(0);
  const pager = usePage();
  pager.params.set("kind", kind);
  const result = useRemote<Page<AuditEvent>>(
    `${orgApi(org.id)}/events?${pager.params}`,
    revision,
  );
  const title =
    kind === "auth" ? "Authentication events" : "Security audit log";
  return (
    <Panel
      title={title}
      action={<Search label="Search event type" onSubmit={pager.search} />}
    >
      {!result && <Loading />}
      {result && "error" in result && (
        <Failure
          error={result.error}
          onRetry={() => setRevision((value) => value + 1)}
        />
      )}
      {result?.data && (
        <>
          {result.data.items.length === 0 ? (
            <Empty
              icon={kind === "auth" ? "activity" : "audit"}
              title="No matching events"
            />
          ) : (
            <DataTable columns={["Action", "Actor", "Subject", "Time"]}>
              {result.data.items.map((entry) => (
                <tr key={entry.id}>
                  <td>
                    <ActionName value={entry.action} />
                  </td>
                  <td>{entry.actorEmail ?? "System"}</td>
                  <td>
                    <span className="table-subject">
                      {entry.subject ?? "—"}
                    </span>
                  </td>
                  <td>
                    <time dateTime={new Date(entry.createdAt).toISOString()}>
                      {time(entry.createdAt)}
                    </time>
                  </td>
                </tr>
              ))}
            </DataTable>
          )}
          <Pagination
            page={pager.page}
            total={result.data.total}
            setPage={pager.setPage}
          />
        </>
      )}
    </Panel>
  );
}

function TeamMembers({ org, team }: { org: Organization; team: Team }) {
  const [revision, setRevision] = useState(0);
  const base = `${orgApi(org.id)}/teams/${encodeURIComponent(team.id)}/members`;
  const result = useRemote<Items<Member>>(base, revision);
  const retry = () => setRevision((value) => value + 1);
  const action = useOperation(retry);
  const manager = canManage(org);
  return (
    <Panel
      title={`${team.name} members`}
      description="Team members must already belong to this organization."
    >
      {manager && (
        <form
          className="inline-form"
          onSubmit={(event) => {
            event.preventDefault();
            const form = event.currentTarget;
            const email = new FormData(form).get("email");
            void action.run(async () => {
              await api(base, { method: "PUT", body: { email } });
              form.reset();
            }, "Team member added.");
          }}
        >
          <label>
            Email address
            <input
              name="email"
              type="email"
              placeholder="teammate@example.com"
              required
              maxLength={254}
            />
          </label>
          <button className="button primary" disabled={action.busy}>
            Add to team
          </button>
        </form>
      )}
      <div className="panel-notice">
        <Notice status={action.status} />
      </div>
      {!result && <Loading />}
      {result && "error" in result && (
        <Failure error={result.error} onRetry={retry} />
      )}
      {result?.data &&
        (result.data.items.length === 0 ? (
          <Empty icon="users" title="No team members yet" />
        ) : (
          <DataTable
            columns={
              manager
                ? ["Email address", "Organization role", "Actions"]
                : ["Email address", "Organization role"]
            }
          >
            {result.data.items.map((member) => (
              <tr key={member.id}>
                <td>
                  <strong>{member.email}</strong>
                </td>
                <td>
                  <RoleTag role={member.role} />
                </td>
                {manager && (
                  <td>
                    <button
                      className="button danger-quiet small"
                      disabled={action.busy}
                      aria-label={`Remove ${member.email} from ${team.name}`}
                      onClick={() => {
                        if (
                          window.confirm(
                            `Remove ${member.email} from ${team.name}?`,
                          )
                        ) {
                          void action.run(
                            () =>
                              api(`${base}/${encodeURIComponent(member.id)}`, {
                                method: "DELETE",
                              }),
                            "Team member removed.",
                          );
                        }
                      }}
                    >
                      Remove
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </DataTable>
        ))}
    </Panel>
  );
}

export function TeamScreen({ org }: { org: Organization }) {
  const [revision, setRevision] = useState(0);
  const [selected, setSelected] = useState<Team>();
  const pager = usePage();
  const base = `${orgApi(org.id)}/teams`;
  const result = useRemote<Page<Team>>(`${base}?${pager.params}`, revision);
  const retry = () => setRevision((value) => value + 1);
  const action = useOperation(retry);
  const manager = canManage(org);
  return (
    <>
      {manager && (
        <Panel title="Create a team">
          <form
            className="inline-form"
            onSubmit={(event) => {
              event.preventDefault();
              const form = event.currentTarget;
              const name = new FormData(form).get("name");
              void action.run(async () => {
                await api(base, { method: "POST", body: { name } });
                form.reset();
              }, "Team created.");
            }}
          >
            <label>
              Team name
              <input
                name="name"
                placeholder="Platform engineering"
                required
                minLength={2}
                maxLength={80}
              />
            </label>
            <button className="button primary" disabled={action.busy}>
              <Icon name="plus" /> Create team
            </button>
          </form>
          <div className="panel-notice">
            <Notice status={action.status} />
          </div>
        </Panel>
      )}
      <Panel
        title="Teams"
        action={<Search label="Search teams" onSubmit={pager.search} />}
      >
        {!result && <Loading />}
        {result && "error" in result && (
          <Failure error={result.error} onRetry={retry} />
        )}
        {result?.data && (
          <>
            {result.data.items.length === 0 ? (
              <Empty icon="teams" title="No teams match this search">
                Create a team to group organization members.
              </Empty>
            ) : (
              <DataTable columns={["Team name", "Actions"]}>
                {result.data.items.map((team) => (
                  <tr key={team.id}>
                    <td>
                      <strong>{team.name}</strong>
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          className="button secondary small"
                          type="button"
                          aria-expanded={selected?.id === team.id}
                          onClick={() =>
                            setSelected(
                              selected?.id === team.id ? undefined : team,
                            )
                          }
                        >
                          {selected?.id === team.id
                            ? "Hide members"
                            : "View members"}
                        </button>
                        {manager && (
                          <button
                            className="button danger-quiet small"
                            disabled={action.busy}
                            aria-label={`Delete team ${team.name}`}
                            onClick={() => {
                              if (
                                window.confirm(`Delete the team ${team.name}?`)
                              ) {
                                void action.run(async () => {
                                  await api(
                                    `${base}/${encodeURIComponent(team.id)}`,
                                    { method: "DELETE" },
                                  );
                                  if (selected?.id === team.id)
                                    setSelected(undefined);
                                }, "Team deleted.");
                              }
                            }}
                          >
                            Delete
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </DataTable>
            )}
            <Pagination
              page={pager.page}
              total={result.data.total}
              setPage={pager.setPage}
            />
          </>
        )}
      </Panel>
      {selected && <TeamMembers key={selected.id} org={org} team={selected} />}
    </>
  );
}
