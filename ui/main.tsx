import { useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { api, ApiError, useOperation, useRemote } from "./api";
import type { Items, Organization, Session, Settings } from "./api";
import { AuthScreen } from "./auth";
import type { AuthLink } from "./auth";
import {
  Brand,
  Failure,
  Icon,
  Loading,
  Notice,
  Panel,
  RoleTag,
} from "./components";
import type { IconName } from "./components";
import { SettingsScreen } from "./settings";
import {
  canManage,
  EventScreen,
  MemberScreen,
  OverviewScreen,
  SessionScreen,
  TeamScreen,
} from "./views";
import "./styles.css";

type View =
  | "overview"
  | "members"
  | "teams"
  | "sessions"
  | "activity"
  | "audit"
  | "settings";

const menu: { id: View; icon: IconName; label: string; description: string }[] =
  [
    {
      id: "overview",
      icon: "overview",
      label: "Overview",
      description: "Organization identity and access activity.",
    },
    {
      id: "members",
      icon: "users",
      label: "Members",
      description: "Manage user access and roles for this organization.",
    },
    {
      id: "teams",
      icon: "teams",
      label: "Teams",
      description: "Group members within the organization.",
    },
    {
      id: "sessions",
      icon: "sessions",
      label: "Sessions",
      description: "Review and revoke active sessions.",
    },
    {
      id: "activity",
      icon: "activity",
      label: "Authentication events",
      description: "Review recorded sign-ins and account activity.",
    },
    {
      id: "audit",
      icon: "audit",
      label: "Security audit log",
      description: "Review changes to memberships, teams, and access.",
    },
    {
      id: "settings",
      icon: "settings",
      label: "Settings",
      description: "Manage your account and deployment configuration.",
    },
  ];

function NewOrganization({ add }: { add: (id: string) => void }) {
  const operation = useOperation();
  return (
    <Panel
      title="Create an organization"
      description="New organizations start with your account as the owner."
    >
      <form
        className="inline-form"
        onSubmit={(event) => {
          event.preventDefault();
          const name = new FormData(event.currentTarget).get("name");
          void operation.run(async () => {
            const { id } = await api<{ id: string }>("/api/orgs", {
              method: "POST",
              body: { name },
            });
            add(id);
          });
        }}
      >
        <label>
          Organization name
          <input
            name="name"
            placeholder="Acme Engineering"
            required
            minLength={2}
            maxLength={80}
          />
        </label>
        <button className="button primary" disabled={operation.busy}>
          <Icon name="plus" />{" "}
          {operation.busy ? "Creating…" : "Create organization"}
        </button>
      </form>
      <div className="panel-notice">
        <Notice status={operation.status} />
      </div>
    </Panel>
  );
}

function Dashboard({
  session,
  settings,
  onSignOut,
}: {
  session: Session;
  settings?: Settings;
  onSignOut: () => void;
}) {
  const [revision, setRevision] = useState(0);
  const organizations = useRemote<Items<Organization>>("/api/orgs", revision);
  const [selected, setSelected] = useState("");
  const [view, setView] = useState<View>("overview");
  const [createOrg, setCreateOrg] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const operation = useOperation();
  const roleOrgs = organizations?.data?.items ?? [];
  const organization =
    roleOrgs.find((entry) => entry.id === selected) ?? roleOrgs[0];
  const showSecurity = organization && canManage(organization);
  const entry = menu.find((item) => item.id === view);
  const reload = () => setRevision((number) => number + 1);

  function open(next: View) {
    setView(next);
    setCreateOrg(false);
    setMobileOpen(false);
    document.getElementById("content")?.focus();
  }

  function create() {
    setCreateOrg(true);
    setMobileOpen(false);
    document.getElementById("content")?.focus();
  }

  function signOut() {
    void operation.run(async () => {
      await api("/api/auth/logout", { method: "POST" });
      onSignOut();
    });
  }

  return (
    <div className="shell">
      <a className="skip-link" href="#content">
        Skip to content
      </a>
      <aside className="sidebar" aria-label="Console sidebar">
        <div className="sidebar-brand">
          <Brand />
          <button
            className="button secondary mobile-toggle"
            aria-controls="console-navigation"
            aria-expanded={mobileOpen}
            aria-label={mobileOpen ? "Close navigation" : "Open navigation"}
            onClick={() => setMobileOpen(!mobileOpen)}
          >
            <Icon name="menu" />
          </button>
        </div>
        <div
          className={`sidebar-body ${mobileOpen ? "is-open" : ""}`}
          id="console-navigation"
        >
          <div className="org-switcher">
            <span className="org-avatar" aria-hidden="true">
              {organization ? (
                organization.name.slice(0, 1).toUpperCase()
              ) : (
                <Icon name="building" />
              )}
            </span>
            <label>
              <span className="sr-only">Select organization</span>
              <select
                value={organization?.id ?? ""}
                onChange={(event) => {
                  setSelected(event.target.value);
                  open("overview");
                }}
                disabled={!organization}
              >
                {roleOrgs.length === 0 && (
                  <option value="">No organizations</option>
                )}
                {roleOrgs.map((entry) => (
                  <option value={entry.id} key={entry.id}>
                    {entry.name}
                  </option>
                ))}
              </select>
            </label>
            <button
              className="org-add"
              aria-label="Create organization"
              title="Create organization"
              onClick={create}
            >
              <Icon name="plus" size={16} />
            </button>
          </div>
          <nav aria-label="Console navigation">
            {[
              { label: "Workspace", entries: menu.slice(0, 4) },
              { label: "Security", entries: menu.slice(4) },
            ].map((group) => (
              <div className="nav-group" key={group.label}>
                <p>{group.label}</p>
                {group.entries
                  .filter(
                    (item) =>
                      showSecurity ||
                      !["sessions", "activity", "audit"].includes(item.id),
                  )
                  .map((item) => (
                    <button
                      className="nav-link"
                      aria-current={
                        item.id === view && !createOrg ? "page" : undefined
                      }
                      key={item.id}
                      disabled={
                        !organization &&
                        item.id !== "overview" &&
                        item.id !== "settings"
                      }
                      onClick={() => open(item.id)}
                    >
                      <Icon name={item.icon} />
                      <span>{item.label}</span>
                    </button>
                  ))}
              </div>
            ))}
          </nav>
          <div className="sidebar-account">
            <span className="user-avatar" aria-hidden="true">
              {session.user.email.charAt(0).toUpperCase()}
            </span>
            <div>
              <strong title={session.user.email}>{session.user.email}</strong>
              <small>Signed in</small>
            </div>
            <button
              className="icon-button"
              aria-label="Sign out"
              title="Sign out"
              disabled={operation.busy}
              onClick={signOut}
            >
              <Icon name="logout" />
            </button>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumbs">
            <Icon name="building" size={16} />
            <span>Console</span>
            <Icon name="right" size={13} />
            <strong>{createOrg ? "Create organization" : entry?.label}</strong>
          </div>
          {organization && <RoleTag role={organization.role} />}
        </header>
        <main className="main-content" id="content" tabIndex={-1}>
          <Notice status={operation.status} />
          {!createOrg && view !== "overview" && (
            <header className="page-heading">
              <h1>{entry?.label}</h1>
              <p>{entry?.description}</p>
            </header>
          )}
          {createOrg && (
            <header className="page-heading">
              <h1>New organization</h1>
            </header>
          )}
          {createOrg ||
          (view === "overview" && organizations?.data && !organization) ? (
            <NewOrganization
              add={(id) => {
                setSelected(id);
                reload();
                open("overview");
              }}
            />
          ) : view === "settings" ? (
            <SettingsScreen
              key={organization?.id}
              organization={organization}
              session={session}
              settings={settings}
              onOrgUpdate={reload}
              onSignOut={onSignOut}
            />
          ) : !organizations ? (
            <div className="panel">
              <Loading />
            </div>
          ) : "error" in organizations ? (
            <div className="panel">
              <Failure error={organizations.error} onRetry={reload} />
            </div>
          ) : (
            organization && (
              <div className="view-content" key={`${organization.id}:${view}`}>
                {view === "overview" && (
                  <OverviewScreen
                    org={organization}
                    settings={settings}
                    openEvents={() => open("activity")}
                  />
                )}
                {view === "members" && (
                  <MemberScreen
                    org={organization}
                    session={session}
                    onUpdate={reload}
                  />
                )}
                {view === "teams" && <TeamScreen org={organization} />}
                {view === "sessions" && showSecurity && (
                  <SessionScreen
                    org={organization}
                    session={session}
                    onOrgRevoked={() => {
                      reload();
                      open("overview");
                    }}
                  />
                )}
                {view === "activity" && showSecurity && (
                  <EventScreen org={organization} kind="auth" />
                )}
                {view === "audit" && showSecurity && (
                  <EventScreen org={organization} kind="audit" />
                )}
              </div>
            )
          )}
        </main>
      </div>
    </div>
  );
}

function getEntry() {
  const url = new URL(window.location.href);
  const fragment = new URLSearchParams(url.hash.slice(1));
  const mode = url.searchParams.get("mode");
  const token = fragment.get("token");
  const oauthError = url.searchParams.get("auth") === "google_failed";
  const link: AuthLink | undefined =
    token && (mode === "verify" || mode === "reset")
      ? { mode, token }
      : undefined;
  if (token || oauthError || link) {
    url.hash = "";
    url.searchParams.delete("mode");
    url.searchParams.delete("auth");
    window.history.replaceState(null, "", url);
  }
  return { link, oauthError };
}

const initialEntry = getEntry();

function App() {
  const [revision, setRevision] = useState(0);
  const [link, setLink] = useState(initialEntry.link);
  const [signedOut, setSignedOut] = useState(false);
  const session = useRemote<Session>("/api/session", revision, false);
  const settings = useRemote<Settings>("/api/settings");
  const signOut = useCallback(() => setSignedOut(true), []);
  useEffect(() => {
    window.addEventListener("lucid-session-expired", signOut);
    return () => window.removeEventListener("lucid-session-expired", signOut);
  }, [signOut]);
  function signIn() {
    setLink(undefined);
    setSignedOut(false);
    setRevision((value) => value + 1);
  }
  const unauthenticated =
    session?.error instanceof ApiError && session.error.status === 401;
  if (link || signedOut || unauthenticated) {
    return (
      <AuthScreen
        link={link}
        oauthError={initialEntry.oauthError && revision === 0}
        settings={settings?.data}
        onSession={signIn}
      />
    );
  }
  if (session?.data)
    return (
      <Dashboard
        session={session.data}
        settings={settings?.data}
        onSignOut={signOut}
      />
    );
  return (
    <main className="boot">
      <Brand />
      {session && "error" in session ? (
        <Failure
          error={session.error}
          onRetry={() => setRevision((value) => value + 1)}
        />
      ) : (
        <Loading />
      )}
    </main>
  );
}

const mount = document.getElementById("root");
if (!mount) throw new Error("Console root element is missing");
createRoot(mount).render(<App />);
