import type { ReactNode } from "react";
import { message, type Role } from "./api";

const paths = {
  overview: "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
  users:
    "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M22 21v-2a4 4 0 0 0-3-3.87 M16 3.13a4 4 0 0 1 0 7.75",
  teams: "M12 2 2 7l10 5 10-5-10-5z M2 12l10 5 10-5 M2 17l10 5 10-5",
  sessions: "M3 4h18v13H3z M8 21h8 M12 17v4",
  activity: "M2 12h4l3-8 5 16 3-8h5",
  audit: "M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11z M9 12l2 2 4-4",
  settings: "M4 7h16 M4 17h16 M8 4v6 M16 14v6",
  logout: "M10 17l5-5-5-5 M15 12H3 M15 3h6v18h-6",
  arrow: "M5 12h14 M14 7l5 5-5 5",
  plus: "M12 5v14 M5 12h14",
  search: "M10.5 18a7.5 7.5 0 1 0 0-15 7.5 7.5 0 0 0 0 15z M16 16l5 5",
  key: "M15 7a5 5 0 1 0-1 8l3 3h3v-3h-2v-2l-2-2a5 5 0 0 0-1-4z M8.5 8.5h.01",
  building: "M4 21V5h11v16 M15 9h5v12 M2 21h20 M8 9h3 M8 13h3 M8 17h3",
  left: "M15 18l-6-6 6-6",
  right: "M9 18l6-6-6-6",
  refresh: "M20 8a8 8 0 1 0 0 8 M20 3v5h-5",
  clock: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z M12 6v6l4 2",
  menu: "M4 6h16 M4 12h16 M4 18h16",
  google: "M21 12h-9 M20.5 7a9 9 0 1 0 .5 5",
} as const;

export type IconName = keyof typeof paths;

export function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  return (
    <svg
      aria-hidden="true"
      width={size}
      height={size}
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d={paths[name]} />
    </svg>
  );
}

export function Brand() {
  return (
    <span className="brand">
      <span className="brand-mark" aria-hidden="true">
        <i />
      </span>
      Lucid<span className="brand-suffix">Auth</span>
    </span>
  );
}

export function Notice({
  status,
}: {
  status?: { tone: "error" | "success"; text: string };
}) {
  if (!status) return null;
  return (
    <p
      role={status.tone === "error" ? "alert" : "status"}
      className={`notice ${status.tone}`}
    >
      {status.text}
    </p>
  );
}

export function Failure({
  error,
  onRetry,
}: {
  error: unknown;
  onRetry: () => void;
}) {
  return (
    <div className="empty">
      <strong>Couldn’t load this view</strong>
      <p role="alert">{message(error)}</p>
      <button className="button secondary" onClick={onRetry}>
        <Icon name="refresh" /> Retry
      </button>
    </div>
  );
}

export function Loading() {
  return (
    <div className="empty" role="status">
      <span className="spinner" /> Loading…
    </div>
  );
}

export function Empty({
  icon = "activity",
  title,
  children,
}: {
  icon?: IconName;
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty">
      <span className="icon-tile">
        <Icon name={icon} size={20} />
      </span>
      <strong>{title}</strong>
      {children && <p>{children}</p>}
    </div>
  );
}

export function Panel({
  title,
  description,
  action,
  children,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="panel">
      <header className="panel-head">
        <div>
          <h2>{title}</h2>
          {description && <p>{description}</p>}
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}

export function RoleTag({ role }: { role: Role }) {
  return <span className={`tag role-${role}`}>{role}</span>;
}

export function StateTag({
  enabled,
  on = "Enabled",
  off = "Disabled",
}: {
  enabled: boolean;
  on?: string;
  off?: string;
}) {
  return (
    <span className={`tag state-tag ${enabled ? "enabled" : ""}`}>
      <i aria-hidden="true" />
      {enabled ? on : off}
    </span>
  );
}
