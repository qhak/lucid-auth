import { browserSupportsWebAuthn } from "@simplewebauthn/browser";
import { useState } from "react";
import { api, orgApi, time, useOperation, useRemote } from "./api";
import type { Device, Items, Organization, Session, Settings } from "./api";
import { passkey } from "./auth";
import { Empty, Failure, Icon, Loading, Notice, Panel } from "./components";
import { canManage, ProviderStatus } from "./views";

type Passkey = { id: string; createdAt: number };

function PasskeySettings() {
  const [revision, setRevision] = useState(0);
  const result = useRemote<Items<Passkey>>("/api/account/passkeys", revision);
  const retry = () => setRevision((number) => number + 1);
  const operation = useOperation(retry);
  return (
    <Panel
      title="Passkeys"
      description="Manage credentials that can sign in to your account."
      action={
        browserSupportsWebAuthn() && (
          <button
            className="button primary"
            disabled={operation.busy}
            onClick={() => {
              void operation.run(
                () => passkey("register"),
                "Passkey registered.",
              );
            }}
          >
            <Icon name="key" /> Register a passkey
          </button>
        )
      }
    >
      <div className="panel-notice">
        <Notice status={operation.status} />
      </div>
      {!result && <Loading />}
      {result && "error" in result && (
        <Failure error={result.error} onRetry={retry} />
      )}
      {result?.data &&
        (result.data.items.length === 0 ? (
          <Empty icon="key" title="No passkeys registered" />
        ) : (
          <ul className="device-list">
            {result.data.items.map((credential) => (
              <li key={credential.id}>
                <span className="icon-tile">
                  <Icon name="key" />
                </span>
                <div>
                  <strong>Passkey</strong>
                  <small>Added {time(credential.createdAt)}</small>
                </div>
                <button
                  className="button danger-quiet small"
                  disabled={operation.busy}
                  aria-label={`Remove passkey added ${time(credential.createdAt)}`}
                  onClick={() => {
                    if (
                      window.confirm("Remove this passkey from your account?")
                    ) {
                      void operation.run(
                        () =>
                          api(
                            `/api/account/passkeys/${encodeURIComponent(credential.id)}`,
                            { method: "DELETE" },
                          ),
                        "Passkey removed.",
                      );
                    }
                  }}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
        ))}
    </Panel>
  );
}

export function SettingsScreen({
  organization,
  session,
  settings,
  onOrgUpdate,
  onSignOut,
}: {
  organization?: Organization;
  session: Session;
  settings?: Settings;
  onOrgUpdate: () => void;
  onSignOut: () => void;
}) {
  const [revision, setRevision] = useState(0);
  const devices = useRemote<Items<Device>>("/api/account/sessions", revision);
  const refresh = () => setRevision((number) => number + 1);
  const orgOperation = useOperation(onOrgUpdate);
  const accountOperation = useOperation(refresh);
  const deletion = useOperation();
  return (
    <>
      {organization && canManage(organization) && (
        <Panel title="Organization details">
          <form
            className="inline-form"
            onSubmit={(event) => {
              event.preventDefault();
              const name = new FormData(event.currentTarget).get("name");
              void orgOperation.run(
                () =>
                  api(orgApi(organization.id), {
                    method: "PATCH",
                    body: { name },
                  }),
                "Organization updated.",
              );
            }}
          >
            <label>
              Organization name
              <input
                key={organization.name}
                name="name"
                defaultValue={organization.name}
                required
                minLength={2}
                maxLength={80}
              />
            </label>
            <button className="button primary" disabled={orgOperation.busy}>
              Save name
            </button>
          </form>
          <div className="panel-notice">
            <Notice status={orgOperation.status} />
          </div>
        </Panel>
      )}
      <Panel
        title="Identity providers"
        description="Google and WebAuthn are configured in the Worker deployment."
      >
        <ProviderStatus settings={settings} />
      </Panel>
      {settings?.passkeys && <PasskeySettings />}
      <Panel title="Your account" description={session.user.email}>
        <div className="panel-copy panel-actions">
          <button
            className="button secondary"
            disabled={accountOperation.busy}
            onClick={() => {
              if (window.confirm("Sign out all devices, including this one?")) {
                void accountOperation.run(async () => {
                  await api("/api/auth/logout-all", { method: "POST" });
                  onSignOut();
                });
              }
            }}
          >
            Sign out all devices
          </button>
        </div>
        <div className="panel-notice">
          <Notice status={accountOperation.status} />
        </div>
        <h3 className="panel-copy device-heading">Your sessions</h3>
        {!devices && <Loading />}
        {devices && "error" in devices && (
          <Failure error={devices.error} onRetry={refresh} />
        )}
        {devices?.data &&
          (devices.data.items.length > 0 ? (
            <ul className="device-list">
              {devices.data.items.map((device) => (
                <li key={device.id}>
                  <span className="icon-tile">
                    <Icon name="sessions" />
                  </span>
                  <div>
                    <strong>
                      {device.id === session.session.id
                        ? "This device"
                        : "Signed-in device"}
                    </strong>
                    <small>
                      Created {time(device.createdAt)} · Expires{" "}
                      {time(device.expiresAt)}
                    </small>
                  </div>
                  <button
                    className="button danger-quiet small"
                    disabled={accountOperation.busy}
                    aria-label={`Revoke session created ${time(device.createdAt)}`}
                    onClick={() => {
                      if (window.confirm("Sign out this device?")) {
                        void accountOperation.run(async () => {
                          await api(
                            `/api/account/sessions/${encodeURIComponent(device.id)}`,
                            { method: "DELETE" },
                          );
                          if (device.id === session.session.id) onSignOut();
                        }, "Session revoked.");
                      }
                    }}
                  >
                    Revoke
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <Empty icon="sessions" title="No active sessions" />
          ))}
      </Panel>
      <Panel
        title="Delete account"
        description="This permanently removes your account and credentials."
      >
        <div className="panel-copy">
          <button
            className="button danger-quiet"
            disabled={deletion.busy}
            onClick={() => {
              if (window.confirm(`Permanently delete ${session.user.email}?`)) {
                void deletion.run(async () => {
                  await api("/api/account", {
                    method: "DELETE",
                    body: { confirm: true },
                  });
                  onSignOut();
                });
              }
            }}
          >
            Delete my account
          </button>
        </div>
        <div className="panel-notice">
          <Notice status={deletion.status} />
        </div>
      </Panel>
    </>
  );
}
