CREATE TABLE users (
  id TEXT PRIMARY KEY NOT NULL,
  email TEXT NOT NULL UNIQUE,
  verified_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE TABLE credentials (
  user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL
);
CREATE TABLE oauth_identities (
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (provider, subject),
  UNIQUE (user_id, provider)
);
CREATE TABLE passkeys (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL CHECK(counter >= 0),
  transports TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX passkeys_user ON passkeys(user_id);
CREATE TABLE sessions (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  access_hash TEXT NOT NULL UNIQUE,
  refresh_hash TEXT NOT NULL UNIQUE,
  access_expires_at INTEGER NOT NULL,
  refresh_expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id, refresh_expires_at);
CREATE INDEX sessions_expiry ON sessions(refresh_expires_at);
CREATE TABLE verification_tokens (
  token_hash TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK(kind IN ('verify', 'reset')),
  binding_hash TEXT,
  expires_at INTEGER NOT NULL
);
CREATE INDEX verification_user ON verification_tokens(user_id, kind);
CREATE INDEX verification_expiry ON verification_tokens(expires_at);
CREATE TABLE flows (
  id_hash TEXT PRIMARY KEY NOT NULL,
  kind TEXT NOT NULL,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  binding_hash TEXT,
  data TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX flows_expiry ON flows(expires_at);
CREATE INDEX flows_user ON flows(user_id);
CREATE TABLE organizations (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE roles (id TEXT PRIMARY KEY NOT NULL);
CREATE TABLE role_permissions (
  role_id TEXT NOT NULL REFERENCES roles(id),
  permission TEXT NOT NULL,
  PRIMARY KEY (role_id, permission)
);
INSERT INTO roles VALUES ('owner'), ('admin'), ('member'), ('viewer');
INSERT INTO role_permissions VALUES
  ('owner','org:read'), ('owner','org:write'), ('owner','members:write'),
  ('owner','teams:write'), ('owner','sessions:write'), ('owner','audit:read'),
  ('admin','org:read'), ('admin','org:write'), ('admin','members:write'),
  ('admin','teams:write'), ('admin','sessions:write'), ('admin','audit:read'),
  ('member','org:read'), ('viewer','org:read');
CREATE TABLE memberships (
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id TEXT NOT NULL REFERENCES roles(id),
  PRIMARY KEY (org_id, user_id)
);
CREATE INDEX memberships_user ON memberships(user_id, org_id);
CREATE TABLE teams (
  id TEXT PRIMARY KEY NOT NULL,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  UNIQUE (org_id, id),
  UNIQUE (org_id, name)
);
CREATE TABLE team_members (
  org_id TEXT NOT NULL,
  team_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  PRIMARY KEY (team_id, user_id),
  FOREIGN KEY (org_id, team_id) REFERENCES teams(org_id, id) ON DELETE CASCADE,
  FOREIGN KEY (org_id, user_id) REFERENCES memberships(org_id, user_id) ON DELETE CASCADE
);
CREATE INDEX team_members_membership ON team_members(org_id, user_id);
CREATE TABLE audit_events (
  id TEXT PRIMARY KEY NOT NULL,
  org_id TEXT REFERENCES organizations(id) ON DELETE CASCADE,
  actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  subject_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  subject TEXT,
  kind TEXT NOT NULL CHECK(kind IN ('auth','audit')),
  created_at INTEGER NOT NULL
);
CREATE INDEX events_org ON audit_events(org_id, created_at DESC);
CREATE INDEX events_actor ON audit_events(actor_id, created_at DESC);
CREATE INDEX events_subject ON audit_events(subject_id);
CREATE INDEX events_expiry ON audit_events(created_at);
CREATE TABLE rate_limits (
  key TEXT PRIMARY KEY NOT NULL,
  requests INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX limits_expiry ON rate_limits(expires_at);
CREATE TABLE dev_mail (
  id TEXT PRIMARY KEY NOT NULL,
  email TEXT NOT NULL,
  kind TEXT NOT NULL,
  token TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX dev_mail_email ON dev_mail(email, created_at DESC);
