CREATE TABLE org_session_revocations (
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  PRIMARY KEY (org_id, session_id)
);
CREATE INDEX org_session_revocations_session ON org_session_revocations(session_id);
