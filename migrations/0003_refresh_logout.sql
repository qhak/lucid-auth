ALTER TABLE sessions ADD COLUMN previous_refresh_hash TEXT;
CREATE INDEX sessions_previous_refresh ON sessions(previous_refresh_hash)
WHERE previous_refresh_hash IS NOT NULL;
DROP TABLE IF EXISTS dev_mail;
