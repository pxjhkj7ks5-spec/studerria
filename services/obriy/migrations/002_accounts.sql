CREATE TABLE IF NOT EXISTS obriy.accounts (
 user_id uuid PRIMARY KEY REFERENCES obriy.users(id) ON DELETE CASCADE,
 username text NOT NULL UNIQUE,
 password_hash text NOT NULL,
 revision uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE obriy.sessions ADD COLUMN IF NOT EXISTS auth_revision uuid;
CREATE TABLE IF NOT EXISTS obriy.access_gates (
 token_hash text PRIMARY KEY, key_hash text NOT NULL, expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS obriy.login_attempts (
 account_key text NOT NULL, attempted_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS obriy_login_attempts_key ON obriy.login_attempts(account_key,attempted_at);
