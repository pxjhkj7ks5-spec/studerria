CREATE SCHEMA IF NOT EXISTS obriy;
CREATE TABLE IF NOT EXISTS obriy.schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS obriy.users (
 id uuid PRIMARY KEY, owner boolean NOT NULL DEFAULT false, chat_enc text, chat_hash text UNIQUE,
 paused_until timestamptz, last_delivery_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS obriy_one_owner ON obriy.users(owner) WHERE owner;
CREATE TABLE IF NOT EXISTS obriy.sessions (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES obriy.users(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS obriy.pairing_codes (
 code_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES obriy.users(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS obriy.zones (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES obriy.users(id) ON DELETE CASCADE,
 data_enc text NOT NULL, enabled boolean NOT NULL DEFAULT true, revision int NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS obriy_zones_user ON obriy.zones(user_id);
CREATE TABLE IF NOT EXISTS obriy.tracks (
 id uuid PRIMARY KEY, external_id text UNIQUE NOT NULL, data jsonb NOT NULL,
 updated_at timestamptz NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
 status text NOT NULL, resolved_at timestamptz
);
CREATE INDEX IF NOT EXISTS obriy_tracks_age ON obriy.tracks(status,updated_at);
CREATE TABLE IF NOT EXISTS obriy.source_events (
 event_key text PRIMARY KEY, provider text NOT NULL, data jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS obriy.track_points (
 id bigserial PRIMARY KEY, track_id uuid NOT NULL REFERENCES obriy.tracks(id) ON DELETE CASCADE,
 observed_at timestamptz NOT NULL, data jsonb NOT NULL, UNIQUE(track_id,observed_at)
);
CREATE TABLE IF NOT EXISTS obriy.official_alerts (
 provider text NOT NULL, external_id text NOT NULL, data jsonb NOT NULL,
 active boolean NOT NULL, updated_at timestamptz NOT NULL,
 received_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(provider,external_id)
);
CREATE TABLE IF NOT EXISTS obriy.alert_state (
 zone_id uuid NOT NULL REFERENCES obriy.zones(id) ON DELETE CASCADE,
 track_id uuid NOT NULL REFERENCES obriy.tracks(id) ON DELETE CASCADE,
 data jsonb NOT NULL, assessment_enc text NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(zone_id,track_id)
);
CREATE TABLE IF NOT EXISTS obriy.risk_assessments (
 id bigserial PRIMARY KEY, zone_id uuid NOT NULL REFERENCES obriy.zones(id) ON DELETE CASCADE,
 track_id uuid NOT NULL REFERENCES obriy.tracks(id) ON DELETE CASCADE,
 data_enc text NOT NULL, engine_version text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS obriy.notification_outbox (
 id uuid PRIMARY KEY, dedupe_key text UNIQUE NOT NULL,
 user_id uuid NOT NULL REFERENCES obriy.users(id) ON DELETE CASCADE,
 zone_id uuid REFERENCES obriy.zones(id) ON DELETE CASCADE,
 track_id uuid REFERENCES obriy.tracks(id) ON DELETE CASCADE,
 payload_enc text NOT NULL, category text NOT NULL DEFAULT 'risk',
 status text NOT NULL DEFAULT 'pending', attempts int NOT NULL DEFAULT 0,
 retry_at timestamptz NOT NULL DEFAULT now(), lease_until timestamptz, lease_token uuid,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 last_error_code text
);
CREATE INDEX IF NOT EXISTS obriy_outbox_pending ON obriy.notification_outbox(status,retry_at);
CREATE TABLE IF NOT EXISTS obriy.notifications (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES obriy.users(id) ON DELETE CASCADE,
 outbox_id uuid REFERENCES obriy.notification_outbox(id) ON DELETE CASCADE,
 status text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS obriy.push_subscriptions (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES obriy.users(id) ON DELETE CASCADE,
 data_enc text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS obriy.audit_events (
 id bigserial PRIMARY KEY, event_code text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS obriy.runtime_state (key text PRIMARY KEY, data jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS obriy.telegram_updates (update_id bigint PRIMARY KEY, processed_at timestamptz NOT NULL DEFAULT now());
