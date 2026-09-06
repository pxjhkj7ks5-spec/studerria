CREATE TABLE IF NOT EXISTS obriy.channel_messages (
 id uuid PRIMARY KEY, channel text NOT NULL, message_id bigint NOT NULL,
 published_at timestamptz NOT NULL, received_at timestamptz NOT NULL,
 content_hash text NOT NULL, revision int NOT NULL DEFAULT 1,
 data_enc text NOT NULL, parsed jsonb, processed_revision int NOT NULL DEFAULT 0,
 eligible boolean NOT NULL DEFAULT false, UNIQUE(channel,message_id)
);
CREATE TABLE IF NOT EXISTS obriy.channel_message_revisions (
 message_id uuid NOT NULL REFERENCES obriy.channel_messages(id) ON DELETE CASCADE,
 revision int NOT NULL, data_enc text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(message_id,revision)
);
CREATE TABLE IF NOT EXISTS obriy.channel_cursors (
 channel text PRIMARY KEY, high_id bigint NOT NULL, last_success_at timestamptz NOT NULL,
 initialized_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS obriy.bulletin_decisions (
 id uuid PRIMARY KEY, message_id uuid NOT NULL REFERENCES obriy.channel_messages(id) ON DELETE CASCADE,
 zone_id uuid NOT NULL REFERENCES obriy.zones(id) ON DELETE CASCADE,
 zone_revision int NOT NULL, message_revision int NOT NULL, area_ids jsonb NOT NULL,
 fingerprint text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(message_id,zone_id,message_revision)
);
ALTER TABLE obriy.notification_outbox ADD COLUMN IF NOT EXISTS bulletin_decision_id uuid REFERENCES obriy.bulletin_decisions(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS obriy_bulletin_pending ON obriy.channel_messages(received_at) WHERE processed_revision<revision;
CREATE INDEX IF NOT EXISTS obriy_bulletin_age ON obriy.channel_messages(published_at);
CREATE INDEX IF NOT EXISTS obriy_bulletin_zone ON obriy.bulletin_decisions(zone_id,created_at);
