'use strict';

const statements = [
  `CREATE TABLE investigations (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 160),
    description TEXT NOT NULL DEFAULT '' CHECK (char_length(description) <= 2000),
    created_by BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE entities (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK (type IN ('PERSON','SOCIAL_ACCOUNT','ORGANIZATION','DOMAIN','WEBSITE','EMAIL','PHONE','LOCATION','POST','PUBLIC_CHANNEL','OTHER')),
    canonical_name TEXT NOT NULL CHECK (char_length(canonical_name) BETWEEN 1 AND 500),
    display_name TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 500),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (investigation_id, type, canonical_name),
    UNIQUE (id, investigation_id)
  )`,
  `CREATE TABLE social_accounts (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL,
    entity_id UUID NOT NULL,
    platform TEXT NOT NULL CHECK (char_length(platform) BETWEEN 1 AND 40),
    username TEXT NOT NULL CHECK (char_length(username) BETWEEN 1 AND 160),
    profile_url TEXT,
    display_name TEXT,
    bio TEXT,
    avatar_url TEXT,
    followers_count BIGINT,
    following_count BIGINT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (entity_id, investigation_id) REFERENCES entities(id, investigation_id) ON DELETE CASCADE,
    UNIQUE (investigation_id, platform, username),
    UNIQUE (entity_id)
  )`,
  `CREATE TABLE observations (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    entity_id UUID,
    source_type TEXT NOT NULL,
    source_url TEXT NOT NULL,
    collector TEXT NOT NULL,
    raw_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (entity_id, investigation_id) REFERENCES entities(id, investigation_id) ON DELETE CASCADE
  )`,
  `CREATE TABLE relationships (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    source_entity_id UUID NOT NULL,
    target_entity_id UUID NOT NULL,
    relationship_type TEXT NOT NULL CHECK (relationship_type IN ('FOLLOWS','FOLLOWED_BY','MUTUAL_FOLLOW','MENTIONS','COMMENTED_ON','COLLABORATED_WITH','LINKED_TO','MEMBER_OF','WORKS_AT','ASSOCIATED_WITH','SAME_USERNAME','SAME_DOMAIN','COMMON_CONNECTION','OTHER')),
    epistemic_status TEXT NOT NULL DEFAULT 'FACT' CHECK (epistemic_status IN ('FACT','INFERENCE')),
    weight NUMERIC(8,3) NOT NULL DEFAULT 1 CHECK (weight >= 0),
    confidence NUMERIC(5,4) NOT NULL DEFAULT 1 CHECK (confidence BETWEEN 0 AND 1),
    explanation TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (source_entity_id, investigation_id) REFERENCES entities(id, investigation_id) ON DELETE CASCADE,
    FOREIGN KEY (target_entity_id, investigation_id) REFERENCES entities(id, investigation_id) ON DELETE CASCADE,
    CHECK (source_entity_id <> target_entity_id),
    UNIQUE (investigation_id, source_entity_id, target_entity_id, relationship_type, epistemic_status)
  )`,
  `CREATE TABLE relationship_evidence (
    id UUID PRIMARY KEY,
    relationship_id UUID NOT NULL REFERENCES relationships(id) ON DELETE CASCADE,
    observation_id UUID REFERENCES observations(id) ON DELETE SET NULL,
    source_type TEXT NOT NULL,
    source_url TEXT NOT NULL,
    collector TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confidence NUMERIC(5,4) NOT NULL DEFAULT 1 CHECK (confidence BETWEEN 0 AND 1),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (relationship_id, collector, source_url)
  )`,
  `CREATE TABLE inference_inputs (
    inference_relationship_id UUID NOT NULL REFERENCES relationships(id) ON DELETE CASCADE,
    fact_relationship_id UUID NOT NULL REFERENCES relationships(id) ON DELETE CASCADE,
    PRIMARY KEY (inference_relationship_id, fact_relationship_id),
    CHECK (inference_relationship_id <> fact_relationship_id)
  )`,
  `CREATE TABLE interactions (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    source_entity_id UUID NOT NULL,
    target_entity_id UUID NOT NULL,
    type TEXT NOT NULL,
    source_url TEXT NOT NULL,
    happened_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    FOREIGN KEY (source_entity_id, investigation_id) REFERENCES entities(id, investigation_id) ON DELETE CASCADE,
    FOREIGN KEY (target_entity_id, investigation_id) REFERENCES entities(id, investigation_id) ON DELETE CASCADE
  )`,
  `CREATE TABLE analysis_runs (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('COLLECTOR','ANALYSIS')),
    status TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed')),
    collector TEXT,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    result JSONB NOT NULL DEFAULT '{}'::jsonb,
    error TEXT,
    created_by BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE analysis_findings (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    analysis_run_id UUID NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
    finding_type TEXT NOT NULL,
    title TEXT NOT NULL,
    explanation TEXT NOT NULL,
    confidence NUMERIC(5,4),
    entity_ids UUID[] NOT NULL DEFAULT '{}',
    input_relationship_ids UUID[] NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  'CREATE INDEX entities_investigation_idx ON entities(investigation_id)',
  'CREATE INDEX entities_type_idx ON entities(investigation_id, type)',
  'CREATE INDEX social_accounts_lookup_idx ON social_accounts(investigation_id, platform, lower(username))',
  'CREATE INDEX relationships_source_idx ON relationships(investigation_id, source_entity_id)',
  'CREATE INDEX relationships_target_idx ON relationships(investigation_id, target_entity_id)',
  'CREATE INDEX relationships_type_confidence_idx ON relationships(investigation_id, relationship_type, confidence)',
  'CREATE INDEX observations_entity_time_idx ON observations(investigation_id, entity_id, observed_at DESC)',
  'CREATE INDEX interactions_pair_time_idx ON interactions(investigation_id, source_entity_id, target_entity_id, happened_at DESC)',
  'CREATE INDEX analysis_runs_investigation_time_idx ON analysis_runs(investigation_id, created_at DESC)',
  'CREATE INDEX findings_investigation_idx ON analysis_findings(investigation_id, finding_type)',
  'CREATE INDEX audit_logs_user_time_idx ON audit_logs(user_id, created_at DESC)',
  'CREATE INDEX audit_logs_resource_idx ON audit_logs(resource_type, resource_id, created_at DESC)'
];

async function up(client) {
  for (const statement of statements) await client.query(statement);
}

module.exports = { id: '001_initial_graph', up };
