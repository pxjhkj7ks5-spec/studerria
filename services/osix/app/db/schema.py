CLICKHOUSE_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS sources (
      id String,
      name String,
      url String,
      source_type String,
      dataset String,
      parser String,
      enabled UInt8,
      updated_at DateTime64(3, 'UTC')
    )
    ENGINE = ReplacingMergeTree(updated_at)
    ORDER BY id
    """,
    """
    CREATE TABLE IF NOT EXISTS raw_snapshots (
      id UUID DEFAULT generateUUIDv4(),
      source_id String,
      url String,
      fetched_at DateTime64(3, 'UTC'),
      content_hash String,
      storage_path String,
      size_bytes UInt64,
      status_code UInt16
    )
    ENGINE = MergeTree
    PARTITION BY toYYYYMM(fetched_at)
    ORDER BY (source_id, fetched_at, content_hash)
    """,
    """
    CREATE TABLE IF NOT EXISTS metrics_time_series (
      dataset String,
      metric String,
      metric_label String,
      source_id String,
      observed_date Date,
      timestamp DateTime64(3, 'UTC'),
      value Int64,
      daily_delta Nullable(Int64),
      content_hash String
    )
    ENGINE = ReplacingMergeTree(timestamp)
    PARTITION BY toYYYYMM(observed_date)
    ORDER BY (dataset, metric, source_id, observed_date)
    """,
    """
    CREATE TABLE IF NOT EXISTS parser_errors (
      id UUID DEFAULT generateUUIDv4(),
      source_id String,
      url String,
      occurred_at DateTime64(3, 'UTC'),
      content_hash String,
      error_type String,
      message String
    )
    ENGINE = MergeTree
    PARTITION BY toYYYYMM(occurred_at)
    ORDER BY (source_id, occurred_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS source_health (
      source_id String,
      checked_at DateTime64(3, 'UTC'),
      status String,
      status_code UInt16,
      latency_ms UInt32,
      last_success_at Nullable(DateTime64(3, 'UTC')),
      message String
    )
    ENGINE = ReplacingMergeTree(checked_at)
    ORDER BY source_id
    """,
    """
    CREATE TABLE IF NOT EXISTS admin_audit_log (
      id UUID DEFAULT generateUUIDv4(),
      actor String,
      role String,
      action String,
      target String,
      created_at DateTime64(3, 'UTC'),
      metadata String
    )
    ENGINE = MergeTree
    PARTITION BY toYYYYMM(created_at)
    ORDER BY (created_at, actor, action)
    """,
)

