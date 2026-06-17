from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from app.core.config import Settings, SourceDefinition
from app.db.schema import CLICKHOUSE_SCHEMA
from app.parsers.base import ParsedMetric

logger = logging.getLogger(__name__)


class ClickHouseStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._client: Any | None = None

    @property
    def client(self) -> Any:
        if self._client is None:
            import clickhouse_connect

            self._client = clickhouse_connect.get_client(
                host=self.settings.clickhouse_host,
                port=self.settings.clickhouse_port,
                username=self.settings.clickhouse_user,
                password=self.settings.clickhouse_password,
                database=self.settings.clickhouse_database,
            )
        return self._client

    def initialize(self) -> None:
        admin = self._admin_client()
        admin.command(f"CREATE DATABASE IF NOT EXISTS {self.settings.clickhouse_database}")
        for statement in CLICKHOUSE_SCHEMA:
            self.client.command(statement)

    def _admin_client(self) -> Any:
        import clickhouse_connect

        return clickhouse_connect.get_client(
            host=self.settings.clickhouse_host,
            port=self.settings.clickhouse_port,
            username=self.settings.clickhouse_user,
            password=self.settings.clickhouse_password,
        )

    def upsert_sources(self, sources: tuple[SourceDefinition, ...]) -> None:
        now = datetime.now(timezone.utc)
        rows = [
            [source.id, source.name, source.url, source.source_type, source.dataset, source.parser, int(source.enabled), now]
            for source in sources
        ]
        self.client.insert(
            "sources",
            rows,
            column_names=["id", "name", "url", "source_type", "dataset", "parser", "enabled", "updated_at"],
        )

    def retire_sources(self, source_ids: tuple[str, ...]) -> None:
        if not source_ids:
            return
        existing = {source.id: source for source in self.list_source_definitions()}
        retired = [
            SourceDefinition(
                id=source.id,
                name=source.name,
                url=source.url,
                source_type=source.source_type,
                dataset=source.dataset,
                parser=source.parser,
                enabled=False,
            )
            for source_id in source_ids
            if (source := existing.get(source_id)) is not None
        ]
        if retired:
            self.upsert_sources(tuple(retired))

    def list_sources(self) -> list[dict[str, Any]]:
        result = self.client.query(
            """
            SELECT id, name, url, source_type, dataset, parser, enabled
            FROM sources
            FINAL
            ORDER BY id
            """
        )
        return [dict(zip(result.column_names, row, strict=False)) for row in result.result_rows]

    def list_source_definitions(self) -> tuple[SourceDefinition, ...]:
        return tuple(
            SourceDefinition(
                id=str(row["id"]),
                name=str(row["name"]),
                url=str(row["url"]),
                source_type=str(row["source_type"]),
                dataset=str(row["dataset"]),
                parser=str(row["parser"]),
                enabled=bool(row["enabled"]),
            )
            for row in self.list_sources()
        )

    def update_source_config(self, source_id: str, url: str | None, enabled: bool | None) -> SourceDefinition | None:
        sources = {source.id: source for source in self.list_source_definitions()}
        current = sources.get(source_id)
        if current is None:
            return None
        updated = SourceDefinition(
            id=current.id,
            name=current.name,
            url=url or current.url,
            source_type=current.source_type,
            dataset=current.dataset,
            parser=current.parser,
            enabled=current.enabled if enabled is None else enabled,
        )
        self.upsert_sources((updated,))
        return updated

    def last_snapshot_hash(self, source_id: str) -> str | None:
        result = self.client.query(
            """
            SELECT content_hash
            FROM raw_snapshots
            WHERE source_id = {source_id:String}
            ORDER BY fetched_at DESC
            LIMIT 1
            """,
            parameters={"source_id": source_id},
        )
        if not result.result_rows:
            return None
        return str(result.result_rows[0][0])

    def insert_snapshot(self, source_id: str, url: str, fetched_at: datetime, content_hash: str, path: str, size: int, status_code: int) -> None:
        self.client.insert(
            "raw_snapshots",
            [[source_id, url, fetched_at, content_hash, path, size, status_code]],
            column_names=["source_id", "url", "fetched_at", "content_hash", "storage_path", "size_bytes", "status_code"],
        )

    def insert_metrics(self, metrics: tuple[ParsedMetric, ...], content_hash: str) -> None:
        now = datetime.now(timezone.utc)
        rows = [
            [
                metric.dataset,
                metric.metric,
                metric.metric_label,
                metric.source_id,
                metric.observed_date,
                now,
                metric.value,
                metric.daily_delta,
                content_hash,
            ]
            for metric in metrics
        ]
        if not rows:
            return
        self.client.insert(
            "metrics_time_series",
            rows,
            column_names=[
                "dataset",
                "metric",
                "metric_label",
                "source_id",
                "observed_date",
                "timestamp",
                "value",
                "daily_delta",
                "content_hash",
            ],
        )

    def insert_parser_error(self, source_id: str, url: str, content_hash: str, error_type: str, message: str) -> None:
        self.client.insert(
            "parser_errors",
            [[source_id, url, datetime.now(timezone.utc), content_hash, error_type, message[:1000]]],
            column_names=["source_id", "url", "occurred_at", "content_hash", "error_type", "message"],
        )

    def update_health(self, source_id: str, status: str, status_code: int, latency_ms: int, message: str = "") -> None:
        now = datetime.now(timezone.utc)
        last_success = now if status == "ok" else None
        self.client.insert(
            "source_health",
            [[source_id, now, status, status_code, latency_ms, last_success, message[:1000]]],
            column_names=["source_id", "checked_at", "status", "status_code", "latency_ms", "last_success_at", "message"],
        )

    def insert_audit(self, actor: str, role: str, action: str, target: str, metadata: str = "{}") -> None:
        self.client.insert(
            "admin_audit_log",
            [[actor, role, action, target, datetime.now(timezone.utc), metadata[:4000]]],
            column_names=["actor", "role", "action", "target", "created_at", "metadata"],
        )

    def latest_metrics(self, dataset: str | None = None) -> list[dict[str, Any]]:
        where = "WHERE dataset = {dataset:String}" if dataset else ""
        params = {"dataset": dataset} if dataset else None
        result = self.client.query(
            f"""
            SELECT dataset, metric, metric_label, source_id, observed_date, value, daily_delta, timestamp
            FROM (
                SELECT dataset, metric, metric_label, source_id, observed_date, value, daily_delta, timestamp
                FROM metrics_time_series
                {where}
                ORDER BY observed_date DESC, timestamp DESC
                LIMIT 1 BY dataset, metric
            )
            ORDER BY metric
            """,
            parameters=params,
        )
        return [dict(zip(result.column_names, row, strict=False)) for row in result.result_rows]

    def metric_series(self, metric: str, dataset: str, start: str | None, end: str | None) -> list[dict[str, Any]]:
        conditions = ["dataset = {dataset:String}", "metric = {metric:String}"]
        params: dict[str, Any] = {"dataset": dataset, "metric": metric}
        if start:
            conditions.append("observed_date >= {start:Date}")
            params["start"] = start
        if end:
            conditions.append("observed_date <= {end:Date}")
            params["end"] = end
        result = self.client.query(
            f"""
            SELECT
                observed_date,
                argMax(source_id, timestamp) AS source_id,
                argMax(value, timestamp) AS value,
                argMax(daily_delta, timestamp) AS daily_delta
            FROM metrics_time_series
            WHERE {" AND ".join(conditions)}
            GROUP BY observed_date
            ORDER BY observed_date ASC
            """,
            parameters=params,
        )
        return [dict(zip(result.column_names, row, strict=False)) for row in result.result_rows]

    def health(self) -> list[dict[str, Any]]:
        active_source_ids = {str(source["id"]) for source in self.list_sources() if bool(source["enabled"])}
        result = self.client.query(
            """
            SELECT source_id, checked_at, status, status_code, latency_ms, last_success_at, message
            FROM source_health
            FINAL
            ORDER BY source_id
            """
        )
        return [
            dict(zip(result.column_names, row, strict=False))
            for row in result.result_rows
            if str(row[0]) in active_source_ids
        ]

    def parser_errors(self) -> list[dict[str, Any]]:
        active_source_ids = {str(source["id"]) for source in self.list_sources() if bool(source["enabled"])}
        result = self.client.query(
            """
            SELECT source_id, url, occurred_at, error_type, message
            FROM parser_errors
            ORDER BY occurred_at DESC
            LIMIT 100
            """
        )
        return [
            dict(zip(result.column_names, row, strict=False))
            for row in result.result_rows
            if str(row[0]) in active_source_ids
        ]
