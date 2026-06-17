from __future__ import annotations

import asyncio
import logging

from app.core.config import Settings, SourceDefinition
from app.db.clickhouse import ClickHouseStore
from app.ingestors.http import HttpSourceIngestor, IngestResult
from app.storage.raw_snapshots import cleanup_old_snapshots

logger = logging.getLogger(__name__)


class Poller:
    def __init__(self, settings: Settings, store: ClickHouseStore) -> None:
        self.settings = settings
        self.store = store
        self.ingestor = HttpSourceIngestor(settings, store)
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            await self._task

    async def run_once(self, sources: tuple[SourceDefinition, ...] | None = None) -> list[IngestResult]:
        cleanup_old_snapshots(self.settings.raw_snapshot_dir, self.settings.raw_retention_days)
        active_sources = sources or self._configured_sources()
        results: list[IngestResult] = []
        for source in active_sources:
            results.append(await self.ingestor.ingest_source(source))
        return results

    async def backfill_mod_losses(self) -> IngestResult:
        cleanup_old_snapshots(self.settings.raw_snapshot_dir, self.settings.raw_retention_days)
        source = next((item for item in self._configured_sources() if item.parser == "mod_listing"), None)
        if source is None:
            return IngestResult("mod-general-losses-listing", "skipped", False, 0, "MOD listing source is disabled")
        return await self.ingestor.backfill_mod_losses(source)

    def _configured_sources(self) -> tuple[SourceDefinition, ...]:
        try:
            sources = self.store.list_source_definitions()
        except Exception:
            logger.exception("failed to load configured sources")
            sources = self.settings.default_sources()
        return tuple(source for source in sources if source.enabled)

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self.run_once()
            except Exception:
                logger.exception("poller iteration failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.settings.poll_interval_seconds)
            except TimeoutError:
                continue
