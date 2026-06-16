from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urljoin

import httpx

from app.core.config import Settings, SourceDefinition, is_allowlisted_url
from app.db.clickhouse import ClickHouseStore
from app.parsers.general_losses import parse_general_losses
from app.parsers.sbs import parse_sbs
from app.storage.raw_snapshots import content_hash, store_snapshot

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngestResult:
    source_id: str
    status: str
    changed: bool
    metrics_count: int
    message: str = ""


class HttpSourceIngestor:
    def __init__(self, settings: Settings, store: ClickHouseStore) -> None:
        self.settings = settings
        self.store = store

    async def ingest_source(self, source: SourceDefinition) -> IngestResult:
        if source.parser == "mod_listing":
            return await self._ingest_mod_listing(source)
        return await self._ingest_page(source)

    async def _ingest_mod_listing(self, source: SourceDefinition) -> IngestResult:
        listing = await self._fetch(source.url)
        article_urls = self._extract_mod_articles(listing.text, source.url)
        if not article_urls:
            self.store.insert_parser_error(source.id, source.url, content_hash(listing.content), "no_articles", "No allowed MOD article links found")
            return IngestResult(source.id, "error", False, 0, "No allowed MOD article links found")
        latest_url = article_urls[0]
        article_source = SourceDefinition(
            id="mod-general-losses",
            name="Ministry of Defence enemy losses article",
            url=latest_url,
            source_type="website",
            dataset=source.dataset,
            parser="general_losses",
        )
        return await self._ingest_page(article_source)

    async def _ingest_page(self, source: SourceDefinition) -> IngestResult:
        if not is_allowlisted_url(source.url, self.settings.allowlisted_prefixes):
            return IngestResult(source.id, "blocked", False, 0, "URL is not allowlisted")

        started = time.monotonic()
        try:
            response = await self._fetch(source.url)
            latency_ms = int((time.monotonic() - started) * 1000)
            fetched_at = datetime.now(timezone.utc)
            digest = content_hash(response.content)
            self.store.update_health(source.id, "ok", response.status_code, latency_ms)
            if self.store.last_snapshot_hash(source.id) == digest:
                return IngestResult(source.id, "ok", False, 0, "Snapshot unchanged")

            snapshot = store_snapshot(self.settings.raw_snapshot_dir, source.id, fetched_at, response.content)
            self.store.insert_snapshot(source.id, source.url, fetched_at, snapshot.content_hash, str(snapshot.path), snapshot.size_bytes, response.status_code)
            parsed = self._parse(source, response.text)
            if not parsed.metrics:
                self.store.insert_parser_error(source.id, source.url, digest, "empty_parse", "No metrics parsed from source")
                return IngestResult(source.id, "error", True, 0, "No metrics parsed")
            self.store.insert_metrics(parsed.metrics, digest)
            return IngestResult(source.id, "ok", True, len(parsed.metrics))
        except Exception as exc:
            latency_ms = int((time.monotonic() - started) * 1000)
            logger.exception("source ingest failed")
            self.store.update_health(source.id, "error", 0, latency_ms, str(exc))
            return IngestResult(source.id, "error", False, 0, str(exc))

    async def _fetch(self, url: str) -> httpx.Response:
        if not is_allowlisted_url(url, self.settings.allowlisted_prefixes):
            raise ValueError("URL is not allowlisted")
        headers = {"User-Agent": "Studerria-OSIX/0.1 (+https://studerria.com/osix)"}
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds, follow_redirects=True, headers=headers) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response

    def _parse(self, source: SourceDefinition, html: str):
        if source.parser == "general_losses":
            return parse_general_losses(source.id, source.dataset, html)
        if source.parser == "sbs":
            return parse_sbs(source.id, source.dataset, html)
        raise ValueError(f"Unsupported parser: {source.parser}")

    def _extract_mod_articles(self, html: str, base_url: str) -> list[str]:
        links = re.findall(r'href=["\']([^"\']+)["\']', html, flags=re.IGNORECASE)
        full_links = [urljoin(base_url, link) for link in links]
        allowed = [
            link
            for link in full_links
            if link.startswith(self.settings.source_mod_article_prefix)
            and is_allowlisted_url(link, self.settings.allowlisted_prefixes)
        ]
        return list(dict.fromkeys(allowed))
