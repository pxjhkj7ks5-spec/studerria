from __future__ import annotations

import json
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


MOD_LOSSES_QUERY = {
    "sort": [{"publishedAt": {"order": "desc"}}, {"id": {"order": "desc"}}],
    "query": {
        "bool": {
            "must": [
                {"term": {"locale": "uk"}},
                {
                    "terms_set": {
                        "tags": {
                            "terms": ["Відсіч агресору"],
                            "minimum_should_match_script": {"source": "1"},
                        }
                    }
                },
                {"term": {"type": "news"}},
            ]
        }
    },
    "_source": ["title", "slug", "publishedAt", "locale", "type", "id", "content", "tags"],
    "from": 0,
    "size": 20,
}


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
        if not is_allowlisted_url(self.settings.source_mod_lookup_url, self.settings.allowlisted_prefixes):
            return IngestResult(source.id, "blocked", False, 0, "MOD lookup URL is not allowlisted")

        started = time.monotonic()
        try:
            response = await self._fetch_mod_lookup()
            latency_ms = int((time.monotonic() - started) * 1000)
            fetched_at = datetime.now(timezone.utc)
            payload = response.json()
            article = self._select_mod_article(payload)
            digest = content_hash(response.content)
            self.store.update_health(source.id, "ok", response.status_code, latency_ms)
            previous_hash = self.store.last_snapshot_hash(source.id)

            if article is None:
                self.store.insert_parser_error(source.id, source.url, digest, "no_articles", "No allowed MOD article records found")
                return IngestResult(source.id, "error", True, 0, "No allowed MOD article records found")

            slug = str(article.get("slug") or "")
            article_url = f"https://mod.gov.ua/news/{slug}"
            if not is_allowlisted_url(article_url, self.settings.allowlisted_prefixes):
                self.store.insert_parser_error(source.id, article_url, digest, "blocked_article", "MOD article URL is not allowlisted")
                return IngestResult(source.id, "blocked", True, 0, "MOD article URL is not allowlisted")
            if previous_hash == digest:
                return IngestResult(source.id, "ok", False, 0, "Snapshot unchanged")

            snapshot = store_snapshot(self.settings.raw_snapshot_dir, source.id, fetched_at, response.content)
            self.store.insert_snapshot(source.id, self.settings.source_mod_lookup_url, fetched_at, snapshot.content_hash, str(snapshot.path), snapshot.size_bytes, response.status_code)

            html = f"<h1>{article.get('title') or ''}</h1>{article.get('content') or ''}"
            parsed = parse_general_losses("mod-general-losses", source.dataset, html)
            if not parsed.metrics:
                self.store.insert_parser_error(source.id, article_url, digest, "empty_parse", "No metrics parsed from MOD article")
                return IngestResult(source.id, "error", True, 0, "No metrics parsed")
            self.store.insert_metrics(parsed.metrics, digest)
            return IngestResult(source.id, "ok", True, len(parsed.metrics))
        except httpx.HTTPStatusError as exc:
            latency_ms = int((time.monotonic() - started) * 1000)
            message = f"HTTP {exc.response.status_code} while fetching MOD lookup"
            self.store.update_health(source.id, "error", exc.response.status_code, latency_ms, message)
            self.store.insert_parser_error(source.id, self.settings.source_mod_lookup_url, "", "http_error", message)
            return IngestResult(source.id, "error", False, 0, message)
        except Exception as exc:
            latency_ms = int((time.monotonic() - started) * 1000)
            logger.exception("MOD source ingest failed")
            self.store.update_health(source.id, "error", 0, latency_ms, str(exc))
            return IngestResult(source.id, "error", False, 0, str(exc))

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
        except httpx.HTTPStatusError as exc:
            latency_ms = int((time.monotonic() - started) * 1000)
            message = f"HTTP {exc.response.status_code} while fetching source"
            self.store.update_health(source.id, "error", exc.response.status_code, latency_ms, message)
            self.store.insert_parser_error(source.id, source.url, "", "http_error", message)
            return IngestResult(source.id, "error", False, 0, message)
        except Exception as exc:
            latency_ms = int((time.monotonic() - started) * 1000)
            logger.exception("source ingest failed")
            self.store.update_health(source.id, "error", 0, latency_ms, str(exc))
            return IngestResult(source.id, "error", False, 0, str(exc))

    async def _fetch(self, url: str) -> httpx.Response:
        if not is_allowlisted_url(url, self.settings.allowlisted_prefixes):
            raise ValueError("URL is not allowlisted")
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; Studerria-OSIX/0.1; +https://studerria.com/osix)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "uk-UA,uk;q=0.9,en;q=0.5",
            "Cache-Control": "no-cache",
        }
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds, follow_redirects=True, headers=headers) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response

    async def _fetch_mod_lookup(self) -> httpx.Response:
        if not is_allowlisted_url(self.settings.source_mod_lookup_url, self.settings.allowlisted_prefixes):
            raise ValueError("MOD lookup URL is not allowlisted")
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; Studerria-OSIX/0.1; +https://studerria.com/osix)",
            "Accept": "application/json,text/plain,*/*",
            "Accept-Language": "uk-UA,uk;q=0.9,en;q=0.5",
            "Content-Type": "application/json",
            "Origin": "https://mod.gov.ua",
            "Referer": self.settings.source_mod_listing_url,
            "Cache-Control": "no-cache",
        }
        body = json.dumps(MOD_LOSSES_QUERY, ensure_ascii=False).encode("utf-8")
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds, follow_redirects=True, headers=headers) as client:
            response = await client.post(self.settings.source_mod_lookup_url, content=body)
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

    def _select_mod_article(self, payload: dict) -> dict | None:
        hits = payload.get("hits", {}).get("hits", [])
        for hit in hits:
            article = hit.get("_source", {}) if isinstance(hit, dict) else {}
            slug = str(article.get("slug") or "")
            title = str(article.get("title") or "").lower()
            if slug.startswith("bojovi-vtrati-voroga-na-") or title.startswith("бойові втрати ворога"):
                return article
        return None
