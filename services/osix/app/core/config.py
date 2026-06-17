from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


DEFAULT_GENERAL_SOURCE_URL = "https://www.zsu.gov.ua/oriientovni-vtraty-protyvnyka"
DEFAULT_MOD_LISTING_URL = "https://mod.gov.ua/news/tag-vidsich-agresoru"
DEFAULT_MOD_LOOKUP_URL = "https://mod.gov.ua/lookup/search?search_type=dfs_query_then_fetch"
DEFAULT_MOD_ARTICLE_PREFIX = "https://mod.gov.ua/news/bojovi-vtrati-voroga-na-"
DEFAULT_SBS_SOURCE_URL = "https://sbs-group.army/"
DEFAULT_SBS_API_URL = "https://sbs-group.army/api/public"


@dataclass(frozen=True)
class SourceDefinition:
    id: str
    name: str
    url: str
    source_type: str
    dataset: str
    parser: str
    enabled: bool = True


@dataclass(frozen=True)
class Settings:
    base_path: str
    public_url: str
    clickhouse_host: str
    clickhouse_port: int
    clickhouse_user: str
    clickhouse_password: str
    clickhouse_database: str
    raw_snapshot_dir: Path
    raw_retention_days: int
    poll_interval_seconds: int
    request_timeout_seconds: float
    admin_username: str
    admin_password_hash: str
    jwt_secret: str
    admin_cookie_name: str
    admin_cookie_secure: bool
    admin_session_ttl_seconds: int
    dashboard_auth_required: bool
    source_general_url: str
    source_mod_listing_url: str
    source_mod_lookup_url: str
    source_mod_article_prefix: str
    source_sbs_url: str
    source_sbs_api_url: str
    mod_backfill_page_size: int
    mod_backfill_max_pages: int

    @property
    def admin_enabled(self) -> bool:
        return bool(self.admin_username and self.admin_password_hash and self.jwt_secret)

    @property
    def allowlisted_prefixes(self) -> tuple[str, ...]:
        sbs_api_prefix = f"{self.source_sbs_api_url.rstrip('/')}/*"
        return (
            self.source_general_url,
            self.source_mod_listing_url,
            self.source_mod_lookup_url,
            self.source_mod_article_prefix,
            self.source_sbs_url,
            self.source_sbs_api_url,
            sbs_api_prefix,
        )

    def default_sources(self) -> tuple[SourceDefinition, ...]:
        return (
            SourceDefinition(
                id="mod-general-losses-listing",
                name="Ministry of Defence enemy losses listing",
                url=self.source_mod_listing_url,
                source_type="website_listing",
                dataset="general_losses",
                parser="mod_listing",
            ),
            SourceDefinition(
                id="sbs-pidrahuyka",
                name="SBS Pidrahuyka",
                url=self.source_sbs_url,
                source_type="website",
                dataset="sbs_stats",
                parser="sbs",
            ),
        )


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _bool_env(name: str, default: bool = False) -> bool:
    value = _env(name, "true" if default else "false").lower()
    return value in {"1", "true", "yes", "on"}


def load_settings() -> Settings:
    base_path = _env("OSIX_BASE_PATH", "/osix") or "/osix"
    if not base_path.startswith("/"):
        base_path = f"/{base_path}"
    return Settings(
        base_path=base_path.rstrip("/") or "/osix",
        public_url=_env("OSIX_PUBLIC_URL", "https://studerria.com/osix"),
        clickhouse_host=_env("OSIX_CLICKHOUSE_HOST", "clickhouse"),
        clickhouse_port=int(_env("OSIX_CLICKHOUSE_PORT", "8123")),
        clickhouse_user=_env("OSIX_CLICKHOUSE_USER", "default"),
        clickhouse_password=_env("OSIX_CLICKHOUSE_PASSWORD", ""),
        clickhouse_database=_env("OSIX_CLICKHOUSE_DATABASE", "osix"),
        raw_snapshot_dir=Path(_env("OSIX_RAW_SNAPSHOT_DIR", "/data/raw-snapshots")),
        raw_retention_days=int(_env("OSIX_RAW_RETENTION_DAYS", "90")),
        poll_interval_seconds=int(_env("OSIX_POLL_INTERVAL_SECONDS", "3600")),
        request_timeout_seconds=float(_env("OSIX_REQUEST_TIMEOUT_SECONDS", "20")),
        admin_username=_env("OSIX_ADMIN_USERNAME", ""),
        admin_password_hash=_env("OSIX_ADMIN_PASSWORD_HASH", ""),
        jwt_secret=_env("OSIX_JWT_SECRET", ""),
        admin_cookie_name=_env("OSIX_ADMIN_COOKIE_NAME", "osix_admin"),
        admin_cookie_secure=_bool_env("OSIX_ADMIN_COOKIE_SECURE", True),
        admin_session_ttl_seconds=int(_env("OSIX_ADMIN_SESSION_TTL_SECONDS", "28800")),
        dashboard_auth_required=_bool_env("OSIX_DASHBOARD_AUTH_REQUIRED", True),
        source_general_url=_env("OSIX_SOURCE_GENERAL_URL", DEFAULT_GENERAL_SOURCE_URL),
        source_mod_listing_url=_env("OSIX_SOURCE_MOD_LISTING_URL", DEFAULT_MOD_LISTING_URL),
        source_mod_lookup_url=_env("OSIX_SOURCE_MOD_LOOKUP_URL", DEFAULT_MOD_LOOKUP_URL),
        source_mod_article_prefix=_env("OSIX_SOURCE_MOD_ARTICLE_PREFIX", DEFAULT_MOD_ARTICLE_PREFIX),
        source_sbs_url=_env("OSIX_SOURCE_SBS_URL", DEFAULT_SBS_SOURCE_URL),
        source_sbs_api_url=_env("OSIX_SOURCE_SBS_API_URL", DEFAULT_SBS_API_URL),
        mod_backfill_page_size=int(_env("OSIX_MOD_BACKFILL_PAGE_SIZE", "50")),
        mod_backfill_max_pages=int(_env("OSIX_MOD_BACKFILL_MAX_PAGES", "100")),
    )


def is_allowlisted_url(url: str, allowed_prefixes: Iterable[str]) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        return False
    normalized = url.rstrip("/")
    for prefix in allowed_prefixes:
        wildcard = prefix.endswith("*")
        clean_prefix = prefix.rstrip("*").rstrip("/")
        if normalized == clean_prefix:
            return True
        if wildcard and normalized.startswith(clean_prefix):
            return True
        if clean_prefix.endswith("/bojovi-vtrati-voroga-na-") and normalized.startswith(clean_prefix):
            return True
    return False
