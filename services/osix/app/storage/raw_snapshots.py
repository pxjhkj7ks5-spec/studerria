from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass(frozen=True)
class StoredSnapshot:
    content_hash: str
    path: Path
    size_bytes: int


def content_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def store_snapshot(root: Path, source_id: str, fetched_at: datetime, content: bytes) -> StoredSnapshot:
    digest = content_hash(content)
    day_dir = root / source_id / fetched_at.strftime("%Y/%m/%d")
    day_dir.mkdir(parents=True, exist_ok=True)
    path = day_dir / f"{fetched_at.strftime('%H%M%S')}-{digest[:16]}.html"
    if not path.exists():
        path.write_bytes(content)
    return StoredSnapshot(content_hash=digest, path=path, size_bytes=len(content))


def cleanup_old_snapshots(root: Path, retention_days: int) -> int:
    if retention_days <= 0 or not root.exists():
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    removed = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        if modified >= cutoff:
            continue
        path.unlink(missing_ok=True)
        removed += 1
    for path in sorted((p for p in root.rglob("*") if p.is_dir()), reverse=True):
        try:
            path.rmdir()
        except OSError:
            pass
    return removed

