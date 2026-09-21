#!/usr/bin/env python3
"""Rotate only successful backups registered by the update helper."""
import argparse
import fcntl
import re
from pathlib import Path


NAME = re.compile(r"(postgres|obriy-postgres|shieldline-postgres|osint-postgres|charredmap-data|naradadruk-data|ykg-data|slashtg-data|osix-data|shieldline-legacy-data)-\d{8}T\d{6}Z\.(dump|tgz)")


def rotate(backup, keep):
    if keep < 1:
        raise ValueError("BACKUP_KEEP_COUNT must be a positive integer")
    match = NAME.fullmatch(backup.name)
    if not match or backup.is_symlink() or not backup.is_file() or backup.stat().st_size == 0:
        raise ValueError("Refusing to register an empty or invalid backup")
    with (backup.parent / ".rotation.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        marker = backup.with_name(backup.name + ".complete")
        if marker.is_symlink():
            raise ValueError("Invalid backup completion marker")
        marker.touch()
        candidates = []
        for path in backup.parent.iterdir():
            candidate = NAME.fullmatch(path.name)
            complete = path.with_name(path.name + ".complete")
            if (candidate and candidate.groups() == match.groups()
                    and path.is_file() and not path.is_symlink()
                    and path.stat().st_size > 0
                    and complete.is_file() and not complete.is_symlink()):
                candidates.append(path)
        for path in sorted(candidates, reverse=True)[keep:]:
            # Pinned copies and the backup just created are never removed.
            if path == backup or path.with_name(path.name + ".keep").exists():
                continue
            path.unlink()
            path.with_name(path.name + ".complete").unlink()
            print(f"Removed old managed backup: {path.name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path)
    parser.add_argument("--keep", type=int, default=2)
    args = parser.parse_args()
    rotate(args.backup, args.keep)
