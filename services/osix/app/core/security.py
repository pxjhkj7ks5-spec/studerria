from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SessionClaims:
    subject: str
    role: str
    expires_at: int


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations_raw, salt, digest = stored_hash.split("$", 3)
        iterations = int(iterations_raw)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256" or iterations < 100000:
        return False
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
    return hmac.compare_digest(derived.hex(), digest)


def create_session_token(subject: str, role: str, secret: str, ttl_seconds: int) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    encoded_payload = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(secret.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded_payload}.{_b64encode(signature)}"


def parse_session_token(token: str, secret: str) -> SessionClaims | None:
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        expected = hmac.new(secret.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256).digest()
        signature = _b64decode(encoded_signature)
        if not hmac.compare_digest(expected, signature):
            return None
        payload = json.loads(_b64decode(encoded_payload).decode("utf-8"))
        expires_at = int(payload["exp"])
        if expires_at < int(time.time()):
            return None
        role = str(payload.get("role", "viewer"))
        if role not in {"viewer", "admin"}:
            return None
        return SessionClaims(subject=str(payload["sub"]), role=role, expires_at=expires_at)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None

