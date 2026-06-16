from __future__ import annotations


class TelegramSourceAdapter:
    """Future adapter boundary. Telegram ingestion is intentionally disabled in MVP."""

    async def poll(self) -> None:
        raise NotImplementedError("Telegram ingestion is not part of the OSIX MVP scope")

