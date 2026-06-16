from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from html.parser import HTMLParser


@dataclass(frozen=True)
class ParsedMetric:
    dataset: str
    metric: str
    metric_label: str
    value: int
    daily_delta: int | None
    observed_date: date
    source_id: str


@dataclass(frozen=True)
class ParseResult:
    metrics: tuple[ParsedMetric, ...]
    observed_date: date | None


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if text:
            self.parts.append(text)

    def text(self) -> str:
        return "\n".join(self.parts)


def html_to_text(html: str) -> str:
    parser = TextExtractor()
    parser.feed(html)
    return parser.text()


def clean_int(value: str) -> int:
    return int(value.replace(" ", "").replace("\u00a0", "").replace(",", ""))

