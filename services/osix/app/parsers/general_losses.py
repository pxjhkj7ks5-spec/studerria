from __future__ import annotations

import re
from datetime import date, datetime, timezone

from .base import ParseResult, ParsedMetric, clean_int, html_to_text


GENERAL_METRIC_PATTERNS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("personnel", "Personnel", (r"особового складу", r"військовослужбовц", r"personnel")),
    ("tanks", "Tanks", (r"танк", r"tanks?")),
    ("armored_vehicles", "Armored vehicles", (r"бойов[а-яіїєґ]+ броньован[а-яіїєґ]+ машин", r"armou?red")),
    ("artillery_systems", "Artillery systems", (r"артилерійськ[а-яіїєґ]+ систем", r"artillery")),
    ("mlrs", "MLRS", (r"рсзв", r"mlrs")),
    ("air_defense_systems", "Air defense systems", (r"засоб[а-яіїєґ]+ ппо", r"air defense")),
    ("aircraft", "Aircraft", (r"літак", r"aircraft")),
    ("helicopters", "Helicopters", (r"гелікоптер", r"helicopters?")),
    ("uav", "UAV", (r"бпла", r"uav", r"безпілот")),
    ("cruise_missiles", "Cruise missiles", (r"крилатих ракет", r"cruise missiles?")),
    ("ships_boats", "Ships and boats", (r"корабл", r"катер", r"ships?")),
    ("submarines", "Submarines", (r"підводн", r"submarines?")),
    ("vehicles_fuel_tanks", "Vehicles and fuel tanks", (r"автомобільної техніки", r"автоцистерн", r"vehicles?")),
    ("special_equipment", "Special equipment", (r"спеціальн[а-яіїєґ]+ технік", r"special equipment")),
)

DATE_PATTERNS = (
    ("dmy", re.compile(r"(\d{1,2})[./-](\d{1,2})[./-](20\d{2})")),
    ("ymd", re.compile(r"(20\d{2})[./-](\d{1,2})[./-](\d{1,2})")),
    ("dmy_short", re.compile(r"(?<!\d)(\d{1,2})[./-](\d{1,2})[./-](\d{2})(?!\d)")),
)


def parse_observed_date(text: str) -> date:
    candidates: list[tuple[int, date]] = []
    for kind, pattern in DATE_PATTERNS:
        for match in pattern.finditer(text):
            parts = [int(part) for part in match.groups()]
            if kind == "ymd":
                parsed = date(parts[0], parts[1], parts[2])
            elif kind == "dmy_short":
                parsed = date(2000 + parts[2], parts[1], parts[0])
            else:
                parsed = date(parts[2], parts[1], parts[0])
            candidates.append((match.start(), parsed))
    if candidates:
        return sorted(candidates, key=lambda item: item[0])[-1][1]
    return datetime.now(timezone.utc).date()


def _line_value(line: str) -> tuple[int, int | None] | None:
    match = re.search(r"[‒–—:-]\s*(?:близько\s*)?(\d[\d\s\u00a0,]{0,})(?:\s*(?:\(\s*)?[+＋]\s*(\d[\d\s\u00a0,]*)\)?)?", line)
    if not match:
        return None
    value = clean_int(match.group(1))
    delta = clean_int(match.group(2)) if match.group(2) else None
    return value, delta


def parse_general_losses(source_id: str, dataset: str, html: str) -> ParseResult:
    text = html_to_text(html)
    observed_date = parse_observed_date(text)
    lines = [line.strip().lower() for line in text.splitlines() if line.strip()]
    metrics: list[ParsedMetric] = []

    for metric, label, needles in GENERAL_METRIC_PATTERNS:
        for line in lines:
            if not any(re.search(needle, line, flags=re.IGNORECASE) for needle in needles):
                continue
            parsed = _line_value(line)
            if parsed is None:
                continue
            value, delta = parsed
            metrics.append(
                ParsedMetric(
                    dataset=dataset,
                    metric=metric,
                    metric_label=label,
                    value=value,
                    daily_delta=delta,
                    observed_date=observed_date,
                    source_id=source_id,
                )
            )
            break

    return ParseResult(metrics=tuple(metrics), observed_date=observed_date)


def is_general_losses_article(article: dict) -> bool:
    slug = str(article.get("slug") or "").lower()
    title = str(article.get("title") or "").lower()
    content = str(article.get("content") or "").lower()
    has_losses_marker = "бойові втрати" in title or "bojovi-vtrati" in slug or "загальні бойові втрати" in content
    has_metrics_body = "загальні бойові втрати" in content and "особов" in content
    return has_losses_marker and has_metrics_body
