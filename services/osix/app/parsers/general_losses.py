from __future__ import annotations

import re
from datetime import date, datetime, timezone

from .base import ParseResult, ParsedMetric, clean_int, html_to_text


GENERAL_METRIC_PATTERNS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("personnel", "Personnel", (r"особового складу", r"personnel")),
    ("tanks", "Tanks", (r"танк", r"tanks?")),
    ("armored_vehicles", "Armored vehicles", (r"бойових броньованих машин", r"armou?red")),
    ("artillery_systems", "Artillery systems", (r"артилерійських систем", r"artillery")),
    ("mlrs", "MLRS", (r"рсзв", r"mlrs")),
    ("air_defense_systems", "Air defense systems", (r"засобів ппо", r"air defense")),
    ("aircraft", "Aircraft", (r"літак", r"aircraft")),
    ("helicopters", "Helicopters", (r"гелікоптер", r"helicopters?")),
    ("uav", "UAV", (r"бпла", r"uav", r"безпілот")),
    ("cruise_missiles", "Cruise missiles", (r"крилатих ракет", r"cruise missiles?")),
    ("ships_boats", "Ships and boats", (r"корабл", r"катер", r"ships?")),
    ("submarines", "Submarines", (r"підводн", r"submarines?")),
    ("vehicles_fuel_tanks", "Vehicles and fuel tanks", (r"автомобільної техніки", r"автоцистерн", r"vehicles?")),
    ("special_equipment", "Special equipment", (r"спеціальної техніки", r"special equipment")),
)

DATE_PATTERNS = (
    re.compile(r"(\d{1,2})[./-](\d{1,2})[./-](20\d{2})"),
    re.compile(r"(20\d{2})[./-](\d{1,2})[./-](\d{1,2})"),
)


def parse_observed_date(text: str) -> date:
    for pattern in DATE_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        parts = [int(part) for part in match.groups()]
        if len(str(parts[0])) == 4:
            return date(parts[0], parts[1], parts[2])
        return date(parts[2], parts[1], parts[0])
    return datetime.now(timezone.utc).date()


def _line_value(line: str) -> tuple[int, int | None] | None:
    match = re.search(r"(\d[\d\s\u00a0,]{1,})\s*(?:[+＋]\s*(\d[\d\s\u00a0,]*))?", line)
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

