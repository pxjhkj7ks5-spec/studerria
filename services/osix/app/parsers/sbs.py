from __future__ import annotations

import re
from datetime import datetime, timezone

from .base import ParseResult, ParsedMetric, clean_int, html_to_text


SBS_METRIC_PATTERNS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("personnel", "Personnel", (r"особового складу", r"personnel")),
    ("tanks", "Tanks", (r"танк", r"tanks?")),
    ("armored_vehicles", "Armored vehicles", (r"броньован", r"armou?red")),
    ("artillery_systems", "Artillery systems", (r"артилер", r"artillery")),
    ("air_defense_systems", "Air defense systems", (r"ппо", r"air defense")),
    ("uav", "UAV", (r"бпла", r"uav")),
    ("vehicles", "Vehicles", (r"автомоб", r"vehicles?")),
)


def parse_sbs(source_id: str, dataset: str, html: str) -> ParseResult:
    text = html_to_text(html)
    observed_date = datetime.now(timezone.utc).date()
    lines = [line.strip().lower() for line in text.splitlines() if line.strip()]
    metrics: list[ParsedMetric] = []

    for metric, label, needles in SBS_METRIC_PATTERNS:
        for line in lines:
            if not any(re.search(needle, line, flags=re.IGNORECASE) for needle in needles):
                continue
            match = re.search(r"(\d[\d\s\u00a0,]{1,})", line)
            if not match:
                continue
            metrics.append(
                ParsedMetric(
                    dataset=dataset,
                    metric=metric,
                    metric_label=label,
                    value=clean_int(match.group(1)),
                    daily_delta=None,
                    observed_date=observed_date,
                    source_id=source_id,
                )
            )
            break

    return ParseResult(metrics=tuple(metrics), observed_date=observed_date)

