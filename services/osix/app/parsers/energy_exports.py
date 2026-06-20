from __future__ import annotations

from collections import defaultdict
from datetime import date
from typing import Any

from .base import ParseResult, ParsedMetric


COMMODITY_METRICS = {
    "crude_oil": ("crude_oil_tonnes", "Crude oil exports, tonnes/day"),
    "oil_products": ("oil_products_tonnes", "Oil products exports, tonnes/day"),
    "pipeline_oil": ("pipeline_oil_tonnes", "Pipeline oil exports, tonnes/day"),
}

REGION_METRICS = {
    "China": ("oil_to_china_tonnes", "Oil exports to China, tonnes/day"),
    "India": ("oil_to_india_tonnes", "Oil exports to India, tonnes/day"),
    "EU": ("oil_to_eu_tonnes", "Oil exports to EU, tonnes/day"),
    "Türkiye": ("oil_to_turkiye_tonnes", "Oil exports to Türkiye, tonnes/day"),
    "Others": ("oil_to_other_tonnes", "Oil exports to other destinations, tonnes/day"),
}


def parse_crea_counter(source_id: str, dataset: str, payload: Any) -> ParseResult:
    rows = payload.get("data", []) if isinstance(payload, dict) else []
    if not isinstance(rows, list):
        return ParseResult(metrics=(), observed_date=None)

    values_by_date: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for row in rows:
        if not isinstance(row, dict):
            continue
        raw_date = str(row.get("date") or "")[:10]
        commodity = str(row.get("commodity") or "")
        region = str(row.get("destination_region") or "")
        if not raw_date or commodity not in COMMODITY_METRICS or region == "total":
            continue
        try:
            tonne = float(row.get("value_tonne") or 0)
            eur = float(row.get("value_eur") or 0)
            date.fromisoformat(raw_date)
        except (TypeError, ValueError):
            continue

        commodity_metric, _ = COMMODITY_METRICS[commodity]
        values_by_date[raw_date][commodity_metric] += tonne
        values_by_date[raw_date]["oil_total_tonnes"] += tonne
        values_by_date[raw_date]["oil_export_revenue_eur"] += eur
        if region in REGION_METRICS:
            region_metric, _ = REGION_METRICS[region]
            values_by_date[raw_date][region_metric] += tonne

    labels = dict(COMMODITY_METRICS.values())
    labels.update(REGION_METRICS.values())
    labels["oil_total_tonnes"] = "Total oil exports, tonnes/day"
    labels["oil_export_revenue_eur"] = "Oil export revenue, EUR/day"
    previous_values: dict[str, int] = {}
    metrics: list[ParsedMetric] = []
    for raw_date in sorted(values_by_date):
        observed_date = date.fromisoformat(raw_date)
        for metric, raw_value in values_by_date[raw_date].items():
            value = int(round(raw_value))
            previous = previous_values.get(metric)
            metrics.append(
                ParsedMetric(
                    dataset=dataset,
                    metric=metric,
                    metric_label=labels[metric],
                    value=value,
                    daily_delta=value - previous if previous is not None else None,
                    observed_date=observed_date,
                    source_id=source_id,
                )
            )
            previous_values[metric] = value

    latest = date.fromisoformat(max(values_by_date)) if values_by_date else None
    return ParseResult(metrics=tuple(metrics), observed_date=latest)
