from __future__ import annotations

from datetime import date
from typing import Any

from .base import ParseResult, ParsedMetric


EQUIPMENT_FIELDS: dict[str, tuple[str, str]] = {
    "aircraft": ("aircraft", "Aircraft"),
    "helicopter": ("helicopters", "Helicopters"),
    "tank": ("tanks", "Tanks"),
    "APC": ("armored_vehicles", "Armored vehicles"),
    "field artillery": ("artillery_systems", "Artillery systems"),
    "MRL": ("mlrs", "MLRS"),
    "anti-aircraft warfare": ("air_defense_systems", "Air defense systems"),
    "drone": ("uav", "UAV"),
    "cruise missiles": ("cruise_missiles", "Cruise missiles"),
    "naval ship": ("ships_boats", "Ships and boats"),
    "submarines": ("submarines", "Submarines"),
    "vehicles and fuel tanks": ("vehicles_fuel_tanks", "Vehicles and fuel tanks"),
    "special equipment": ("special_equipment", "Special equipment"),
}


def parse_general_staff_history(
    source_id: str,
    dataset: str,
    personnel_payload: Any,
    equipment_payload: Any,
) -> ParseResult:
    personnel_by_date = _rows_by_date(personnel_payload)
    equipment_by_date = _rows_by_date(equipment_payload)
    available_dates = sorted(set(personnel_by_date) | set(equipment_by_date))
    if not available_dates:
        return ParseResult(metrics=(), observed_date=None)

    metrics: list[ParsedMetric] = []
    previous_values: dict[str, int] = {}
    baseline_date = date(2022, 2, 24)
    first_equipment = equipment_by_date.get(available_dates[0], {})
    baseline_fields = [("personnel", "Personnel")]
    baseline_fields.extend(
        mapped
        for raw_field, mapped in EQUIPMENT_FIELDS.items()
        if raw_field in first_equipment
    )
    for metric, label in baseline_fields:
        metrics.append(
            ParsedMetric(
                dataset=dataset,
                metric=metric,
                metric_label=label,
                value=0,
                daily_delta=0,
                observed_date=baseline_date,
                source_id=source_id,
            )
        )
        previous_values[metric] = 0

    for observed_date in available_dates:
        values: list[tuple[str, str, int]] = []
        personnel = personnel_by_date.get(observed_date, {}).get("personnel")
        if personnel is not None:
            values.append(("personnel", "Personnel", _int_value(personnel)))
        equipment = equipment_by_date.get(observed_date, {})
        for raw_field, (metric, label) in EQUIPMENT_FIELDS.items():
            if raw_field in equipment and equipment[raw_field] is not None:
                values.append((metric, label, _int_value(equipment[raw_field])))

        parsed_date = date.fromisoformat(observed_date)
        for metric, label, value in values:
            previous = previous_values.get(metric)
            metrics.append(
                ParsedMetric(
                    dataset=dataset,
                    metric=metric,
                    metric_label=label,
                    value=value,
                    daily_delta=value - previous if previous is not None else None,
                    observed_date=parsed_date,
                    source_id=source_id,
                )
            )
            previous_values[metric] = value

    return ParseResult(metrics=tuple(metrics), observed_date=date.fromisoformat(available_dates[-1]))


def _rows_by_date(payload: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(payload, list):
        return {}
    rows: dict[str, dict[str, Any]] = {}
    for row in payload:
        if not isinstance(row, dict) or not isinstance(row.get("date"), str):
            continue
        raw_date = str(row["date"])
        try:
            date.fromisoformat(raw_date)
        except ValueError:
            continue
        rows[raw_date] = row
    return rows


def _int_value(value: Any) -> int:
    return int(round(float(value)))
