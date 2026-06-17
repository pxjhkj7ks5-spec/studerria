from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .base import ParseResult, ParsedMetric, clean_int, html_to_text


SBS_METRIC_PATTERNS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("personnel", "Personnel", (r"особового складу", r"personnel")),
    ("tanks", "Tanks", (r"(?<![а-яіїєґa-z])танк(?:и|ів|а|у)?(?![а-яіїєґa-z])", r"tanks?")),
    ("armored_vehicles", "Armored vehicles", (r"броньован", r"armou?red")),
    ("artillery_systems", "Artillery systems", (r"артилер", r"artillery")),
    ("air_defense_systems", "Air defense systems", (r"ппо", r"air defense")),
    ("uav", "UAV", (r"бпла", r"uav")),
    ("vehicles", "Vehicles", (r"автомоб", r"vehicles?")),
)

SBS_TARGET_SLUGS: dict[int, tuple[str, str]] = {
    1: ("tanks", "Tanks"),
    2: ("armored_vehicles", "APCs, IFVs, ACVs"),
    3: ("guns_howitzers", "Guns and howitzers"),
    4: ("self_propelled_artillery", "Self-propelled artillery"),
    5: ("mlrs_air_defense", "MLRS, SAM, AA guns"),
    6: ("mortars", "Mortars"),
    7: ("vehicles", "Vehicles and special equipment"),
    8: ("radars_portable", "Radars and sensors, portable"),
    9: ("radars_systems", "Radar, ELINT and comms systems"),
    10: ("ew_portable", "EW, portable"),
    11: ("ew_systems", "EW systems"),
    12: ("ew_vehicles", "EW vehicles"),
    13: ("antennas", "Antennas"),
    14: ("network_equipment", "Network equipment"),
    15: ("personnel_targets", "Personnel targets"),
    16: ("strategic_infrastructure", "Strategic infrastructure"),
    17: ("tactical_infrastructure", "Tactical infrastructure"),
    18: ("motorcycles", "Motorcycles"),
    19: ("buggies", "Military buggies"),
    20: ("warehouses", "Warehouses"),
    21: ("shelters", "Shelters"),
    22: ("dugouts", "Dugouts"),
    23: ("drone_launch_points", "Drone launch points"),
    24: ("enemy_copters", "Enemy copters"),
    25: ("enemy_fixed_wing_uav", "Enemy fixed-wing UAV"),
    26: ("enemy_ugv", "Enemy UGV"),
    27: ("cameras", "Cameras"),
    28: ("other_targets", "Other targets"),
    29: ("helicopters", "Helicopters"),
    32: ("sam_systems", "SAM systems"),
    33: ("aa_guns", "AA guns"),
    34: ("air_defense_systems", "Air defense systems"),
    35: ("uas_systems", "UAS systems"),
    36: ("portable_mlrs", "Portable MLRS"),
    41: ("aircraft", "Aircraft"),
    42: ("fleet", "Fleet"),
}


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


def parse_sbs_statistics(source_id: str, dataset: str, payload: dict[str, Any]) -> ParseResult:
    data = payload.get("data", payload)
    observed_date = datetime.now(timezone.utc).date()
    metrics: list[ParsedMetric] = []

    def add(metric: str, label: str, value: Any) -> None:
        if value is None:
            return
        try:
            parsed_value = int(value)
        except (TypeError, ValueError):
            return
        metrics.append(
            ParsedMetric(
                dataset=dataset,
                metric=metric,
                metric_label=label,
                value=parsed_value,
                daily_delta=None,
                observed_date=observed_date,
                source_id=source_id,
            )
        )

    total_hit = 0
    total_destroyed = 0
    targets = data.get("targetsByType") if isinstance(data, dict) else None
    if isinstance(targets, list):
        for target in targets:
            if not isinstance(target, dict):
                continue
            target_id = int(target.get("targetClassId") or target.get("screenId") or 0)
            slug, label = SBS_TARGET_SLUGS.get(target_id, (f"target_{target_id}", str(target.get("targetClass") or f"Target {target_id}")))
            hit = int(target.get("hit") or 0)
            destroyed = int(target.get("destroyed") or 0)
            total_hit += hit
            total_destroyed += destroyed
            add(f"{slug}_hit", f"{label} hit", hit)
            add(f"{slug}_destroyed", f"{label} destroyed", destroyed)

    personnel = data.get("personnel") if isinstance(data, dict) else None
    if isinstance(personnel, dict):
        killed = int(personnel.get("killed") or 0)
        wounded = int(personnel.get("wounded") or 0)
        add("personnel", "Personnel casualties", data.get("totalPersonnelCasualties") or killed + wounded)
        add("personnel_killed", "Personnel killed", killed)
        add("personnel_wounded", "Personnel wounded", wounded)

    flights = data.get("flights") if isinstance(data, dict) else None
    if isinstance(flights, dict):
        add("flights_strike", "Strike flights", flights.get("strike"))
        add("flights_recon", "Recon flights", flights.get("recon"))

    add("total_hit", "Targets hit", total_hit)
    add("total_destroyed", "Targets destroyed", total_destroyed)

    return ParseResult(metrics=tuple(metrics), observed_date=observed_date)
