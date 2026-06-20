import sys
import unittest
from pathlib import Path


SERVICE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_ROOT))

from app.parsers.energy_exports import parse_crea_counter
from app.parsers.general_staff_history import parse_general_staff_history


class DataSourceParserTests(unittest.TestCase):
    def test_general_staff_history_starts_with_invasion_baseline_and_daily_deltas(self):
        personnel = [
            {"date": "2022-02-25", "personnel": 2800},
            {"date": "2022-02-26", "personnel": 4300},
        ]
        equipment = [
            {"date": "2022-02-25", "tank": 80, "APC": 516, "drone": 0},
            {"date": "2022-02-26", "tank": 146, "APC": 706, "drone": 2},
        ]

        result = parse_general_staff_history("general-staff-history", "general_losses", personnel, equipment)
        indexed = {(metric.observed_date.isoformat(), metric.metric): metric for metric in result.metrics}

        self.assertEqual(indexed[("2022-02-24", "personnel")].value, 0)
        self.assertEqual(indexed[("2022-02-25", "personnel")].daily_delta, 2800)
        self.assertEqual(indexed[("2022-02-26", "personnel")].daily_delta, 1500)
        self.assertEqual(indexed[("2022-02-26", "tanks")].value, 146)
        self.assertEqual(result.observed_date.isoformat(), "2022-02-26")

    def test_crea_counter_builds_volume_revenue_and_destination_metrics(self):
        payload = {
            "data": [
                {"date": "2026-06-19T00:00:00", "commodity": "crude_oil", "destination_region": "China", "value_tonne": 100, "value_eur": 1000},
                {"date": "2026-06-19T00:00:00", "commodity": "oil_products", "destination_region": "India", "value_tonne": 50, "value_eur": 700},
                {"date": "2026-06-20T00:00:00", "commodity": "crude_oil", "destination_region": "China", "value_tonne": 120, "value_eur": 1200},
                {"date": "2026-06-20T00:00:00", "commodity": "oil_products", "destination_region": "India", "value_tonne": 60, "value_eur": 900},
            ]
        }

        result = parse_crea_counter("crea-russia-fossil-tracker", "russia_oil_exports", payload)
        indexed = {(metric.observed_date.isoformat(), metric.metric): metric for metric in result.metrics}

        self.assertEqual(indexed[("2026-06-20", "oil_total_tonnes")].value, 180)
        self.assertEqual(indexed[("2026-06-20", "oil_export_revenue_eur")].value, 2100)
        self.assertEqual(indexed[("2026-06-20", "oil_to_china_tonnes")].value, 120)
        self.assertEqual(indexed[("2026-06-20", "oil_total_tonnes")].daily_delta, 30)
        self.assertEqual(result.observed_date.isoformat(), "2026-06-20")


if __name__ == "__main__":
    unittest.main()
