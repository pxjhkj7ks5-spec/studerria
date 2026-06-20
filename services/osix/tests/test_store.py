import sys
import unittest
from datetime import date
from pathlib import Path


SERVICE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_ROOT))

from app.core.config import load_settings
from app.db.clickhouse import ClickHouseStore


class FakeClient:
    def __init__(self):
        self.commands = []

    def command(self, query, parameters=None):
        self.commands.append((query, parameters))


class FakeQueryResult:
    def __init__(self, rows):
        self.result_rows = rows


class FakeQueryClient(FakeClient):
    def __init__(self, rows):
        super().__init__()
        self.rows = rows
        self.queries = []

    def query(self, query, parameters=None):
        self.queries.append((query, parameters))
        return FakeQueryResult(self.rows)


class StoreTests(unittest.TestCase):
    def test_delete_metrics_outside_range_is_scoped_to_dataset_and_source(self):
        store = ClickHouseStore(load_settings())
        store._client = FakeClient()

        store.delete_metrics_outside_range(
            "general_losses",
            "mod-general-losses",
            "2022-02-24",
            "2026-06-20",
        )

        query, parameters = store.client.commands[0]
        self.assertIn("ALTER TABLE metrics_time_series", query)
        self.assertIn("mutations_sync = 1", query)
        self.assertEqual(
            parameters,
            {
                "dataset": "general_losses",
                "source_id": "mod-general-losses",
                "start": "2022-02-24",
                "end": "2026-06-20",
            },
        )

    def test_latest_observed_date_returns_source_scoped_maximum(self):
        store = ClickHouseStore(load_settings())
        store._client = FakeQueryClient([(date(2026, 6, 19),)])

        result = store.latest_observed_date("russia_oil_exports", "crea-russia-fossil-tracker")

        query, parameters = store.client.queries[0]
        self.assertIn("maxOrNull(observed_date)", query)
        self.assertEqual(result, date(2026, 6, 19))
        self.assertEqual(parameters["source_id"], "crea-russia-fossil-tracker")


if __name__ == "__main__":
    unittest.main()
