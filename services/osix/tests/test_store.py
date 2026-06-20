import sys
import unittest
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


class StoreTests(unittest.TestCase):
    def test_delete_metrics_outside_range_is_scoped_to_dataset_and_source(self):
        store = ClickHouseStore(load_settings())
        store._client = FakeClient()

        store.delete_metrics_outside_range(
            "general_losses",
            "mod-general-losses",
            "2025-01-01",
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
                "start": "2025-01-01",
                "end": "2026-06-20",
            },
        )


if __name__ == "__main__":
    unittest.main()
