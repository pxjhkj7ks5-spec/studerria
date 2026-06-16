import unittest
import sys
from pathlib import Path

SERVICE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_ROOT))

from app.core.config import DEFAULT_MOD_ARTICLE_PREFIX, DEFAULT_MOD_LISTING_URL, DEFAULT_MOD_LOOKUP_URL, is_allowlisted_url
from app.parsers.general_losses import parse_general_losses
from app.parsers.sbs import parse_sbs


FIXTURES = Path(__file__).resolve().parent / "fixtures"


class ParserTests(unittest.TestCase):
    def test_general_losses_parser_extracts_values_and_deltas(self):
        html = (FIXTURES / "general_losses.html").read_text(encoding="utf-8")
        result = parse_general_losses("zsu-general-losses", "general_losses", html)
        by_metric = {metric.metric: metric for metric in result.metrics}

        self.assertEqual(result.observed_date.isoformat(), "2026-06-16")
        self.assertEqual(by_metric["personnel"].value, 1002340)
        self.assertEqual(by_metric["personnel"].daily_delta, 1040)
        self.assertEqual(by_metric["tanks"].value, 10920)
        self.assertEqual(by_metric["uav"].daily_delta, 87)

    def test_sbs_parser_keeps_separate_dataset(self):
        html = (FIXTURES / "sbs.html").read_text(encoding="utf-8")
        result = parse_sbs("sbs-pidrahuyka", "sbs_stats", html)
        by_metric = {metric.metric: metric for metric in result.metrics}

        self.assertEqual(by_metric["personnel"].dataset, "sbs_stats")
        self.assertEqual(by_metric["personnel"].value, 12500)
        self.assertEqual(by_metric["uav"].value, 930)

    def test_mod_general_losses_parser_extracts_short_dates_and_single_digit_values(self):
        html = (FIXTURES / "mod_general_losses.html").read_text(encoding="utf-8")
        result = parse_general_losses("mod-general-losses", "general_losses", html)
        by_metric = {metric.metric: metric for metric in result.metrics}

        self.assertEqual(result.observed_date.isoformat(), "2026-06-16")
        self.assertEqual(by_metric["personnel"].value, 1385420)
        self.assertEqual(by_metric["personnel"].daily_delta, 1230)
        self.assertEqual(by_metric["armored_vehicles"].value, 24768)
        self.assertEqual(by_metric["artillery_systems"].value, 44118)
        self.assertEqual(by_metric["uav"].value, 353541)
        self.assertEqual(by_metric["uav"].daily_delta, 2062)
        self.assertEqual(by_metric["air_defense_systems"].value, 1427)
        self.assertEqual(by_metric["submarines"].value, 2)
        self.assertEqual(by_metric["special_equipment"].value, 4300)

    def test_allowlist_accepts_mod_listing_and_article_prefix(self):
        allowed = (DEFAULT_MOD_LISTING_URL, DEFAULT_MOD_LOOKUP_URL, DEFAULT_MOD_ARTICLE_PREFIX)

        self.assertTrue(is_allowlisted_url(DEFAULT_MOD_LISTING_URL, allowed))
        self.assertTrue(is_allowlisted_url(DEFAULT_MOD_LOOKUP_URL, allowed))
        self.assertTrue(is_allowlisted_url(f"{DEFAULT_MOD_ARTICLE_PREFIX}16-06-2026", allowed))
        self.assertFalse(is_allowlisted_url("https://example.com/news/bojovi-vtrati-voroga-na-16-06-2026", allowed))


if __name__ == "__main__":
    unittest.main()
