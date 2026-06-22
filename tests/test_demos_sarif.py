"""Tests for SARIF export and the bundled demo scenarios.

No network. Standard library only. Each demo is asserted to actually produce
(or, for the clean baseline, NOT produce) the findings its SCENARIO.md claims.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from browserforensics import TOOL_NAME, TOOL_VERSION  # noqa: E402
from browserforensics.cli import main, _render_sarif  # noqa: E402
from browserforensics.core import analyze, analyze_history  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(ROOT, "demos")


def _rules(history=None, downloads=None):
    h = os.path.join(DEMOS, history) if history else None
    d = os.path.join(DEMOS, downloads) if downloads else None
    return {f.rule for f in analyze(h, d)}


class TestVersion(unittest.TestCase):
    def test_version_matches_version_file(self):
        with open(os.path.join(ROOT, "VERSION"), encoding="utf-8") as fh:
            self.assertEqual(TOOL_VERSION, fh.read().strip())


class TestSarif(unittest.TestCase):
    def test_sarif_structure(self):
        recs = [
            {"url": "http://185.220.101.47/x", "title": "a"},
            {"url": "https://pastebin.com/raw/aa", "title": "b"},
        ]
        doc = json.loads(_render_sarif(analyze_history(recs)))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("$schema", doc)
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], TOOL_NAME)
        self.assertTrue(run["tool"]["driver"]["rules"])
        self.assertTrue(run["results"])
        # every result references a defined rule by index
        n_rules = len(run["tool"]["driver"]["rules"])
        for r in run["results"]:
            self.assertIn(r["level"], ("error", "warning", "note"))
            self.assertLess(r["ruleIndex"], n_rules)
            self.assertIn("security-severity",
                          run["tool"]["driver"]["rules"][r["ruleIndex"]]["properties"])

    def test_sarif_cli_to_file(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "r.sarif")
            rc = main(["scan", "--history",
                       os.path.join(DEMOS, "01-basic", "history.json"),
                       "--format", "sarif", "-o", out])
            self.assertEqual(rc, 1)
            with open(out, encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc["version"], "2.1.0")

    def test_sarif_empty_is_valid(self):
        doc = json.loads(_render_sarif([]))
        self.assertEqual(doc["runs"][0]["results"], [])
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["rules"], [])


class TestDemoScenarios(unittest.TestCase):
    def test_02_clean_baseline_has_no_findings(self):
        self.assertEqual(_rules(history="02-clean-baseline/history.json"), set())

    def test_03_firefox_csv_aliases(self):
        r = _rules(downloads="03-firefox-csv/downloads.csv")
        self.assertIn("download.executable", r)
        self.assertIn("download.from_exfil_host", r)
        self.assertIn("download.browser_flagged", r)

    def test_04_double_extension(self):
        r = _rules(downloads="04-double-extension-lure/downloads.csv")
        self.assertIn("download.double_extension", r)

    def test_05_c2_beacon(self):
        r = _rules(history="05-c2-beacon-history/history.json")
        self.assertIn("history.ip_literal_host", r)
        self.assertIn("history.encoded_query", r)
        self.assertIn("history.suspicious_tld", r)

    def test_06_bulk_exfil_multi_pattern(self):
        r = _rules(history="06-cloud-bulk-exfil/history.json",
                   downloads="06-cloud-bulk-exfil/downloads.csv")
        self.assertIn("history.multi_exfil_pattern", r)
        self.assertIn("download.large_transfer", r)
        self.assertIn("history.sensitive_keyword", r)

    def test_07_malvertising_shorteners(self):
        r = _rules(history="07-malvertising-shortener/history.csv")
        self.assertIn("history.url_shortener", r)
        self.assertIn("history.suspicious_tld", r)
        self.assertIn("history.ip_literal_host", r)

    def test_08_zip_tld(self):
        r = _rules(history="08-zip-tld-phish/history.json")
        self.assertIn("history.suspicious_tld", r)

    def test_09_flat_json_array(self):
        r = _rules(downloads="09-flat-json-array/downloads.json")
        self.assertIn("download.executable", r)
        self.assertIn("download.from_exfil_host", r)
        self.assertIn("download.from_ip", r)

    def test_every_demo_has_scenario(self):
        for entry in os.listdir(DEMOS):
            d = os.path.join(DEMOS, entry)
            if os.path.isdir(d):
                self.assertTrue(
                    os.path.exists(os.path.join(d, "SCENARIO.md")),
                    f"{entry} is missing SCENARIO.md")


if __name__ == "__main__":
    unittest.main()
