"""Smoke tests for BROWSERFORENSICS. No network. Standard library only."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from browserforensics import (  # noqa: E402
    TOOL_NAME, TOOL_VERSION, analyze_history, analyze_downloads, load_records,
)
from browserforensics.cli import main, _render_html, _render_json  # noqa: E402
from browserforensics.core import Severity  # noqa: E402

DEMO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "demos", "01-basic")


class TestMeta(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(TOOL_NAME, "BROWSERFORENSICS")
        self.assertTrue(TOOL_VERSION)

    def test_severity_order(self):
        self.assertGreater(Severity.rank("critical"), Severity.rank("low"))


class TestHistory(unittest.TestCase):
    def test_ip_and_exfil_detected(self):
        recs = [
            {"url": "http://185.220.101.47/x", "title": "a"},
            {"url": "https://pastebin.com/raw/aa", "title": "b"},
            {"url": "https://anonfiles.com/zz", "title": "c"},
            {"url": "https://transfer.sh/get/q", "title": "d"},
            {"url": "https://bit.ly/abc", "title": "e"},
        ]
        rules = {f.rule for f in analyze_history(recs)}
        self.assertIn("history.ip_literal_host", rules)
        self.assertIn("history.exfil_site_visit", rules)
        self.assertIn("history.url_shortener", rules)
        self.assertIn("history.multi_exfil_pattern", rules)

    def test_clean_history(self):
        recs = [{"url": "https://news.ycombinator.com/", "title": "HN"}]
        self.assertEqual(analyze_history(recs), [])


class TestDownloads(unittest.TestCase):
    def test_double_extension_and_flagged(self):
        recs = [
            {"url": "https://x.com/a", "target_path": "c:/d/invoice.pdf.exe"},
            {"url": "http://10.0.0.5/p.bin", "target_path": "p.bin",
             "danger_type": "dangerous_file"},
        ]
        rules = {f.rule for f in analyze_downloads(recs)}
        self.assertIn("download.double_extension", rules)
        self.assertIn("download.from_ip", rules)
        self.assertIn("download.browser_flagged", rules)


class TestLoaders(unittest.TestCase):
    def test_load_demo_files(self):
        h = load_records(os.path.join(DEMO, "history.json"), "history")
        d = load_records(os.path.join(DEMO, "downloads.csv"), "downloads")
        self.assertTrue(h and d)
        self.assertIn("url", h[0])
        self.assertIn("received_bytes", d[1])


class TestRenderers(unittest.TestCase):
    def test_html_and_json(self):
        recs = [{"url": "http://1.2.3.4/x", "title": "t"}]
        f = analyze_history(recs)
        self.assertIn("<!DOCTYPE html>", _render_html(f))
        doc = json.loads(_render_json(f))
        self.assertEqual(doc["tool"], TOOL_NAME)
        self.assertGreaterEqual(doc["summary"]["total"], 1)


class TestCli(unittest.TestCase):
    def test_scan_exit_nonzero_on_findings(self):
        rc = main(["scan", "--history", os.path.join(DEMO, "history.json")])
        self.assertEqual(rc, 1)

    def test_html_output_to_file(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "r.html")
            rc = main(["scan", "--downloads", os.path.join(DEMO, "downloads.csv"),
                       "--format", "html", "-o", out])
            self.assertEqual(rc, 1)
            with open(out, encoding="utf-8") as fh:
                self.assertIn("BROWSERFORENSICS", fh.read())

    def test_no_args_returns_usage_error(self):
        self.assertEqual(main(["scan"]), 2)


if __name__ == "__main__":
    unittest.main()
