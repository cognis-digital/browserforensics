"""Hardening tests: error paths, edge cases, and input validation.

All tests are offline (no network) and use only the standard library.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from browserforensics.core import (  # noqa: E402
    analyze,
    analyze_downloads,
    analyze_history,
    load_records,
)
from browserforensics.cli import main  # noqa: E402


class TestLoadRecordsEdgeCases(unittest.TestCase):
    """load_records should reject bad inputs with clear errors, not tracebacks."""

    def _write_tmp(self, content: str, suffix: str = ".json") -> str:
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def test_empty_file_returns_empty_list(self):
        """An empty (zero-byte) file must return [] without crashing."""
        path = self._write_tmp("")
        try:
            records = load_records(path, "history")
            self.assertEqual(records, [])
        finally:
            os.unlink(path)

    def test_invalid_kind_raises_value_error(self):
        """Passing an unknown kind must raise ValueError immediately."""
        path = self._write_tmp("[]")
        try:
            with self.assertRaises(ValueError) as ctx:
                load_records(path, "sessions")
            self.assertIn("sessions", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_missing_file_raises_file_not_found(self):
        """A path that does not exist must raise FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            load_records("/no/such/file/browserforensics_test.json", "history")

    def test_valid_json_list_loads(self):
        """A JSON array of objects must load as normalized records."""
        data = json.dumps([{"url": "http://example.com", "title": "Ex"}])
        path = self._write_tmp(data)
        try:
            records = load_records(path, "history")
            self.assertTrue(records)
            self.assertIn("url", records[0])
        finally:
            os.unlink(path)

    def test_csv_with_only_header_returns_empty(self):
        """A CSV with only a header row and no data rows returns an empty list."""
        path = self._write_tmp("url,title\n", ".csv")
        try:
            records = load_records(path, "history")
            self.assertEqual(records, [])
        finally:
            os.unlink(path)


class TestAnalyzeEdgeCases(unittest.TestCase):
    """analyze() and the per-artifact analyzers should handle degenerate inputs."""

    def test_analyze_no_paths_raises(self):
        """analyze() with no paths must raise ValueError, not AttributeError."""
        with self.assertRaises(ValueError):
            analyze()

    def test_analyze_history_empty_list(self):
        """analyze_history([]) must return [] without crashing."""
        self.assertEqual(analyze_history([]), [])

    def test_analyze_downloads_empty_list(self):
        """analyze_downloads([]) must return [] without crashing."""
        self.assertEqual(analyze_downloads([]), [])

    def test_analyze_history_missing_url_skipped(self):
        """Records with no URL key must be silently skipped (not crash)."""
        recs = [{"title": "no url here"}, {"url": "", "title": "empty url"}]
        findings = analyze_history(recs)
        self.assertIsInstance(findings, list)

    def test_analyze_downloads_zero_bytes(self):
        """A download record with zero bytes must not raise ZeroDivisionError."""
        recs = [{"url": "http://x.com/f.exe", "target_path": "f.exe", "received_bytes": 0}]
        findings = analyze_downloads(recs)
        self.assertTrue(any(f.rule == "download.executable" for f in findings))


class TestCliHardeningPaths(unittest.TestCase):
    """CLI must return exit-code 2 with a message on bad inputs."""

    def _write_tmp_json(self, data: list) -> str:
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        return path

    def test_nonexistent_history_file_exits_2(self):
        """Providing a non-existent --history path must exit 2."""
        rc = main(["scan", "--history", "/no/such/path/ghost_history.json"])
        self.assertEqual(rc, 2)

    def test_nonexistent_downloads_file_exits_2(self):
        """Providing a non-existent --downloads path must exit 2."""
        rc = main(["scan", "--downloads", "/no/such/path/ghost_downloads.csv"])
        self.assertEqual(rc, 2)

    def test_clean_input_exits_0(self):
        """A file with only benign URLs must produce findings=0 and exit 0."""
        path = self._write_tmp_json([
            {"url": "https://www.bbc.co.uk/news", "title": "BBC"},
            {"url": "https://docs.python.org/3/", "title": "Python docs"},
        ])
        try:
            rc = main(["scan", "--history", path, "--fail-on", "critical"])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)

    def test_directory_path_exits_2(self):
        """Passing a directory instead of a file must exit 2 cleanly."""
        with tempfile.TemporaryDirectory() as td:
            rc = main(["scan", "--history", td])
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
