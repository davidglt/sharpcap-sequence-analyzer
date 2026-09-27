import json
import os
import tempfile
import unittest
from pathlib import Path

import sharpcap_sequence_analyzer as analyzer


class AnalyzerTests(unittest.TestCase):
    def test_find_latest_log_uses_filename_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            older = root / "Log_2026-01-01T00_00_00-1.log"
            newer = root / "Log_2026-01-02T00_00_00-1.log"
            older.write_text("", encoding="utf-8")
            newer.write_text("", encoding="utf-8")
            os.utime(older, (200, 200))
            os.utime(newer, (100, 100))
            self.assertEqual(analyzer.find_latest_log(root), newer)

    def test_parse_timestamp_rolls_over_midnight(self) -> None:
        start = analyzer.datetime(2026, 1, 1, 23, 59, 0)
        previous = analyzer.datetime(2026, 1, 1, 23, 59, 59)
        timestamp = analyzer.parse_timestamp(start, "00:00:01.000", previous)
        self.assertEqual(timestamp, analyzer.datetime(2026, 1, 2, 0, 0, 1))

    def test_classify_diagnostic_marks_exceptions_critical(self) -> None:
        self.assertEqual(
            analyzer.classify_diagnostic("error", "Unhandled exception", False),
            ("software_exception", "critical"),
        )

    def test_build_report_and_write_reports_use_portable_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "Log_2026-01-01T00_00_00-1.log"
            log.write_text(
                "Info\t00:00:01.000\t#1\tCreating file name provider for target 'M42', Camera, L, Light\n",
                encoding="utf-8",
            )
            report = analyzer.build_report(log)
            self.assertEqual(report["source_log"]["path"], log.name)
            output = root / "reports"
            paths = analyzer.write_reports(report, output)
            self.assertTrue(all(path.is_file() for path in paths))
            with paths[0].open(encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["source_log"]["path"], log.name)

    def test_parse_arguments_supports_reproducible_paths(self) -> None:
        arguments = analyzer.parse_arguments(
            ["--config", "config.properties", "--log", "session.log", "--reports-dir", "output"]
        )
        self.assertEqual(arguments.config, Path("config.properties"))
        self.assertEqual(arguments.log, Path("session.log"))
        self.assertEqual(arguments.reports_dir, Path("output"))


if __name__ == "__main__":
    unittest.main()
