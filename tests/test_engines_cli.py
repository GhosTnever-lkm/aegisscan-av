from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aegisscan.cli import build_parser, run
from aegisscan.engines import ClamAVEngine, YaraEngine
from aegisscan.models import Finding, ScanResult, Severity
from aegisscan.report import exit_code, render_json, render_text


class ExternalEngineTests(unittest.TestCase):
    @patch("aegisscan.engines.shutil.which", return_value="/usr/bin/clamscan")
    @patch("aegisscan.engines.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="", stderr=""))
    def test_clamav_clean_result_is_empty_and_shell_is_disabled(self, mock_run, _mock_which) -> None:
        engine = ClamAVEngine()
        self.assertEqual(engine.scan_path(Path("file.bin"), "file.bin"), [])
        self.assertFalse(mock_run.call_args.kwargs["shell"])
        command = mock_run.call_args.args[0]
        self.assertIn("--max-filesize=33554432", command)
        self.assertIn("--max-scansize=134217728", command)
        self.assertFalse(any("remove" in value.lower() or "move" in value.lower() for value in command))

    @patch("aegisscan.engines.shutil.which", return_value="/usr/bin/clamscan")
    @patch("aegisscan.engines.subprocess.run", return_value=SimpleNamespace(returncode=1, stdout="/private/path/file.bin: Example.Test FOUND\n", stderr=""))
    def test_clamav_detection_uses_safe_relative_path(self, _mock_run, _mock_which) -> None:
        findings = ClamAVEngine().scan_path(Path("/private/path/file.bin"), "file.bin")
        self.assertEqual(findings[0].code, "CLAMAV_DETECTION")
        self.assertEqual(findings[0].path, "file.bin")
        self.assertNotIn("/private/path", findings[0].message)

    @patch("aegisscan.engines.shutil.which", return_value="/usr/bin/clamscan")
    @patch(
        "aegisscan.engines.subprocess.run",
        return_value=SimpleNamespace(
            returncode=1,
            stdout="/tmp/aegis-a.bin: Demo.Test FOUND\nWARNING: Skipping large file: max file size exceeded\n",
            stderr="",
        ),
    )
    def test_clamav_detection_also_reports_partial_batch(self, _mock_run, _mock_which) -> None:
        findings = ClamAVEngine().scan_path(Path("/tmp/aegis-a.bin"), "a.bin")
        self.assertEqual(
            [finding.code for finding in findings],
            ["CLAMAV_DETECTION", "CLAMAV_PARTIAL_SCAN"],
        )

    @patch("aegisscan.engines.shutil.which", return_value="/usr/bin/clamscan")
    @patch("aegisscan.engines.subprocess.run")
    def test_clamav_batches_files_and_maps_each_detection(self, mock_run, _mock_which) -> None:
        first = Path("/tmp/aegis-a.bin")
        second = Path("/tmp/aegis-b.bin")
        mock_run.return_value = SimpleNamespace(
            returncode=1,
            stdout=f"{first}: Demo.First FOUND\n{second}: Demo.Second FOUND\n",
            stderr="",
        )
        findings = ClamAVEngine().scan_paths([(first, "a.bin"), (second, "b.bin")])
        self.assertEqual([finding.path for finding in findings], ["a.bin", "b.bin"])
        self.assertEqual(mock_run.call_count, 1)
        self.assertFalse(mock_run.call_args.kwargs["shell"])

    @patch("aegisscan.engines.shutil.which", return_value="/usr/bin/clamscan")
    @patch("aegisscan.engines.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="", stderr=""))
    def test_clamav_splits_large_path_sets_into_bounded_batches(self, mock_run, _mock_which) -> None:
        inputs = [(Path(f"/tmp/aegis-{index}.bin"), f"{index}.bin") for index in range(49)]
        self.assertEqual(ClamAVEngine().scan_paths(inputs), [])
        self.assertEqual(mock_run.call_count, 2)
        self.assertLessEqual(len(mock_run.call_args_list[0].args[0]), 64)

    @patch("aegisscan.engines.shutil.which", return_value="/usr/bin/clamscan")
    @patch("aegisscan.engines.subprocess.run", side_effect=subprocess.TimeoutExpired("clamscan", 1))
    def test_clamav_timeout_is_reported(self, _mock_run, _mock_which) -> None:
        findings = ClamAVEngine(timeout_seconds=1).scan_path(Path("file.bin"), "file.bin")
        self.assertEqual(findings[0].code, "CLAMAV_TIMEOUT")

    @patch("aegisscan.engines.shutil.which", return_value="/usr/bin/clamscan")
    @patch("aegisscan.engines.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="WARNING: Skipping large file: max file size exceeded\n", stderr=""))
    def test_clamav_limit_warning_is_not_reported_as_clean(self, _mock_run, _mock_which) -> None:
        findings = ClamAVEngine().scan_path(Path("file.bin"), "file.bin")
        self.assertEqual(findings[0].code, "CLAMAV_PARTIAL_SCAN")

    @patch("aegisscan.engines.shutil.which", return_value="/usr/bin/clamscan")
    @patch("aegisscan.engines.subprocess.run", return_value=SimpleNamespace(returncode=2, stdout="", stderr="engine error"))
    def test_clamav_nonzero_error_is_reported(self, _mock_run, _mock_which) -> None:
        findings = ClamAVEngine().scan_path(Path("file.bin"), "file.bin")
        self.assertEqual(findings[0].code, "CLAMAV_ERROR")

    @patch("aegisscan.engines.shutil.which", return_value="/usr/bin/clamscan")
    @patch("aegisscan.engines.subprocess.run", side_effect=OSError("missing engine"))
    def test_clamav_launch_error_is_reported_without_crashing(self, _mock_run, _mock_which) -> None:
        findings = ClamAVEngine().scan_path(Path("file.bin"), "file.bin")
        self.assertEqual(findings[0].code, "CLAMAV_ERROR")

    @patch("aegisscan.engines.shutil.which", return_value="/usr/bin/clamscan")
    def test_clamav_rejects_unbounded_configuration(self, _mock_which) -> None:
        with self.assertRaises(ValueError):
            ClamAVEngine(max_files=0)
        with self.assertRaises(ValueError):
            ClamAVEngine(max_recursion=-1)

    @patch("aegisscan.engines.shutil.which", return_value=None)
    def test_clamav_missing_binary_is_explicit(self, _mock_which) -> None:
        with self.assertRaisesRegex(RuntimeError, "not found"):
            ClamAVEngine()

    def test_yara_dependency_is_optional_and_failure_is_actionable(self) -> None:
        with patch.dict(sys.modules, {"yara": None}), self.assertRaisesRegex(RuntimeError, "YARA support"):
            YaraEngine(Path("rules.yar"))

    def test_yara_matches_local_rule_and_uses_relative_path(self) -> None:
        fake_rules = SimpleNamespace(match=lambda **kwargs: [SimpleNamespace(rule="SyntheticRule")])
        fake_yara = SimpleNamespace(compile=lambda **kwargs: fake_rules)
        with patch.dict(sys.modules, {"yara": fake_yara}):
            findings = YaraEngine(Path("rules.yar")).scan_bytes("bundle/member.txt", b"safe bytes")
        self.assertEqual(findings[0].code, "YARA_MATCH")
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].path, "bundle/member.txt")

    def test_yara_no_match_is_clean(self) -> None:
        fake_rules = SimpleNamespace(match=lambda **kwargs: [])
        fake_yara = SimpleNamespace(compile=lambda **kwargs: fake_rules)
        with patch.dict(sys.modules, {"yara": fake_yara}):
            findings = YaraEngine(Path("rules.yar")).scan_bytes("member", b"ordinary text")
        self.assertEqual(findings, [])

    def test_yara_match_failure_is_an_incomplete_scan_finding(self) -> None:
        def fail(**kwargs):
            raise RuntimeError("engine failure")

        fake_yara = SimpleNamespace(compile=lambda **kwargs: SimpleNamespace(match=fail))
        with patch.dict(sys.modules, {"yara": fake_yara}):
            findings = YaraEngine(Path("rules.yar")).scan_bytes("member", b"bytes")
        self.assertEqual(findings[0].code, "YARA_SCAN_ERROR")


class ReportAndCliTests(unittest.TestCase):
    def test_report_uses_safe_relative_paths_and_exit_policies(self) -> None:
        result = ScanResult("sample.zip", findings=[Finding("inner.txt", "TEST", Severity.MEDIUM, "test", "indicator")])
        self.assertEqual(exit_code(result), 0)
        self.assertEqual(exit_code(result, fail_on_warning=True), 1)
        output = render_text(result)
        self.assertIn("REVIEW REQUIRED", output)
        self.assertNotIn("/home/", render_json(result))
        self.assertEqual(json.loads(render_json(result))["finding_count"], 1)

    def test_skipped_content_is_incomplete_not_clean(self) -> None:
        result = ScanResult("sample", files_skipped=1)
        self.assertEqual(exit_code(result), 2)
        self.assertIn("SCAN INCOMPLETE", render_text(result))

    def test_cli_writes_json_only_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "note.txt"
            target.write_text("safe local file", encoding="utf-8")
            report = root / "reports" / "scan.json"
            args = build_parser().parse_args(["scan", str(target), "--json-out", str(report)])
            with patch("sys.stdout"):
                code = run(args)
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(report.read_text())["files_scanned"], 1)

    def test_cli_refuses_report_over_scanned_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "keep.txt"
            original = "original user content"
            target.write_text(original, encoding="utf-8")
            args = build_parser().parse_args(["scan", str(target), "--json-out", str(target)])
            with patch("sys.stderr"):
                code = run(args)
            self.assertEqual(code, 2)
            self.assertEqual(target.read_text(encoding="utf-8"), original)

    def test_cli_refuses_report_inside_scanned_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "keep.txt"
            original = "original user content"
            source.write_text(original, encoding="utf-8")
            report = root / "scan.json"
            args = build_parser().parse_args(["scan", str(root), "--json-out", str(report)])
            with patch("sys.stderr"):
                code = run(args)
            self.assertEqual(code, 2)
            self.assertEqual(source.read_text(encoding="utf-8"), original)
            self.assertFalse(report.exists())

    def test_cli_report_does_not_modify_scanned_file_through_external_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            scan_root = root / "scan"
            scan_root.mkdir()
            source = scan_root / "keep.txt"
            original = "original user content"
            source.write_text(original, encoding="utf-8")
            report = root / "scan.json"
            try:
                os.link(source, report)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"hard links are unavailable: {exc}")
            args = build_parser().parse_args(["scan", str(scan_root), "--json-out", str(report)])
            code = run(args)
            self.assertEqual(code, 0)
            self.assertEqual(source.read_text(encoding="utf-8"), original)
            self.assertEqual(json.loads(report.read_text(encoding="utf-8"))["files_scanned"], 1)
            self.assertFalse(os.path.samefile(source, report))

    def test_cli_invalid_limits_return_configuration_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "note.txt"
            target.write_text("safe")
            args = build_parser().parse_args(["scan", str(target), "--max-file-mib", "0"])
            with patch("sys.stderr"):
                self.assertEqual(run(args), 2)

    def test_cli_invalid_archive_depth_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "note.txt"
            target.write_text("safe")
            args = build_parser().parse_args(["scan", str(target), "--max-archive-depth", "-1"])
            with patch("sys.stderr"):
                self.assertEqual(run(args), 2)

    def test_cli_yara_without_optional_dependency_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "note.txt"
            target.write_text("safe")
            rules = root / "rules.yar"
            rules.write_text("rule Empty { condition: false }")
            args = build_parser().parse_args(["scan", str(target), "--yara-rules", str(rules)])
            with patch.dict(sys.modules, {"yara": None}), patch("sys.stderr"):
                self.assertEqual(run(args), 2)
