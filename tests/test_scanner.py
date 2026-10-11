from __future__ import annotations

import hashlib
import io
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aegisscan.config import ScanLimits
from aegisscan.models import Finding, Severity
from aegisscan.scanner import Scanner
from aegisscan.signatures import SignatureDatabase


def zip_bytes(entries: list[tuple[str, bytes]], compression: int = zipfile.ZIP_STORED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return buffer.getvalue()


def codes(result) -> set[str]:
    return {finding.code for finding in result.findings}


class ScannerFileTests(unittest.TestCase):
    def test_clean_file_is_scanned_without_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "notes.txt"
            path.write_text("ordinary release notes", encoding="utf-8")
            result = Scanner().scan(path)
        self.assertEqual(result.files_scanned, 1)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.bytes_scanned, len(b"ordinary release notes"))
        self.assertEqual(result.target, "notes.txt")

    def test_local_sha256_signature_is_high_confidence(self) -> None:
        content = b"synthetic signature fixture only"
        db = SignatureDatabase({hashlib.sha256(content).hexdigest(): "lab-marker"})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "fixture.bin"
            path.write_bytes(content)
            result = Scanner(signatures=db).scan(path)
        self.assertIn("SHA256_SIGNATURE", codes(result))
        self.assertTrue(result.has_high_risk)
        self.assertIn("lab-marker", result.findings[0].message)

    def test_heuristics_are_indicators_not_verdicts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "script.txt"
            path.write_bytes(b"powershell -EncodedCommand example")
            result = Scanner().scan(path)
        self.assertIn("POWERSHELL_ENCODED_COMMAND", codes(result))
        finding = result.findings[0]
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.engine, "heuristics")

    def test_file_limit_skips_contents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "big.bin"
            path.write_bytes(b"x" * 20)
            result = Scanner(ScanLimits(max_file_bytes=10)).scan(path)
        self.assertEqual(result.files_scanned, 0)
        self.assertIn("FILE_SIZE_LIMIT", codes(result))

    def test_total_file_count_limit_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "a.txt").write_text("first")
            (root / "b.txt").write_text("second")
            result = Scanner(ScanLimits(max_files=1)).scan(root)
        self.assertEqual(result.files_scanned, 1)
        self.assertIn("FILE_COUNT_LIMIT", codes(result))

    def test_growth_during_read_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "growing.txt"
            path.write_bytes(b"x")
            with patch.object(Path, "open", return_value=io.BytesIO(b"12345")):
                result = Scanner(ScanLimits(max_file_bytes=4)).scan(path)
        self.assertEqual(result.files_scanned, 0)
        self.assertIn("FILE_GROWTH_LIMIT", codes(result))

    def test_file_read_error_is_reported_with_relative_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "private-name.txt"
            path.write_text("safe")
            with patch.object(Path, "open", side_effect=PermissionError("denied")):
                result = Scanner().scan(path)
        self.assertTrue(result.errors)
        self.assertIn("private-name.txt", result.errors[0])
        self.assertNotIn(directory, result.errors[0])

    def test_directory_read_error_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch("aegisscan.scanner.os.scandir", side_effect=PermissionError("denied")):
                result = Scanner().scan(Path(directory).resolve())
        self.assertTrue(result.errors)
        self.assertIn("cannot read .", result.errors[0])

    def test_tree_at_exact_depth_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "root"
            nested = root / "sub"
            nested.mkdir(parents=True)
            (nested / "note.txt").write_text("safe")
            result = Scanner(ScanLimits(max_depth=1)).scan(root)
        self.assertEqual(result.files_scanned, 1)
        self.assertNotIn("DIRECTORY_DEPTH_LIMIT", codes(result))

    def test_invalid_limits_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ScanLimits(max_files=0)
        with self.assertRaises(ValueError):
            ScanLimits(max_archive_depth=-1)
        with self.assertRaises(ValueError):
            ScanLimits(max_entries=0)

    def test_total_directory_entry_count_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "a.txt").write_text("a")
            (root / "b.txt").write_text("b")
            result = Scanner(ScanLimits(max_entries=1)).scan(root)
        self.assertIn("DIRECTORY_ENTRY_LIMIT", codes(result))
        self.assertLessEqual(result.files_scanned, 1)

    def test_total_directory_count_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "a").mkdir()
            (root / "b").mkdir()
            result = Scanner(ScanLimits(max_directories=1)).scan(root)
        self.assertIn("DIRECTORY_COUNT_LIMIT", codes(result))

    def test_optional_clamav_findings_are_included(self) -> None:
        engine = Mock()
        engine.scan_paths.return_value = [
            Finding("file.txt", "CLAMAV_DETECTION", Severity.CRITICAL, "clamav", "synthetic detection")
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "file.txt"
            path.write_text("safe synthetic fixture")
            result = Scanner(clamav=engine).scan(path)
        self.assertIn("CLAMAV_DETECTION", codes(result))
        engine.scan_paths.assert_called_once()

    def test_root_symlink_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            external = Path(outside).resolve() / "outside.txt"
            external.write_text("safe")
            link = Path(directory).resolve() / "link.txt"
            try:
                link.symlink_to(external)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            result = Scanner().scan(link)
        self.assertEqual(result.files_scanned, 0)
        self.assertIn("SYMLINK_SKIPPED", codes(result))

    def test_target_below_symlink_directory_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory).resolve()
            external = Path(outside).resolve()
            (external / "outside.txt").write_text(
                "powershell -EncodedCommand synthetic", encoding="utf-8"
            )
            link = root / "linked-directory"
            try:
                link.symlink_to(external, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symlink unavailable: {exc}")

            result = Scanner().scan(link / "outside.txt")

        self.assertEqual(result.files_scanned, 0)
        self.assertIn("SYMLINK_SKIPPED", codes(result))
        self.assertNotIn("POWERSHELL_ENCODED_COMMAND", codes(result))

    def test_link_path_guard_handles_relative_and_parent_components(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "subdir" / ".." / "missing.txt"
            with patch("aegisscan.scanner.Path.cwd", return_value=root):
                self.assertFalse(Scanner._contains_linklike_component(Path("missing.txt")))
                self.assertFalse(Scanner._contains_linklike_component(target))

    def test_link_path_guard_rejects_windows_junction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            junction = Path(directory).resolve() / "junction"
            junction.mkdir()
            with patch.object(
                Path, "is_junction", lambda candidate: candidate.name == "junction", create=True
            ):
                self.assertTrue(Scanner._contains_linklike_component(junction))

    def test_link_path_guard_rejects_windows_reparse_point(self) -> None:
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        metadata = SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=reparse_flag)
        with (
            patch.object(Path, "lstat", return_value=metadata),
            patch.object(Path, "is_junction", return_value=False, create=True),
        ):
            self.assertTrue(Scanner._contains_linklike_component(Path("/synthetic/path")))

    def test_total_scan_budget_is_enforced_across_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "a.txt").write_bytes(b"a" * 6)
            (root / "b.txt").write_bytes(b"b" * 6)
            result = Scanner(ScanLimits(max_total_bytes=10)).scan(root)
        self.assertEqual(result.bytes_scanned, 6)
        self.assertEqual(result.files_scanned, 1)
        self.assertIn("TOTAL_SCAN_BYTE_LIMIT", codes(result))

    def test_nonexistent_target_returns_error_without_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "missing.bin"
            result = Scanner().scan(target)
        self.assertTrue(result.errors)
        self.assertNotIn(directory, result.errors[0])

    def test_symlink_is_skipped_without_reading_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory).resolve() / "scan"
            root.mkdir()
            external = Path(outside).resolve() / "outside.txt"
            external.write_text("powershell -EncodedCommand synthetic", encoding="utf-8")
            try:
                (root / "linked.txt").symlink_to(external)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            result = Scanner().scan(root)
        self.assertEqual(result.files_scanned, 0)
        self.assertIn("SYMLINK_SKIPPED", codes(result))
        self.assertNotIn("POWERSHELL_ENCODED_COMMAND", codes(result))

    def test_directory_depth_limit_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            nested = Path(directory).resolve() / "a" / "b"
            nested.mkdir(parents=True)
            (nested / "file.txt").write_text("safe")
            result = Scanner(ScanLimits(max_depth=1)).scan(Path(directory).resolve())
        self.assertIn("DIRECTORY_DEPTH_LIMIT", codes(result))


class ScannerArchiveTests(unittest.TestCase):
    def _scan_zip(self, data: bytes, limits: ScanLimits | None = None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "sample.zip"
            path.write_bytes(data)
            return Scanner(limits).scan(path)

    def test_scans_zip_members_without_extracting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive_path = root / "sample.zip"
            archive_path.write_bytes(zip_bytes([("folder/readme.txt", b"hello")]))
            archive_size = archive_path.stat().st_size
            result = Scanner().scan(archive_path)
            self.assertFalse((root / "folder").exists())
        self.assertEqual(result.files_scanned, 2)
        self.assertEqual(result.bytes_scanned, archive_size + 5)

    def test_archive_entry_count_exact_limit_and_overflow(self) -> None:
        data = zip_bytes([("a.txt", b"a"), ("b.txt", b"b")])
        exact = self._scan_zip(data, ScanLimits(max_archive_entries=2))
        over = self._scan_zip(data, ScanLimits(max_archive_entries=1))
        self.assertNotIn("ARCHIVE_ENTRY_LIMIT", codes(exact))
        self.assertIn("ARCHIVE_ENTRY_LIMIT", codes(over))
        self.assertEqual(exact.files_scanned, 3)

    def test_archive_member_limit_and_expansion_ratio(self) -> None:
        large = self._scan_zip(
            zip_bytes([("large.bin", b"A" * 2048)]),
            ScanLimits(max_archive_member_bytes=1024),
        )
        ratio = self._scan_zip(
            zip_bytes([("repeat.bin", b"A" * 2048)], compression=zipfile.ZIP_DEFLATED),
            ScanLimits(max_compression_ratio=2),
        )
        self.assertIn("ARCHIVE_MEMBER_SIZE_LIMIT", codes(large))
        self.assertIn("ARCHIVE_RATIO_LIMIT", codes(ratio))

    def test_archive_total_expanded_size_limit(self) -> None:
        data = zip_bytes([("a.bin", b"a" * 8), ("b.bin", b"b" * 8)])
        result = self._scan_zip(data, ScanLimits(max_archive_uncompressed_bytes=10))
        self.assertIn("ARCHIVE_TOTAL_SIZE_LIMIT", codes(result))

    def test_archive_traversal_is_reported_and_never_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "malformed-name.zip"
            path.write_bytes(zip_bytes([("../outside.txt", b"safe test marker")]))
            result = Scanner().scan(path)
            self.assertFalse((root.parent / "outside.txt").exists())
        self.assertIn("ARCHIVE_PATH_TRAVERSAL", codes(result))
        self.assertTrue(any(f.path.endswith("../outside.txt") for f in result.findings))

    def test_corrupt_zip_signature_is_not_silently_accepted(self) -> None:
        result = self._scan_zip(b"PK\x03\x04not-a-valid-zip")
        self.assertIn("CORRUPT_ARCHIVE", codes(result))

    def test_nested_archive_depth_is_bounded(self) -> None:
        inner = zip_bytes([("note.txt", b"safe")])
        outer = zip_bytes([("inner.zip", inner)])
        result = self._scan_zip(outer, ScanLimits(max_archive_depth=1))
        self.assertIn("ARCHIVE_NESTING_LIMIT", codes(result))

    def test_total_byte_budget_skips_archive_member_before_read(self) -> None:
        archive = zip_bytes([("member.txt", b"x" * 16)])
        result = self._scan_zip(archive, ScanLimits(max_total_bytes=len(archive) + 8))
        self.assertIn("TOTAL_SCAN_BYTE_LIMIT", codes(result))
        self.assertEqual(result.bytes_scanned, len(archive))

    def test_archive_budget_does_not_read_more_than_remaining_bytes(self) -> None:
        data = zip_bytes([("member.bin", b"z" * 12)])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "bounded.zip"
            path.write_bytes(data)
            result = Scanner(ScanLimits(max_total_bytes=len(data) + 4)).scan(path)
        self.assertEqual(result.bytes_scanned, len(data))
        self.assertIn("TOTAL_SCAN_BYTE_LIMIT", codes(result))
