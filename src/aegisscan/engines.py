from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Protocol

from .models import Finding, Severity
from .safety import display_safe


class ByteEngine(Protocol):
    name: str

    def scan_bytes(self, path: str, data: bytes) -> list[Finding]: ...


class YaraEngine:
    """Optional yara-python adapter using user-supplied local rules."""

    name = "yara"

    def __init__(self, rules_path: Path) -> None:
        try:
            import yara  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("YARA support requires `pip install aegisscan-av[yara]`") from exc
        try:
            self._rules = yara.compile(filepath=str(rules_path))
        except Exception as exc:  # yara exposes several parser-specific exception types
            raise ValueError(f"cannot compile YARA rules ({type(exc).__name__})") from exc

    def scan_bytes(self, path: str, data: bytes) -> list[Finding]:
        try:
            matches = self._rules.match(data=data)
        except Exception as exc:
            return [
                Finding(
                    display_safe(path),
                    "YARA_SCAN_ERROR",
                    Severity.MEDIUM,
                    self.name,
                    f"YARA failed ({type(exc).__name__}); this content is not confirmed clean.",
                )
            ]
        return [
            Finding(
                path=display_safe(path),
                code="YARA_MATCH",
                severity=Severity.HIGH,
                engine=self.name,
                message=f"Matched local YARA rule {display_safe(str(match.rule))!r}.",
            )
            for match in matches
        ]


class ClamAVEngine:
    """Optional read-only clamscan adapter using bounded batches."""

    name = "clamav"

    def __init__(
        self,
        executable: str = "clamscan",
        timeout_seconds: int = 45,
        max_file_bytes: int = 32 * 1024 * 1024,
        max_scan_bytes: int = 128 * 1024 * 1024,
        max_files: int = 2_000,
        max_recursion: int = 3,
    ) -> None:
        resolved = shutil.which(executable)
        if not resolved:
            raise RuntimeError(f"ClamAV executable not found: {executable}")
        if min(timeout_seconds, max_file_bytes, max_scan_bytes, max_files) <= 0:
            raise ValueError("ClamAV time and scan limits must be greater than zero")
        if max_recursion < 0:
            raise ValueError("ClamAV recursion limit cannot be negative")
        self.executable = resolved
        self.timeout_seconds = timeout_seconds
        self.max_file_bytes = max_file_bytes
        self.max_scan_bytes = max_scan_bytes
        self.max_files = max_files
        self.max_recursion = max_recursion

    def scan_path(self, path: Path, display_path: str) -> list[Finding]:
        return self.scan_paths([(path, display_path)])

    def scan_paths(self, paths: list[tuple[Path, str]]) -> list[Finding]:
        findings: list[Finding] = []
        for batch in self._batches(paths):
            findings.extend(self._scan_batch(batch))
        return findings

    def _batches(self, paths: list[tuple[Path, str]]) -> list[list[tuple[Path, str]]]:
        batches: list[list[tuple[Path, str]]] = []
        current: list[tuple[Path, str]] = []
        size = len(self.executable) + 200
        for item in paths:
            item_size = len(str(item[0])) + 1
            if current and (len(current) >= 48 or size + item_size > 12_000):
                batches.append(current)
                current = []
                size = len(self.executable) + 200
            current.append(item)
            size += item_size
        if current:
            batches.append(current)
        return batches

    @staticmethod
    def _path_key(value: str) -> str:
        return os.path.normcase(os.path.normpath(os.path.abspath(value.strip("\"'"))))

    def _scan_batch(self, batch: list[tuple[Path, str]]) -> list[Finding]:
        if not batch:
            return []
        relative_target = display_safe(batch[0][1])
        command = [
            self.executable,
            "--no-summary",
            "--infected",
            f"--max-filesize={self.max_file_bytes}",
            f"--max-scansize={self.max_scan_bytes}",
            f"--max-files={self.max_files}",
            f"--max-recursion={self.max_recursion}",
            *(str(path) for path, _ in batch),
        ]
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return [Finding(relative_target, "CLAMAV_TIMEOUT", Severity.MEDIUM, self.name, f"ClamAV timed out for a batch of {len(batch)} files; its results are incomplete.")]
        except OSError as exc:
            return [Finding(relative_target, "CLAMAV_ERROR", Severity.MEDIUM, self.name, f"ClamAV could not scan a batch ({type(exc).__name__}); its results are incomplete.")]

        output = "\n".join(part for part in (result.stdout, result.stderr) if part)
        path_by_key = {
            self._path_key(str(path)): display_safe(display)
            for path, display in batch
        }
        has_partial = any(
            token in line.casefold()
            for line in output.splitlines()
            for token in ("skipping", "scan limit", "max file", "limit reached")
        )
        detections: list[Finding] = []
        unmapped_detection = False
        for line in output.splitlines():
            if not line.rstrip().endswith("FOUND"):
                continue
            raw_path, separator, raw_label = line.rpartition(": ")
            label = raw_label.removesuffix(" FOUND").strip() if separator else ""
            display = path_by_key.get(self._path_key(raw_path)) if separator else None
            if display is None:
                unmapped_detection = True
                continue
            detections.append(
                Finding(
                    display,
                    "CLAMAV_DETECTION",
                    Severity.CRITICAL,
                    self.name,
                    f"ClamAV reported {display_safe(label or 'a detection')!r}; file was not modified.",
                )
            )
        if detections:
            if unmapped_detection:
                detections.append(
                    Finding(relative_target, "CLAMAV_UNMAPPED_DETECTION", Severity.CRITICAL, self.name, "ClamAV reported a detection that could not be mapped to one input path.")
                )
            if has_partial:
                detections.append(
                    Finding(
                        relative_target,
                        "CLAMAV_PARTIAL_SCAN",
                        Severity.MEDIUM,
                        self.name,
                        f"ClamAV also reported a scan limit in a batch of {len(batch)} files.",
                    )
                )
            return detections
        if unmapped_detection:
            return [Finding(relative_target, "CLAMAV_UNMAPPED_DETECTION", Severity.CRITICAL, self.name, "ClamAV reported a detection that could not be mapped to one input path.")]
        if has_partial:
            return [
                Finding(
                    relative_target,
                    "CLAMAV_PARTIAL_SCAN",
                    Severity.MEDIUM,
                    self.name,
                    f"ClamAV reported a scan limit in a batch of {len(batch)} files; these results are incomplete.",
                )
            ]
        if result.returncode == 0:
            return []
        return [
            Finding(
                relative_target,
                "CLAMAV_ERROR",
                Severity.MEDIUM,
                self.name,
                f"ClamAV exited with status {result.returncode} for a batch of {len(batch)} files; its results are incomplete.",
            )
        ]
