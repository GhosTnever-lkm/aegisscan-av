from __future__ import annotations

import json

from .models import ScanResult

_INCOMPLETE_CODES = {
    "CLAMAV_TIMEOUT",
    "CLAMAV_ERROR",
    "CLAMAV_PARTIAL_SCAN",
    "YARA_SCAN_ERROR",
    "CORRUPT_ARCHIVE",
    "SPECIAL_FILE_SKIPPED",
    "SYMLINK_SKIPPED",
    "JUNCTION_SKIPPED",
    "DIRECTORY_CYCLE",
    "DIRECTORY_ESCAPE",
}


def scan_incomplete(result: ScanResult) -> bool:
    return (
        bool(result.errors)
        or result.files_skipped > 0
        or any(
            finding.code in _INCOMPLETE_CODES or finding.code.endswith("_LIMIT")
            for finding in result.findings
        )
    )


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=True, indent=2) + "\n"


def render_text(result: ScanResult) -> str:
    status = (
        "SCAN INCOMPLETE"
        if scan_incomplete(result)
        else "REVIEW REQUIRED"
        if result.has_warnings
        else "NO INDICATORS FOUND"
    )
    lines = [
        f"AegisScan — {status}",
        f"Target: {result.target}",
        f"Files scanned: {result.files_scanned}; skipped: {result.files_skipped}; bytes read: {result.bytes_scanned}",
    ]
    if result.findings:
        lines.append("Findings:")
        for finding in result.findings:
            lines.append(f"  {finding.severity.name:<8} {finding.code:<28} {finding.path} — {finding.message}")
    if result.errors:
        lines.append("Errors:")
        lines.extend(f"  {error}" for error in result.errors)
    lines.append("Note: indicators are triage signals, not a guarantee that a file is malicious or clean.")
    return "\n".join(lines) + "\n"


def exit_code(result: ScanResult, fail_on_warning: bool = False) -> int:
    if scan_incomplete(result):
        return 2
    if result.has_high_risk or (fail_on_warning and result.has_warnings):
        return 1
    return 0
