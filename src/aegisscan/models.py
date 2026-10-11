from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50


@dataclass(frozen=True, slots=True)
class Finding:
    path: str
    code: str
    severity: Severity
    engine: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "code": self.code,
            "severity": self.severity.name.lower(),
            "engine": self.engine,
            "message": self.message,
        }


@dataclass(slots=True)
class ScanResult:
    target: str
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_high_risk(self) -> bool:
        return any(f.severity >= Severity.HIGH for f in self.findings)

    @property
    def has_warnings(self) -> bool:
        return any(f.severity >= Severity.LOW for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "scanner": "AegisScan",
            "target": self.target,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "bytes_scanned": self.bytes_scanned,
            "finding_count": len(self.findings),
            "errors": self.errors,
            "findings": [finding.to_dict() for finding in self.findings],
        }
