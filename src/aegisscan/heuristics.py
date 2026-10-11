from __future__ import annotations

import re

from .models import Finding, Severity
from .safety import display_safe

# These are static indicators, not proof that a file is malicious.
_RULES: tuple[tuple[str, Severity, str, re.Pattern[bytes]], ...] = (
    (
        "POWERSHELL_ENCODED_COMMAND",
        Severity.MEDIUM,
        "Encoded PowerShell command pattern; review the script before running it.",
        re.compile(rb"powershell(?:\.exe)?[^\r\n]{0,120}-(?:enc|encodedcommand)\b", re.I),
    ),
    (
        "SCRIPT_BASE64_DECODER",
        Severity.LOW,
        "Script contains a base64 decoder reference; this can be legitimate but merits review.",
        re.compile(rb"frombase64string\s*\(|(?:b64decode|base64\.decode)\s*\(", re.I),
    ),
    (
        "PROCESS_INJECTION_API",
        Severity.MEDIUM,
        "Process-injection API name found in static content; no code was executed.",
        re.compile(rb"(?:createremotethread|virtualallocex|writeprocessmemory)", re.I),
    ),
    (
        "SCRIPT_DOWNLOAD_AND_EXECUTE",
        Severity.MEDIUM,
        "A download-and-execute pattern was found in static content.",
        re.compile(rb"(?:downloadstring|urlmon|urldownloadtofile)[^\r\n]{0,160}(?:invoke-expression|iex|start-process)", re.I),
    ),
    (
        "WINDOWS_SCRIPT_HOST_AUTOMATION",
        Severity.LOW,
        "Windows Script Host automation reference; verify the file's intended behavior.",
        re.compile(rb"wscript\.shell|scripting\.filesystemobject", re.I),
    ),
)


def inspect_bytes(path: str, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    for code, severity, message, pattern in _RULES:
        if pattern.search(data):
            findings.append(
                Finding(
                    path=display_safe(path),
                    code=code,
                    severity=severity,
                    engine="heuristics",
                    message=message,
                )
            )
    return findings
