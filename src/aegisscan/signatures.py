from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

_HASH = re.compile(r"^[0-9a-fA-F]{64}$")


class SignatureDatabase:
    """An explicit local SHA-256 allowlist of known-bad file digests."""

    def __init__(self, signatures: dict[str, str] | None = None) -> None:
        normalized: dict[str, str] = {}
        for digest, label in (signatures or {}).items():
            if not isinstance(digest, str) or not _HASH.fullmatch(digest):
                raise ValueError(f"invalid SHA-256 signature: {digest!r}")
            if not isinstance(label, str) or not label.strip():
                raise ValueError("signature labels must be non-empty strings")
            normalized[digest.lower()] = label.strip()
        self._signatures = normalized

    @classmethod
    def load(cls, path: Path) -> "SignatureDatabase":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read signature database: {exc}") from exc
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            raise ValueError("signature database requires schema_version: 1")
        signatures = data.get("sha256")
        if not isinstance(signatures, dict):
            raise ValueError("signature database requires an object named 'sha256'")
        return cls(signatures)

    def lookup(self, digest: str) -> str | None:
        return self._signatures.get(digest.lower())

    def __len__(self) -> int:
        return len(self._signatures)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
