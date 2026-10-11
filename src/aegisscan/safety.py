from __future__ import annotations

import unicodedata
from pathlib import PurePosixPath


def display_safe(value: str) -> str:
    """Escape control/format characters before showing attacker-controlled names."""
    out: list[str] = []
    for char in value:
        category = unicodedata.category(char)
        if category in {"Cc", "Cf", "Cs"}:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    return "".join(out)


def unsafe_archive_path(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return (
        path.is_absolute()
        or any(part == ".." for part in path.parts)
        or normalized.startswith("//")
        or (len(normalized) >= 2 and normalized[1] == ":")
        or "\x00" in normalized
    )
