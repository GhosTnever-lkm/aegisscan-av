from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScanLimits:
    max_files: int = 10_000
    max_depth: int = 20
    max_directories: int = 10_000
    max_entries: int = 100_000
    max_file_bytes: int = 32 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024
    max_archive_depth: int = 3
    max_archive_entries: int = 2_000
    max_archive_member_bytes: int = 16 * 1024 * 1024
    max_archive_uncompressed_bytes: int = 128 * 1024 * 1024
    max_compression_ratio: int = 200

    def __post_init__(self) -> None:
        for name in (
            "max_files",
            "max_depth",
            "max_directories",
            "max_entries",
            "max_file_bytes",
            "max_total_bytes",
            "max_archive_entries",
            "max_archive_member_bytes",
            "max_archive_uncompressed_bytes",
            "max_compression_ratio",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be greater than zero")
        if self.max_archive_depth < 0:
            raise ValueError("max_archive_depth cannot be negative")
