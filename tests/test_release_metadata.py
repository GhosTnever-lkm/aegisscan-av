from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

from aegisscan import __version__

ROOT = Path(__file__).resolve().parents[1]


class ReleaseMetadataTests(unittest.TestCase):
    def test_package_version_matches_version_file_and_project_metadata(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        version_file = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertEqual(__version__, version_file)
        self.assertEqual(__version__, project["project"]["version"])

    def test_changelog_starts_with_current_release(self) -> None:
        first_entry = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").splitlines()[2]
        self.assertEqual(first_entry, f"## {__version__} - 2026-10-11")
