from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from aegisscan.safety import display_safe, unsafe_archive_path
from aegisscan.signatures import SignatureDatabase, sha256_hex


class SignatureDatabaseTests(unittest.TestCase):
    def test_lookup_normalizes_digest_case(self) -> None:
        digest = hashlib.sha256(b"synthetic harmless marker").hexdigest()
        database = SignatureDatabase({digest.upper(): "test-fixture"})
        self.assertEqual(database.lookup(digest), "test-fixture")
        self.assertEqual(len(database), 1)

    def test_invalid_digest_and_empty_label_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            SignatureDatabase({"not-a-digest": "sample"})
        with self.assertRaises(ValueError):
            SignatureDatabase({"0" * 64: " "})

    def test_load_requires_versioned_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "signatures.json"
            path.write_text(json.dumps({"schema_version": 1, "sha256": {"0" * 64: "sample"}}))
            database = SignatureDatabase.load(path)
            self.assertEqual(database.lookup("0" * 64), "sample")
            path.write_text('{"sha256": {}}')
            with self.assertRaises(ValueError):
                SignatureDatabase.load(path)

    def test_display_safe_escapes_control_and_format_characters(self) -> None:
        self.assertEqual(display_safe("line\nbidi\u202e.txt"), r"line\u000abidi\u202e.txt")

    def test_archive_path_guard_rejects_absolute_and_parent_traversal(self) -> None:
        for name in ("../outside.txt", "/rooted.txt", "C:\\windows\\file.exe", "//server/share"):
            with self.subTest(name=name):
                self.assertTrue(unsafe_archive_path(name))
        self.assertFalse(unsafe_archive_path("mods/example/readme.txt"))

    def test_sha256_helper(self) -> None:
        self.assertEqual(sha256_hex(b"abc"), hashlib.sha256(b"abc").hexdigest())
