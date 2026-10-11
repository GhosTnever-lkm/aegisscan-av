from __future__ import annotations

import io
import lzma
import os
import stat
import zipfile
import zlib
from collections.abc import Iterable
from pathlib import Path

from .config import ScanLimits
from .engines import ByteEngine, ClamAVEngine
from .heuristics import inspect_bytes
from .models import Finding, ScanResult, Severity
from .safety import display_safe, unsafe_archive_path
from .signatures import SignatureDatabase, sha256_hex


class Scanner:
    """Read-only filesystem scanner with strict file/archive resource limits."""

    def __init__(
        self,
        limits: ScanLimits | None = None,
        signatures: SignatureDatabase | None = None,
        byte_engines: Iterable[ByteEngine] = (),
        clamav: ClamAVEngine | None = None,
    ) -> None:
        self.limits = limits or ScanLimits()
        self.signatures = signatures or SignatureDatabase()
        self.byte_engines = tuple(byte_engines)
        self.clamav = clamav
        self._result: ScanResult | None = None
        self._root: Path | None = None
        self._clamav_paths: list[tuple[Path, str]] = []

    def scan(self, target: Path) -> ScanResult:
        path = Path(target).expanduser()
        label = display_safe(path.name or ".")
        result = ScanResult(target=label)
        self._result = result
        self._clamav_paths = []
        try:
            if self._contains_linklike_component(path):
                result.files_skipped += 1
                result.findings.append(Finding(label, "SYMLINK_SKIPPED", Severity.INFO, "filesystem", "Symbolic links and reparse points in the target path are never followed."))
                return result
            root = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            detail = getattr(exc, "strerror", None) or type(exc).__name__
            result.errors.append(f"target unavailable: {detail}")
            return result
        self._root = root if root.is_dir() else root.parent
        if root.is_file():
            self._scan_file(root, label)
        elif root.is_dir():
            self._scan_directory(root)
        else:
            result.files_skipped += 1
            result.errors.append("target is not a regular file or directory")
        self._run_clamav()
        return result

    @staticmethod
    def _contains_linklike_component(path: Path) -> bool:
        """Reject links in the user-supplied path before resolving its target."""
        absolute = path if path.is_absolute() else Path.cwd() / path
        current = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            if part == ".":
                continue
            if part == "..":
                current = current.parent
                continue
            current = current / part
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                # Let resolve(strict=True) report a missing target below.
                continue
            if stat.S_ISLNK(metadata.st_mode):
                return True
            is_junction = getattr(current, "is_junction", None)
            if callable(is_junction) and is_junction():
                return True
            attributes = getattr(metadata, "st_file_attributes", 0)
            reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            if attributes & reparse_point:
                return True
        return False

    def _run_clamav(self) -> None:
        assert self._result is not None
        if self.clamav and self._clamav_paths:
            self._result.findings.extend(self.clamav.scan_paths(self._clamav_paths))

    def _scan_directory(self, root: Path) -> None:
        assert self._result is not None
        root_real = root.resolve()
        stack: list[tuple[Path, int]] = [(root, 0)]
        visited: set[Path] = set()
        directories_scanned = 0
        entries_seen = 0
        while stack:
            directory, depth = stack.pop()
            if directories_scanned >= self.limits.max_directories:
                self._limit_finding(
                    self._relative(directory),
                    "DIRECTORY_COUNT_LIMIT",
                    "Maximum directory count reached; remaining directories were skipped.",
                )
                return
            directories_scanned += 1
            try:
                resolved = directory.resolve(strict=True)
                resolved.relative_to(root_real)
            except (OSError, ValueError):
                self._result.files_skipped += 1
                self._result.findings.append(Finding(self._relative(directory), "DIRECTORY_ESCAPE", Severity.HIGH, "filesystem", "Directory resolved outside the selected scan root and was not followed."))
                continue
            if resolved in visited:
                self._result.files_skipped += 1
                self._result.findings.append(Finding(self._relative(directory), "DIRECTORY_CYCLE", Severity.LOW, "filesystem", "Repeated directory target was skipped."))
                continue
            visited.add(resolved)
            if depth > self.limits.max_depth:
                self._limit_finding(self._relative(directory), "DIRECTORY_DEPTH_LIMIT", "Directory depth limit reached.")
                continue
            try:
                with os.scandir(directory) as iterator:
                    entries = []
                    entry_overflow = False
                    for entry in iterator:
                        if entries_seen >= self.limits.max_entries:
                            entry_overflow = True
                            break
                        entries.append(entry)
                        entries_seen += 1
                    entries.sort(key=lambda item: item.name.casefold())
            except OSError as exc:
                self._result.errors.append(
                    f"cannot read {self._relative(directory)}: {exc.strerror or type(exc).__name__}"
                )
                continue
            next_dirs: list[Path] = []
            for entry in entries:
                candidate = Path(entry.path)
                display = self._relative(candidate)
                try:
                    if entry.is_symlink():
                        self._result.files_skipped += 1
                        self._result.findings.append(Finding(display, "SYMLINK_SKIPPED", Severity.INFO, "filesystem", "Symbolic links are never followed."))
                        continue
                    is_junction = getattr(candidate, "is_junction", lambda: False)()
                    if is_junction:
                        self._result.files_skipped += 1
                        self._result.findings.append(Finding(display, "JUNCTION_SKIPPED", Severity.INFO, "filesystem", "Directory junctions are never traversed."))
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        next_dirs.append(candidate)
                    elif entry.is_file(follow_symlinks=False):
                        if self._result.files_scanned >= self.limits.max_files:
                            self._limit_finding(display, "FILE_COUNT_LIMIT", "Maximum file count reached.")
                            return
                        self._scan_file(candidate, display)
                    else:
                        self._result.files_skipped += 1
                        self._result.findings.append(Finding(display, "SPECIAL_FILE_SKIPPED", Severity.INFO, "filesystem", "Non-regular filesystem entry was skipped."))
                except OSError as exc:
                    self._result.errors.append(f"cannot inspect {display}: {exc}")
            stack.extend((child, depth + 1) for child in reversed(next_dirs))
            if entry_overflow:
                self._limit_finding(
                    self._relative(directory),
                    "DIRECTORY_ENTRY_LIMIT",
                    "Maximum total directory entry count reached; remaining entries were skipped.",
                )
                return

    def _relative(self, path: Path) -> str:
        assert self._root is not None
        try:
            value = path.relative_to(self._root).as_posix()
        except ValueError:
            value = path.name
        return display_safe(value or ".")

    def _scan_file(self, path: Path, display: str) -> None:
        assert self._result is not None
        try:
            stat = path.stat(follow_symlinks=False)
            if stat.st_size > self.limits.max_file_bytes:
                self._result.files_skipped += 1
                self._limit_finding(display, "FILE_SIZE_LIMIT", "File exceeds the configured byte limit; contents were not read.")
                return
            remaining = self.limits.max_total_bytes - self._result.bytes_scanned
            if remaining <= 0 or stat.st_size > remaining:
                self._result.files_skipped += 1
                self._limit_finding(display, "TOTAL_SCAN_BYTE_LIMIT", "Total scan byte budget reached; file contents were not analyzed.")
                return
            read_limit = min(self.limits.max_file_bytes, remaining)
            with path.open("rb") as stream:
                data = stream.read(read_limit + 1)
        except OSError as exc:
            self._result.errors.append(
                f"cannot read {display}: {exc.strerror or type(exc).__name__}"
            )
            return
        if len(data) > read_limit:
            self._result.files_skipped += 1
            code = (
                "TOTAL_SCAN_BYTE_LIMIT"
                if remaining <= self.limits.max_file_bytes
                else "FILE_GROWTH_LIMIT"
            )
            self._limit_finding(display, code, "File grew beyond the configured read budget while being read.")
            return
        self._result.files_scanned += 1
        self._result.bytes_scanned += len(data)
        self._scan_bytes(display, data, archive_depth=0)
        if self.clamav:
            self._clamav_paths.append((path, display))

    def _scan_bytes(self, display: str, data: bytes, archive_depth: int) -> None:
        assert self._result is not None
        digest = sha256_hex(data)
        label = self.signatures.lookup(digest)
        if label:
            self._result.findings.append(Finding(display_safe(display), "SHA256_SIGNATURE", Severity.CRITICAL, "local-hash-db", f"Matched local signature {display_safe(label)!r}."))
        self._result.findings.extend(inspect_bytes(display, data))
        for engine in self.byte_engines:
            self._result.findings.extend(engine.scan_bytes(display, data))
        if not data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            return
        if archive_depth >= self.limits.max_archive_depth:
            self._limit_finding(display, "ARCHIVE_NESTING_LIMIT", "Nested archive depth limit reached.")
            return
        self._scan_zip(display, data, archive_depth + 1)

    def _scan_zip(self, display: str, data: bytes, archive_depth: int) -> None:
        assert self._result is not None
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except (zipfile.BadZipFile, OSError, ValueError):
            self._result.findings.append(Finding(display_safe(display), "CORRUPT_ARCHIVE", Severity.MEDIUM, "archive", "ZIP signature found but archive metadata is invalid."))
            return
        with archive:
            infos = archive.infolist()
            if len(infos) > self.limits.max_archive_entries:
                self._limit_finding(display, "ARCHIVE_ENTRY_LIMIT", "Archive entry count exceeds the configured limit; remaining entries were skipped.")
            total_declared = 0
            for info in infos[: self.limits.max_archive_entries]:
                if info.is_dir():
                    continue
                total_declared += max(info.file_size, 0)
                member_display = display_safe(f"{display}!/{info.filename}")
                if unsafe_archive_path(info.filename):
                    self._result.findings.append(Finding(member_display, "ARCHIVE_PATH_TRAVERSAL", Severity.HIGH, "archive", "Archive contains an absolute or parent-traversal path; nothing was extracted."))
                if info.file_size < 0 or info.file_size > self.limits.max_archive_member_bytes:
                    self._result.files_skipped += 1
                    self._limit_finding(member_display, "ARCHIVE_MEMBER_SIZE_LIMIT", "Archive member exceeds the configured uncompressed size limit." )
                    continue
                if total_declared > self.limits.max_archive_uncompressed_bytes:
                    self._result.files_skipped += 1
                    self._limit_finding(display, "ARCHIVE_TOTAL_SIZE_LIMIT", "Archive declared uncompressed size exceeds the configured limit; remaining members were skipped.")
                    break
                ratio = info.file_size / max(info.compress_size, 1)
                if ratio > self.limits.max_compression_ratio:
                    self._result.files_skipped += 1
                    self._limit_finding(member_display, "ARCHIVE_RATIO_LIMIT", "Archive member compression ratio exceeds the configured limit." )
                    continue
                remaining = self.limits.max_total_bytes - self._result.bytes_scanned
                if remaining <= 0 or info.file_size > remaining:
                    self._result.files_skipped += 1
                    self._limit_finding(display, "TOTAL_SCAN_BYTE_LIMIT", "Total scan byte budget reached; remaining archive members were skipped.")
                    break
                if self._result.files_scanned >= self.limits.max_files:
                    self._limit_finding(member_display, "FILE_COUNT_LIMIT", "Maximum total file count reached inside archives.")
                    break
                try:
                    with archive.open(info, "r") as stream:
                        read_limit = min(self.limits.max_archive_member_bytes, remaining)
                        payload = stream.read(read_limit + 1)
                except (
                    OSError,
                    EOFError,
                    RuntimeError,
                    ValueError,
                    NotImplementedError,
                    zipfile.BadZipFile,
                    lzma.LZMAError,
                    zlib.error,
                ) as exc:
                    self._result.errors.append(
                        f"cannot read archive member {member_display}: {type(exc).__name__}"
                    )
                    continue
                if len(payload) > read_limit:
                    self._result.files_skipped += 1
                    code = (
                        "TOTAL_SCAN_BYTE_LIMIT"
                        if remaining <= self.limits.max_archive_member_bytes
                        else "ARCHIVE_MEMBER_READ_LIMIT"
                    )
                    self._limit_finding(member_display, code, "Archive member expanded beyond the configured read limit.")
                    if code == "TOTAL_SCAN_BYTE_LIMIT":
                        break
                    continue
                self._result.files_scanned += 1
                self._result.bytes_scanned += len(payload)
                self._scan_bytes(member_display, payload, archive_depth)

    def _limit_finding(self, path: str, code: str, message: str) -> None:
        assert self._result is not None
        self._result.findings.append(Finding(display_safe(path), code, Severity.LOW, "limits", message))
