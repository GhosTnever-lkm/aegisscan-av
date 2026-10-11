from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import ScanLimits
from .engines import ClamAVEngine, YaraEngine
from .report import exit_code, render_json, render_text
from .scanner import Scanner
from .signatures import SignatureDatabase


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Local-first defensive file scanner. Scanned content is never executed.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan one file or a directory")
    scan.add_argument("target", type=Path)
    scan.add_argument("--signatures", type=Path, help="local JSON SHA-256 signature database")
    scan.add_argument("--yara-rules", type=Path, help="local YARA rules (requires the yara extra)")
    scan.add_argument("--clamav", action="store_true", help="also run the installed clamscan engine on each regular file")
    scan.add_argument("--json-out", type=Path, help="write a JSON report to this path")
    scan.add_argument("--max-files", type=int, default=10_000)
    scan.add_argument("--max-depth", type=int, default=20)
    scan.add_argument("--max-directories", type=int, default=10_000)
    scan.add_argument("--max-entries", type=int, default=100_000)
    scan.add_argument("--max-file-mib", type=int, default=32)
    scan.add_argument("--max-total-mib", type=int, default=512)
    scan.add_argument("--max-archive-entries", type=int, default=2_000)
    scan.add_argument("--max-member-mib", type=int, default=16)
    scan.add_argument("--max-archive-mib", type=int, default=128)
    scan.add_argument("--max-archive-depth", type=int, default=3)
    scan.add_argument("--max-compression-ratio", type=int, default=200)
    scan.add_argument("--fail-on-warning", action="store_true", help="return exit code 1 for any warning/indicator")
    return parser


def _mib(value: int, option: str) -> int:
    if value <= 0:
        raise ValueError(f"{option} must be greater than zero")
    return value * 1024 * 1024


def run(args: argparse.Namespace) -> int:
    try:
        signature_db = SignatureDatabase.load(args.signatures) if args.signatures else SignatureDatabase()
        limits = ScanLimits(
            max_files=args.max_files,
            max_depth=args.max_depth,
            max_directories=args.max_directories,
            max_entries=args.max_entries,
            max_file_bytes=_mib(args.max_file_mib, "--max-file-mib"),
            max_total_bytes=_mib(args.max_total_mib, "--max-total-mib"),
            max_archive_depth=args.max_archive_depth,
            max_archive_entries=args.max_archive_entries,
            max_archive_member_bytes=_mib(args.max_member_mib, "--max-member-mib"),
            max_archive_uncompressed_bytes=_mib(args.max_archive_mib, "--max-archive-mib"),
            max_compression_ratio=args.max_compression_ratio,
        )
        byte_engines = [YaraEngine(args.yara_rules)] if args.yara_rules else []
        clamav = (
            ClamAVEngine(
                max_file_bytes=limits.max_file_bytes,
                max_scan_bytes=limits.max_archive_uncompressed_bytes,
                max_files=limits.max_archive_entries,
                max_recursion=limits.max_archive_depth,
            )
            if args.clamav
            else None
        )
        result = Scanner(limits, signature_db, byte_engines, clamav).scan(args.target)
    except (ValueError, RuntimeError) as exc:
        print(f"aegis: {exc}", file=sys.stderr)
        return 2

    print(render_text(result), end="")
    if args.json_out:
        try:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(render_json(result), encoding="utf-8")
        except OSError as exc:
            print(f"aegis: cannot write report: {exc}", file=sys.stderr)
            return 2
    return exit_code(result, args.fail_on_warning)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "scan":
        raise SystemExit(run(args))
    parser.error("unknown command")


if __name__ == "__main__":
    main()
