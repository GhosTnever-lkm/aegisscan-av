# Changelog

## 0.1.3 - 2026-10-13

- Close the file-replacement race by opening without following links and verifying the opened file identity before reading; changed or linked files are skipped and make the scan incomplete.
- When ClamAV is enabled, scan bounded temporary snapshots of the exact bytes AegisScan read, rather than reopening source paths. Temporary snapshots are removed after ClamAV finishes.
- Added regression tests for path replacement, stable ClamAV input, and snapshot cleanup.

## 0.1.2 - 2026-10-11

- Fixed all ruff lint findings (import order, unused import, regex flags, nested `with` statements); `ruff check .` is now clean.
- Invalid signature database root now raises `TypeError` instead of `ValueError`.
- Verified locally with 60 synthetic tests; no behavior change in scanning.

## 0.1.1 - 2026-10-11

- Reject targets whose user-supplied path contains a symbolic link or Windows reparse point before resolving or reading the target.
- Added coverage for symlinked target ancestors, junction/reparse-point guards, and canonical temporary paths across platforms.
- Verified locally with 60 synthetic tests and 90% branch coverage; no malware samples are included.

## 0.1.0 - 2026-10-11

- Initial local-first defensive scanner: SHA-256 signature database, bounded file/tree/ZIP inspection, explainable static indicators, JSON/text reports, and optional YARA/ClamAV integrations.
- Read-only scanning by default: never executes scanned content, follows symlinks, deletes, or quarantines files.
- Verified locally with 56 synthetic tests and 90% branch coverage; includes CI across supported Python versions and operating systems.
