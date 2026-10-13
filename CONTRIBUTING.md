# Contributing

AegisScan is defensive software. Keep source files unchanged, local-first, bounded, and explainable. Optional engines may use short-lived local snapshots that are removed after the scan.

- Never add real malware samples, payloads, credentials, personal data, or unlicensed rules.
- Add benign synthetic fixtures generated inside temporary directories.
- Preserve the no-execution, no-symlink-following, no-extraction defaults.
- Add tests for malformed archives, resource limits, and false-positive behavior.
- Run `coverage run --branch --source=aegisscan -m unittest discover -s tests -v` and `coverage report --fail-under=80` before submitting.
- Keep changes scoped; update `VERSION` and `CHANGELOG.md` for user-visible releases.
