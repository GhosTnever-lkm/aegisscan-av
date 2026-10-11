# AegisScan AV

**Local-first malware triage for files and archives.** AegisScan combines a user-managed SHA-256 signature list, explainable static indicators, bounded ZIP inspection, and optional YARA / ClamAV engines. It never executes scanned content.

> **Honest scope:** AegisScan is an early-stage defensive scanner, not a replacement for Microsoft Defender, ClamAV, or a managed endpoint-protection product. It cannot guarantee that a file is clean. The bundled heuristics are indicators for review, not malware verdicts.

[![CI](https://github.com/GhosTnever-lkm/aegisscan-av/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/GhosTnever-lkm/aegisscan-av/actions/workflows/ci.yml) [![Version](https://img.shields.io/badge/version-0.1.1-blue)](CHANGELOG.md) [![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## For whom

- People who want a read-only local triage report before opening an unfamiliar download.
- Mod makers and tool authors checking releases without uploading private builds.
- Developers who want consistent static findings in local review or CI.

## What it does

- Rejects targets reached through symbolic links or Windows reparse points; during tree scans it never follows symbolic links or junctions and reports unreadable paths instead of silently skipping them.
- Matches exact SHA-256 signatures from a local JSON database.
- Flags a small set of explainable script/process indicators; it does not infer that a file is malicious from a single generic string.
- Inspects ZIP entries in memory—never extracts them—and bounds entry count, file size, total scan bytes, nesting depth, and compression ratio.
- Detects archive path traversal attempts and still safely scans the member bytes without writing them to disk.
- Supports optional local YARA rules (`yara-python`) and an installed ClamAV `clamscan` engine.
- Produces a readable terminal summary and optional JSON report with relative paths and safely escaped control characters.

## Quick start

```bash
git clone https://github.com/GhosTnever-lkm/aegisscan-av.git
cd aegisscan-av
python -m pip install .
aegis scan ./downloads --json-out reports/scan.json
```

Use a local hash list:

```bash
aegis scan ./candidate.zip --signatures rules/signatures.json --fail-on-warning
```

The expected signature file format is shown in [`rules/signatures.example.json`](rules/signatures.example.json). Empty by default: AegisScan does not ship a pretend or unmaintained malware database.

Optional YARA and ClamAV engines:

```bash
python -m pip install '.[yara]'
aegis scan ./candidate.zip --yara-rules ./my-local-rules.yar --clamav
```

YARA rules are supplied by you; ClamAV must be installed separately and its definitions kept current with its own supported tools. AegisScan does not download feeds or execute scanned files.

## Three workflows

1. **Before opening a download:** scan the file or containing folder and inspect the terminal summary.
2. **Before a mod/tool release:** scan the staged folder or ZIP, then attach the JSON report to your internal release checklist.
3. **In CI:** install AegisScan, run `aegis scan ./dist --json-out artifacts/aegis.json`, and use `--fail-on-warning` only when your policy intentionally treats every indicator as blocking.

## Output and exit codes

- `0`: scan completed without high-risk findings (warnings may be present unless `--fail-on-warning` is set).
- `1`: high/critical finding, or any warning with `--fail-on-warning`.
- `2`: configuration/input/report error, optional-engine failure, or an incomplete scan caused by unreadable/skipped content or a safety limit.

Reports omit absolute root paths. Files are read-only; JSON output is written only when you request `--json-out`.

## Limits and safety

Defaults are deliberately bounded: 10,000 files and directories, 100,000 directory entries, depth 20, file size 32 MiB, total scan budget 512 MiB, ZIP entry count 2,000, member size 16 MiB, per-archive expanded size 128 MiB, nesting depth 3, and compression ratio 200. Tune these only for trusted workloads. A skipped or unreadable file is not a clean result.

## Demo

Current local QA: **60 tests passed** with **90% branch coverage**. The repository contains only harmless synthetic fixtures; no malware samples are included. See the [demo output](docs/demo.md) and [architecture / threat model](docs/architecture.md). Run tests locally:

```bash
python -m unittest discover -s tests -v
```

No malware samples are included. Tests exercise safe marker strings, archive limits, traversal names, symlinks, and engine-error handling using temporary files.

## Support / Pro Version

- **Open source:** MIT-licensed CLI and safe scanning core.
- **Pro:** not published yet. Potential next step is an evidence-rich HTML report and policy packs after the free engine is validated; no purchase link exists until the deliverable is ready.
- **Custom work:** request an integration or policy change through [GitHub Issues](https://github.com/GhosTnever-lkm/aegisscan-av/issues/new). No response-time or delivery commitment is implied.

## Development

```bash
python -m pip install -e '.[test]'
coverage run --branch --source=aegisscan -m unittest discover -s tests -v
coverage report --fail-under=80
```

See [CHANGELOG](CHANGELOG.md), [security policy](SECURITY.md), and [contributing guide](CONTRIBUTING.md).
