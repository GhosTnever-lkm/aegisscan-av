# Architecture and threat model

AegisScan is a local triage pipeline. It is intentionally not a background service and does not execute, repair, upload, or quarantine scanned files.

## Scan pipeline

1. **Validate the target path:** reject missing targets and any symbolic link or Windows reparse point in the supplied path before resolving it.
2. **Bound traversal:** enforce file, directory, entry, depth, file-size, and total-byte budgets before reading content.
3. **Read once:** compute a SHA-256 digest and pass the same bounded byte buffer to built-in and optional byte engines.
4. **Inspect archives:** read ZIP members in memory only; never extract. Check path names, entry count, uncompressed size, compression ratio, nesting depth, and cumulative scan budget.
5. **Correlate evidence:** match only user-supplied local hashes, static explanatory indicators, and optional local YARA / ClamAV results.
6. **Report:** emit relative, control-character-escaped paths and JSON or terminal output. A skipped or unreadable object is never described as clean.

## Threats addressed

- ZIP path traversal and malformed/corrupt archives.
- Decompression bombs and excessive nested archives.
- Symbolic-link/reparse-point target paths, discovered junction escapes, and repeated directory targets.
- Very large files, trees, directory-entry counts, and archive-entry counts.
- Terminal/report spoofing using control and Unicode-format characters.
- False confidence from generic static strings: heuristic indicators remain warnings and explain their evidence.

## Out of scope for the initial release

- Real-time filesystem protection, process monitoring, network filtering, memory scanning, exploit prevention, automatic quarantine/removal, cloud reputation, and automatic signature-feed updates.
- A guarantee that a clean report means a file is safe.

## Trust boundaries

YARA rules and SHA-256 labels are user-provided local input. ClamAV is an optional separately installed scanner. AegisScan invokes ClamAV with argument arrays (never a shell), scan limits, and no repair flags. Rules and external-engine output are treated as data, not instructions.
