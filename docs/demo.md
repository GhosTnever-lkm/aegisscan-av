# Safe synthetic demo

This example uses an inert text fixture that contains no executable payload. The heuristic reports a review indicator, not a malware verdict.

```text
$ printf '%s\n' 'powershell -EncodedCommand example' > harmless-fixture.txt
$ aegis scan harmless-fixture.txt
AegisScan — REVIEW REQUIRED
Target: harmless-fixture.txt
Files scanned: 1; skipped: 0; bytes read: 34
Findings:
  MEDIUM   POWERSHELL_ENCODED_COMMAND  harmless-fixture.txt — Encoded PowerShell command pattern; review the script before running it.
Note: indicators are triage signals, not a guarantee that a file is malicious or clean.
```

For a clean file, the output says `NO INDICATORS FOUND`. That result is not proof of safety.
