# Security policy

AegisScan is a defensive, local-first file scanner. It never executes scanned content and does not delete, repair, upload, or quarantine files. Target path components are checked before resolution; symbolic links and reparse points are rejected. Archive members are inspected in memory with explicit size, count, depth, and compression-ratio bounds.

## Reporting a scanner vulnerability

Do not attach malware samples or secrets to a public issue. Report suspected vulnerabilities through GitHub Security Advisories for this repository when available; otherwise open a minimal issue that does not include harmful payloads or private data.

## Important limitation

AegisScan is an early-stage scanner and cannot guarantee detection or cleanliness. Keep an up-to-date, reputable endpoint-protection product enabled. Static indicators may be false positives; verify findings with a trusted engine and incident-response process.
