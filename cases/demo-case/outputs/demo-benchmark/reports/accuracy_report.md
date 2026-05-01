# SIFT Sentinel Accuracy Report

## Summary

- Precision: `1.0`
- Recall: `1.0`
- F1: `1.0`
- Hallucinated confirmed findings: `0`
- False positives: `0`
- Missed truth items: `0`

## Evidence Integrity

All confirmed findings include structured evidence references tied to specific tool call IDs. The policy layer denies writes under the evidence root and allows output only below the case output directory.

## Ground Truth Coverage

- `GT-001` hit: Masqueraded winupdate.exe performed external C2 and contained injected executable memory
- `GT-002` hit: HKCU Run key persisted SyncCache.dll through rundll32.exe
- `GT-003` hit: Encoded PowerShell staged or executed winupdate.exe

## Refuted Leads

F-002
