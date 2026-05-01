# SIFT Sentinel Triage Report: Demo Evil: Workstation Intrusion With Memory Injection

- Case ID: `demo-evil-001`
- Run ID: `demo-benchmark`
- Generated UTC: `2026-04-30T22:36:49Z`
- Confirmed findings: `3`
- Inferred findings: `0`
- Refuted leads: `1`
- Evidence integrity: `ok`

## Executive Summary

SIFT Sentinel confirmed malicious execution, memory injection, external command-and-control, and Run key persistence after iterating through missing evidence checks.

## Confirmed Findings

### F-001: Winupdate.exe beacon with memory injection evidence

- Severity: `critical`
- Status: `confirmed`
- Confidence: `0.94`
- Hypothesis: A masqueraded winupdate.exe process communicated externally and contains injected executable memory.
- MITRE: `T1055, T1036, T1071`

Evidence:
- `memory_netstat` row 2 `remote_ip` = `45.77.89.22` via `memory_netstat-04c13142bb`
- `memory_processes` row 4 `image_path` = `C:\Users\Public\winupdate.exe` via `memory_processes-ac4e76654e`
- `disk_prefetch` row 1 `path` = `C:\Users\Public\winupdate.exe` via `disk_prefetch-06ba450501`
- `memory_malfind` row 1 `protection` = `PAGE_EXECUTE_READWRITE` via `memory_malfind-181d7a5a57`
- `disk_amcache` row 1 `sha1` = `6F1D7B81C0FF1DAA2D7C9CE9E6FAE7D2C2F40111` via `disk_amcache-a154eeef07`
- `disk_timeline` row 1 `event` = `FileCreate` via `disk_timeline-1d6aa8f234`

Notes:
- `malfind`: Private VAD contains MZ header and shellcode-like strings; not backed by image file
- `pid`: 4884
- `remote_ip`: 45.77.89.22
- `remote_port`: 443
- `self_correction`: Confirmed after adding malfind, Amcache, and disk timeline evidence.
- `sha1`: 6F1D7B81C0FF1DAA2D7C9CE9E6FAE7D2C2F40111

### F-004: Encoded PowerShell staged winupdate.exe

- Severity: `high`
- Status: `confirmed`
- Confidence: `0.88`
- Hypothesis: PowerShell launched an encoded command that staged or executed winupdate.exe.
- MITRE: `T1059.001, T1105`

Evidence:
- `windows_events` row 1 `command_line` = `powershell.exe -NoP -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA7 Start-Process C:\Users\Public\winupdate.exe` via `windows_events-63e32b26a0`
- `memory_processes` row 3 `command_line` = `powershell.exe -NoP -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA7 Start-Process C:\Users\Public\winupdate.exe` via `memory_processes-ac4e76654e`
- `disk_timeline` row 1 `path` = `C:\Users\Public\winupdate.exe` via `disk_timeline-1d6aa8f234`

Notes:
- `self_correction`: Confirmed after process and timeline corroboration.
- `user`: ACME\jlee

### F-003: Run key persistence loads SyncCache.dll via rundll32

- Severity: `high`
- Status: `confirmed`
- Confidence: `0.91`
- Hypothesis: A user Run key persists a suspicious DLL through rundll32.exe.
- MITRE: `T1112, T1218.011, T1547.001`

Evidence:
- `windows_events` row 2 `command_line` = `rundll32.exe C:\ProgramData\AcmeCache\SyncCache.dll,Start` via `windows_events-63e32b26a0`
- `disk_timeline` row 3 `path` = `C:\ProgramData\AcmeCache\SyncCache.dll` via `disk_timeline-1d6aa8f234`
- `registry_run_keys` row 1 `value_data` = `rundll32.exe C:\ProgramData\AcmeCache\SyncCache.dll,Start` via `registry_run_keys-9473f7c59e`

Notes:
- `self_correction`: Confirmed only after registry Run key evidence was collected.


## Inferred Or Refuted Leads

### F-002: Uncorroborated svchost.exe path anomaly

- Severity: `medium`
- Status: `refuted`
- Confidence: `0.08`
- Hypothesis: Prefetch references svchost.exe outside System32, but this requires corroboration before reporting.
- MITRE: `T1036`

Evidence:
- `disk_prefetch` row 2 `path` = `C:\Users\Public\svchost.exe` via `disk_prefetch-06ba450501`

Notes:
- `path`: C:\Users\Public\svchost.exe
- `self_correction`: Self-corrected: no Amcache or timeline record for the suspicious path, so this stays out of confirmed findings.


## Self-Correction And Validation

### VAL-001: External callback needs binary and memory corroboration

- Severity: `high`
- Finding: `F-001`
- Required action: `memory_malfind, disk_amcache, disk_timeline`
- Reason: Network evidence alone can misattribute a process; require injection, hash, and file timeline evidence.

### VAL-002: Svchost masquerade lead is single-source

- Severity: `medium`
- Finding: `F-002`
- Required action: `disk_amcache, disk_timeline`
- Reason: A Prefetch-only path anomaly is not enough for a confirmed report.

### VAL-003: Rundll32 execution needs persistence mechanism validation

- Severity: `high`
- Finding: `F-003`
- Required action: `registry_run_keys`
- Reason: Execution is not persistence until an ASEP or service mechanism is proven.


## Evidence Integrity

Pre-run and post-run evidence manifests match. No configured evidence artifact changed.

- Before artifacts: `9`
- After artifacts: `9`
- Changed: `0`
- Missing: `0`
- Added: `0`

## Tool Execution Audit

- `case_manifest` `case_manifest-d43587a2b5`: ok; rows=0; started=2026-04-30T22:36:49Z; ended=2026-04-30T22:36:49Z
- `disk_amcache` `disk_amcache-a154eeef07`: ok; rows=3; started=2026-04-30T22:36:49Z; ended=2026-04-30T22:36:49Z
- `disk_prefetch` `disk_prefetch-06ba450501`: ok; rows=3; started=2026-04-30T22:36:49Z; ended=2026-04-30T22:36:49Z
- `disk_timeline` `disk_timeline-1d6aa8f234`: ok; rows=4; started=2026-04-30T22:36:49Z; ended=2026-04-30T22:36:49Z
- `memory_malfind` `memory_malfind-181d7a5a57`: ok; rows=1; started=2026-04-30T22:36:49Z; ended=2026-04-30T22:36:49Z
- `memory_netstat` `memory_netstat-04c13142bb`: ok; rows=3; started=2026-04-30T22:36:49Z; ended=2026-04-30T22:36:49Z
- `memory_processes` `memory_processes-ac4e76654e`: ok; rows=5; started=2026-04-30T22:36:49Z; ended=2026-04-30T22:36:49Z
- `registry_run_keys` `registry_run_keys-9473f7c59e`: ok; rows=1; started=2026-04-30T22:36:49Z; ended=2026-04-30T22:36:49Z
- `windows_events` `windows_events-63e32b26a0`: ok; rows=3; started=2026-04-30T22:36:49Z; ended=2026-04-30T22:36:49Z
