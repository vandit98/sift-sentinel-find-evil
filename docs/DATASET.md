# Dataset Documentation

## Dataset

`cases/demo-case` is a synthetic DFIR case created for this project. It contains no real victim data, credentials, malware, or private network information.

The fixture models a Windows workstation intrusion across multiple evidence sources:

| Artifact | File | Purpose |
|---|---|---|
| Memory process list | `evidence/memory/processes.csv` | Process tree, image paths, command lines |
| Memory network list | `evidence/memory/netstat.csv` | Process to remote connection mapping |
| Memory malfind output | `evidence/memory/malfind.csv` | Executable private memory region evidence |
| Prefetch | `evidence/disk/prefetch.csv` | Execution lead generation |
| Amcache | `evidence/disk/amcache.csv` | Binary provenance and hashes |
| Timeline | `evidence/disk/timeline.csv` | File creation and registry activity |
| Event logs | `evidence/disk/evtx_security.csv` | Process creation command lines |
| Registry Run keys | `evidence/disk/registry_run_keys.csv` | Persistence mechanism |
| PCAP summary | `evidence/network/pcap_summary.csv` | Network corroboration |

## Ground Truth

Ground truth is documented in `cases/demo-case/ground_truth.json`.

Confirmed truth items:

- `GT-001`: `winupdate.exe` performed external C2 and contained injected executable memory.
- `GT-002`: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\AcmeSync` persisted `SyncCache.dll` through `rundll32.exe`.
- `GT-003`: Encoded PowerShell staged or executed `winupdate.exe`.

Intentional trap:

- `TRAP-001`: `C:\Users\Public\svchost.exe` appears in Prefetch but lacks Amcache or timeline support. The agent should not confirm it.

## Reproducibility

Run:

```bash
PYTHONPATH=src python3 -m sift_sentinel benchmark \
  --case cases/demo-case/case.json \
  --run-id demo-benchmark \
  --max-iterations 3
```

Outputs:

- `cases/demo-case/outputs/demo-benchmark/analysis/execution_log.jsonl`
- `cases/demo-case/outputs/demo-benchmark/analysis/evidence_integrity.json`
- `cases/demo-case/outputs/demo-benchmark/analysis/evidence_manifest_before.json`
- `cases/demo-case/outputs/demo-benchmark/analysis/evidence_manifest_after.json`
- `cases/demo-case/outputs/demo-benchmark/reports/findings.json`
- `cases/demo-case/outputs/demo-benchmark/reports/triage_report.md`
- `cases/demo-case/outputs/demo-benchmark/reports/accuracy_report.md`
