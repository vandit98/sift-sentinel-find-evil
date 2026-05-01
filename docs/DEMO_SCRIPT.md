# Five-Minute Demo Video Script

## 0:00 - 0:30 Problem

"AI attackers move in minutes. SIFT Sentinel gives Protocol SIFT an evidence-safe autonomous execution layer so the defender can respond in seconds without trusting prompt guardrails alone."

## 0:30 - 1:15 Architecture

Show `docs/images/architecture.mmd` or the README Mermaid diagram.

Key line: "The model never gets a shell. It gets typed tools, and the code enforces read-only evidence."

## 1:15 - 2:15 Live Run

Command:

```bash
PYTHONPATH=src python3 -m sift_sentinel benchmark \
  --case cases/demo-case/case.json \
  --run-id video-demo \
  --max-iterations 3
```

Show the benchmark JSON: precision, recall, F1, hallucination count.

## 2:15 - 2:45 Evidence Integrity

Open:

```bash
cat cases/demo-case/outputs/video-demo/analysis/evidence_integrity.json
```

Narrate: "The agent hashes evidence before and after the run. The hashes match, so the autonomous loop did not modify configured evidence."

## 2:45 - 3:45 Self-Correction

Open:

```bash
rg "self_correction|validation_issue|agent_iteration" \
  cases/demo-case/outputs/video-demo/analysis/execution_log.jsonl
```

Narrate:

- Iteration 1 creates inferred findings.
- The validator demands missing evidence.
- Iteration 2 confirms real malicious activity.
- The Prefetch-only `svchost.exe` lead is refuted.

## 3:45 - 4:30 Evidence Trail

Open `reports/triage_report.md`.

Point to row-level evidence references:

- `memory_netstat` row 2
- `memory_malfind` row 1
- `disk_amcache` row 1
- `registry_run_keys` row 1

## 4:30 - 5:00 Why It Matters

"This is not just a better prompt. It is a safer execution boundary, a self-correcting analyst loop, and a benchmark that makes hallucinations visible."
