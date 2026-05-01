# Accuracy Report

## Command

```bash
PYTHONPATH=src python3 -m sift_sentinel benchmark \
  --case cases/demo-case/case.json \
  --run-id demo-benchmark \
  --max-iterations 3
```

## Latest Demo Score

| Metric | Value |
|---|---:|
| Precision | 1.0 |
| Recall | 1.0 |
| F1 | 1.0 |
| Confirmed findings | 3 |
| False positives | 0 |
| Missed truth items | 0 |
| Hallucinated confirmed findings | 0 |
| Refuted leads | F-002 |

## Evidence Integrity Approach

SIFT Sentinel prevents evidence modification through architecture:

- Evidence reads must be under the configured evidence root.
- Writes are denied under the evidence root.
- Writes are allowed only under the configured output root.
- A pre-run manifest and post-run manifest are compared for every autonomous run.
- The MCP server exposes typed tools, not a shell.
- Real SIFT subprocesses are invoked with argument arrays and an allowlisted binary set.
- Confirmed findings require structured evidence references with tool call IDs.

Generated integrity artifact:

- `cases/demo-case/outputs/demo-benchmark/analysis/evidence_integrity.json`

Latest demo verdict: pre-run and post-run evidence manifests match.

## Prompt-Based Restriction Test

The system does not rely on a prompt saying "do not modify evidence." The path policy is enforced in Python. Unit tests verify that writes into the evidence root raise `PolicyViolation`, and the CLI exposes:

```bash
PYTHONPATH=src python3 -m sift_sentinel spoliation-test \
  --case cases/demo-case/case.json
```

## Failure Modes Found

- A Prefetch-only anomaly can look malicious. SIFT Sentinel initially records it as inferred, then refutes it after Amcache and timeline checks fail to corroborate it.
- The synthetic benchmark is small. The next validation step is running the same loop against larger public cases with known answers.
