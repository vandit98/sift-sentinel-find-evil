# Try-It-Out Instructions

## Local Demo

Requirements:

- Python 3.9 or newer
- No external Python packages

Run:

```bash
PYTHONPATH=src python3 -m sift_sentinel benchmark \
  --case cases/demo-case/case.json \
  --run-id judge-demo \
  --max-iterations 3
```

Open:

- `cases/demo-case/outputs/judge-demo/reports/triage_report.md`
- `cases/demo-case/outputs/judge-demo/reports/accuracy_report.md`
- `cases/demo-case/outputs/judge-demo/analysis/execution_log.jsonl`
- `cases/demo-case/outputs/judge-demo/analysis/evidence_integrity.json`

Run guardrail checks:

```bash
PYTHONPATH=src python3 -m sift_sentinel validate \
  --case cases/demo-case/case.json

PYTHONPATH=src python3 -m sift_sentinel spoliation-test \
  --case cases/demo-case/case.json

PYTHONPATH=src python3 -m sift_sentinel contracts
```

## MCP Server

Run the stdio MCP server:

```bash
PYTHONPATH=src python3 -m sift_sentinel mcp
```

Claude Desktop-style configuration example:

```json
{
  "mcpServers": {
    "sift-sentinel": {
      "command": "python3",
      "args": ["-m", "sift_sentinel", "mcp"],
      "env": {
        "PYTHONPATH": "/absolute/path/to/sift-sentinel/src"
      }
    }
  }
}
```

A ready-to-edit copy is in `integrations/claude-code/mcp.example.json`.

## SIFT Workstation

On SIFT:

1. Install Protocol SIFT from the hackathon instructions.
2. Clone this repo.
3. Put case evidence under `cases/<case-name>/evidence`.
4. Create a `case.json` that maps artifact names to parsed SIFT outputs.
5. Run the benchmark command above.

For raw images, use or extend `sift_sentinel.sift_wrappers`. The current contracts cover Volatility 3, EvtxECmd, MFTECmd, PECmd, AmcacheParser, RECmd, YARA, and Sleuth Kit `fls`.
