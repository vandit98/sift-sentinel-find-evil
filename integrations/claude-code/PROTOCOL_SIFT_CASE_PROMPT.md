# Protocol SIFT Case Prompt Add-On

Use this with Protocol SIFT when SIFT Sentinel is configured as an MCP server.

## Operating Rule

Use SIFT Sentinel tools for evidence inventory, guardrail checks, autonomous triage, and benchmark scoring before issuing any raw forensic command.

## Required First Steps

1. Call `sift_sentinel_validate_case` with the case file.
2. Call `sift_sentinel_spoliation_check` and confirm every evidence write probe is denied.
3. Call `sift_sentinel_run_triage` with `max_iterations` set to a finite value.
4. Read `evidence_integrity.json` before trusting the report.

## Reporting Rule

Treat a finding as confirmed only if it includes:

- Tool call ID
- Artifact name
- Row or offset reference
- Corroborating source when available
- Evidence integrity verdict for the run

