# Security Model

SIFT Sentinel is not a malware sandbox. It is an evidence-safe orchestration layer for DFIR tooling.

## Controls

- No generic shell command is exposed through MCP.
- Evidence root paths are read-only by enforced policy.
- Writes outside the configured output root are denied.
- SIFT subprocesses use allowlisted binaries and argv arrays.
- Volatility plugins are allowlisted.
- Tool output is structured before it reaches the model.
- Confirmed findings require evidence references and tool call IDs.

## Reporting Issues

Open a GitHub issue with:

- Tool name
- Case configuration
- Expected behavior
- Observed behavior
- Whether evidence integrity was affected

