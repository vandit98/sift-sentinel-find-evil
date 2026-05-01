# Architecture

## Pattern

SIFT Sentinel uses the challenge's **Custom MCP Server** pattern as the primary architecture. It also includes a self-correcting triage loop and benchmark harness because those two pieces make the autonomy measurable.

## Components

- `sift_sentinel.mcp_server`: MCP stdio server with typed tools.
- `sift_sentinel.agent`: autonomous triage loop with validation and self-correction.
- `sift_sentinel.tools`: read-only structured forensic tools over parsed artifacts.
- `sift_sentinel.policies`: evidence integrity guardrail.
- `sift_sentinel.runners`: safe subprocess runner for real SIFT tools.
- `sift_sentinel.sift_wrappers`: narrow Volatility and EvtxECmd wrappers.
- `sift_sentinel.validation`: case validation and spoliation checks.
- `sift_sentinel.scoring`: accuracy and hallucination benchmark.

## Trust Boundaries

| Boundary | Enforcement | Type |
|---|---|---|
| Evidence root is read-only | `EvidencePolicy.assert_readable_evidence` and `assert_output_path` | Architectural |
| Output root is the only write target | `EvidencePolicy.assert_output_path` | Architectural |
| Evidence changes are detected | pre-run and post-run hash manifests | Architectural |
| No arbitrary command execution | MCP server exposes typed tools only | Architectural |
| SIFT subprocesses use argv arrays | `SafeSubprocessRunner`, `shell=False` | Architectural |
| Volatility plugin choices are allowlisted | `VOLATILITY_PLUGINS` | Architectural |
| Claims must cite evidence refs | validation and scoring require tool call IDs | Architectural |
| Analyst behavior and sequencing | deterministic agent loop and docs | Prompt-independent |

Prompt-based guidance can still improve the host model's behavior, but the core safety properties do not depend on prompt obedience.

## Execution Flow

```mermaid
sequenceDiagram
    participant Host as MCP Host or CLI
    participant MCP as SIFT Sentinel MCP Server
    participant Agent as Self-Correcting Agent
    participant Policy as EvidencePolicy
    participant Tools as Typed Forensic Tools
    participant Out as Outputs

    Host->>MCP: tools/call run_triage(case, max_iterations)
    MCP->>Agent: start run
    Agent->>Tools: case_manifest
    Tools->>Policy: verify evidence reads
    Tools-->>Agent: hashes and artifact inventory
    Agent->>Tools: initial triage tools
    Tools-->>Agent: structured rows
    Agent->>Agent: propose inferred findings
    Agent->>Agent: validate gaps
    Agent->>Tools: run missing tools
    Tools-->>Agent: corroborating evidence
    Agent->>Agent: confirm or refute findings
    Agent->>Out: findings.json, triage_report.md, execution_log.jsonl, evidence_integrity.json
    MCP-->>Host: structured run result
```

## Self-Correction Example

Iteration 1 creates four inferred findings:

- Winupdate external callback
- Prefetch-only `C:\Users\Public\svchost.exe`
- Encoded PowerShell execution
- Rundll32 loading `SyncCache.dll`

The validator refuses to confirm them until missing evidence is collected:

- External callback needs `memory_malfind`, `disk_amcache`, and `disk_timeline`.
- Prefetch-only masquerade lead needs `disk_amcache` and `disk_timeline`.
- Rundll32 execution needs `registry_run_keys`.

Iteration 2 updates the findings:

- `F-001` becomes confirmed after malfind, hash, and timeline evidence.
- `F-002` becomes refuted because no Amcache or timeline record supports the suspicious svchost path.
- `F-003` becomes confirmed after registry Run key evidence.
- `F-004` becomes confirmed after process and timeline corroboration.

The full trace is in `cases/demo-case/outputs/demo-run/analysis/execution_log.jsonl`.

## SIFT Wrapper Coverage

SIFT Sentinel now declares typed contracts for the core artifact families judges care about:

| Wrapper | SIFT family | Boundary |
|---|---|---|
| `volatility_json` | Memory | Allowlisted Volatility 3 plugins, JSON renderer |
| `evtxecmd_csv` | Event logs | Read-only EVTX directory, CSV output only |
| `mftecmd_csv` | NTFS timeline | Read-only `$MFT` or `$J`, CSV output only |
| `pecmd_csv` | Execution evidence | Read-only Prefetch directory, CSV output only |
| `amcacheparser_csv` | Binary provenance | Read-only Amcache hive, CSV output only |
| `recmd_batch_csv` | Registry | Read-only hive directory, approved batch files only |
| `yara_scan` | Threat hunting | Read-only rules and evidence artifacts |
| `sleuthkit_fls` | Filesystem | Read-only image listing, non-negative offsets |
