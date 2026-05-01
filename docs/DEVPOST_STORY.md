# Devpost Story Draft

## What It Does

SIFT Sentinel makes Protocol SIFT safer and more autonomous by putting a typed MCP server between the AI agent and forensic tooling. Instead of exposing a generic shell, it exposes structured tools such as memory process review, network connection review, Amcache parsing, timeline review, Run key review, and benchmark scoring.

The agent runs a triage loop, creates initial hypotheses, validates its own gaps, runs the missing tools, and revises findings. It can confirm malicious behavior, refute weak leads, and produce a report where every claim maps back to a specific tool call and evidence row.

It also hashes every configured evidence artifact before and after each run, then writes an evidence integrity report. That gives judges a direct answer to the spoliation question: did the autonomous agent change the evidence?

## How We Built It

The project is a standard-library Python package with four main layers:

- A minimal MCP stdio server for AI clients.
- An evidence policy that enforces read-only evidence and output-only writes.
- Typed forensic tools that return structured rows instead of raw terminal dumps.
- A deterministic self-correction loop with JSONL execution logs and benchmark scoring.
- A spoliation-test command that proves evidence writes are denied by code.

The demo case is synthetic and redistributable, but shaped like parsed SIFT outputs: memory process rows, netstat rows, malfind rows, Prefetch, Amcache, event logs, timeline, and registry Run keys.

## Challenges

The hard part was not parsing CSV. The hard part was designing a system that can move quickly without making the common AI failure mode worse. A fast hallucination is still a hallucination.

SIFT Sentinel solves this by making confirmation expensive in the right way: a finding can start as inferred, but it needs independent evidence before it becomes confirmed. That is how a senior analyst behaves during an incident.

## What We Learned

Protocol SIFT already gives agents useful DFIR instincts, but prompt guardrails are not enough for evidence integrity. The strongest architecture is a narrow execution layer that physically cannot run destructive commands or write to evidence paths.

We also learned that self-correction should be logged as a first-class artifact. Judges and analysts need to see not only what the agent concluded, but what it changed its mind about.

## What's Next

- Add more SIFT wrappers: MFTECmd, RECmd, PECmd, YARA, Sleuth Kit, and Plaso.
- Run against public datasets such as NIST CFReDS and Honeynet challenges.
- Add multi-source correlation for memory plus disk plus PCAP in the same case.
- Package a Claude Code and OpenClaw MCP configuration.
- Add a small web UI for live progress, findings, and evidence drilldown.
