# Research Notes

Research was performed on 2026-05-01 IST.

## Hackathon Requirements

The Find Evil Devpost page says the mission is to improve Protocol SIFT so an agent can sequence analysis, recognize contradictions, and self-correct. It identifies a custom MCP server as the most sound architecture because it exposes structured functions instead of a generic shell and avoids destructive tools entirely.

Source: [Find Evil Devpost](https://findevil.devpost.com/)

## SIFT and Protocol SIFT

SANS describes SIFT as a free and open-source incident response and forensic workstation with tools for file systems, network evidence, memory images, Plaso, Volatility, Sleuth Kit, bulk_extractor, YARA, and many more. The same SANS page describes Protocol SIFT as experimental research and notes it has not been validated for evidentiary reliability.

Source: [SANS SIFT Workstation](https://www.sans.org/tools/sift-workstation/)

The public Protocol SIFT repository is primarily a Claude Code configuration package: global instructions, settings, skill files, case templates, and a PDF report script. It gives agents DFIR knowledge, but it still depends heavily on prompt adherence and client permission behavior.

Source: [teamdfir/protocol-sift](https://github.com/teamdfir/protocol-sift)

## MCP Design

The MCP docs define servers as providers of resources, tools, and prompts. Their server tutorial emphasizes that tools are functions called by the LLM and warns that stdio servers must not log to stdout because that corrupts JSON-RPC framing.

Source: [Build an MCP server](https://modelcontextprotocol.io/docs/develop/build-server)

The MCP Python SDK docs list Python as an official Tier 1 SDK and show FastMCP as a common way to expose typed tools. SIFT Sentinel uses a minimal stdio implementation to avoid dependencies, but keeps the same tool/list and tool/call model.

Source: [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)

## MCP Security

The MCP security best-practices page recommends local server filesystem and resource restrictions, stdio for local servers, restricted HTTP access when HTTP is used, and scope minimization. SIFT Sentinel applies those ideas to DFIR evidence: local stdio, narrow tools, read-only evidence paths, and output-only writes.

Source: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)

## Dataset Strategy

NIST CFReDS provides documented forensic reference data sets intended for validation, training, and proficiency testing. The bundled case is synthetic for easy judging, but the benchmark interface is designed to extend to CFReDS, Honeynet challenges, and SIFT lab data.

Sources:

- [NIST CFReDS](https://www.nist.gov/programs-projects/computer-forensic-reference-data-sets)
- [Honeynet Challenges](https://www.honeynet.org/challenges/)

