"""Command-line interface for SIFT Sentinel."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

from .agent import SentinelAgent
from .case import CaseConfig
from .evidence import build_manifest, evidence_integrity_report
from .mcp_server import SentinelMCPServer
from .policies import EvidencePolicy
from .scoring import load_ground_truth, score_findings, write_accuracy_artifacts
from .sift_wrappers import SiftWrappers
from .tools import SentinelTools
from .utils import write_json
from .validation import spoliation_check, validate_case


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="SIFT Sentinel autonomous DFIR agent")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="Run autonomous triage")
    run_parser.add_argument("--case", required=True, help="Path to case.json")
    run_parser.add_argument("--max-iterations", type=int, default=3)
    run_parser.add_argument("--run-id", default=None)

    benchmark_parser = sub.add_parser("benchmark", help="Run triage and score against ground truth")
    benchmark_parser.add_argument("--case", required=True, help="Path to case.json")
    benchmark_parser.add_argument("--max-iterations", type=int, default=3)
    benchmark_parser.add_argument("--run-id", default=None)

    manifest_parser = sub.add_parser("manifest", help="Hash and inventory evidence")
    manifest_parser.add_argument("--case", required=True, help="Path to case.json")

    validate_parser = sub.add_parser("validate", help="Validate case configuration and artifact paths")
    validate_parser.add_argument("--case", required=True, help="Path to case.json")

    integrity_parser = sub.add_parser("integrity", help="Generate current evidence integrity report")
    integrity_parser.add_argument("--case", required=True, help="Path to case.json")

    spoliation_parser = sub.add_parser("spoliation-test", help="Run policy checks that prove evidence writes are denied")
    spoliation_parser.add_argument("--case", required=True, help="Path to case.json")

    sub.add_parser("contracts", help="List typed SIFT wrapper contracts")

    tool_parser = sub.add_parser("tool", help="Run a typed read-only tool")
    tool_parser.add_argument("--case", required=True, help="Path to case.json")
    tool_parser.add_argument("tool_name", choices=["memory_processes", "memory_netstat", "memory_malfind", "disk_prefetch", "disk_amcache", "disk_timeline", "windows_events", "registry_run_keys"])

    sub.add_parser("mcp", help="Run MCP stdio server")

    args = parser.parse_args(argv)
    if args.command == "run":
        result = SentinelAgent().run(args.case, max_iterations=args.max_iterations, run_id=args.run_id)
        print(json.dumps({"output_dir": str(result.output_dir), "findings": [f.as_dict() for f in result.findings]}, indent=2))
    elif args.command == "benchmark":
        result = SentinelAgent().run(args.case, max_iterations=args.max_iterations, run_id=args.run_id)
        case = CaseConfig.load(args.case)
        truth = load_ground_truth(case)
        score = score_findings(result.findings, truth)
        write_accuracy_artifacts(result.output_dir, score, truth)
        print(json.dumps({"output_dir": str(result.output_dir), "score": score}, indent=2, sort_keys=True))
    elif args.command == "manifest":
        case = CaseConfig.load(args.case)
        policy = EvidencePolicy(case.case_dir, case.evidence_root, case.output_root)
        manifest = build_manifest(case, policy)
        output_path = policy.assert_output_path(case.output_root / "latest-manifest.json")
        write_json(output_path, manifest)
        print(json.dumps({"manifest": manifest, "written": str(output_path)}, indent=2, sort_keys=True))
    elif args.command == "validate":
        print(json.dumps(validate_case(args.case), indent=2, sort_keys=True))
    elif args.command == "integrity":
        case = CaseConfig.load(args.case)
        policy = EvidencePolicy(case.case_dir, case.evidence_root, case.output_root)
        print(json.dumps(evidence_integrity_report(case, policy), indent=2, sort_keys=True))
    elif args.command == "spoliation-test":
        print(json.dumps(spoliation_check(args.case), indent=2, sort_keys=True))
    elif args.command == "contracts":
        print(json.dumps(SiftWrappers.tool_contracts(), indent=2, sort_keys=True))
    elif args.command == "tool":
        case = CaseConfig.load(args.case)
        policy = EvidencePolicy(case.case_dir, case.evidence_root, case.output_root)
        tools = SentinelTools(case, policy)
        result = getattr(tools, args.tool_name)()
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    elif args.command == "mcp":
        SentinelMCPServer().serve()
    else:
        parser.error(f"Unhandled command: {args.command}")


if __name__ == "__main__":
    main()
