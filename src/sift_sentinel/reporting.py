"""Markdown report generation."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from .case import CaseConfig
from .models import Finding, ToolResult, ValidationIssue
from .utils import utc_now


def generate_triage_report(
    case: CaseConfig,
    findings: Iterable[Finding],
    validation_issues: Iterable[ValidationIssue],
    tool_results: Dict[str, ToolResult],
    run_id: str,
    integrity: Optional[Dict[str, Any]] = None,
) -> str:
    findings = list(findings)
    confirmed = [finding for finding in findings if finding.status == "confirmed"]
    inferred = [finding for finding in findings if finding.status == "inferred"]
    refuted = [finding for finding in findings if finding.status == "refuted"]
    issues = list(validation_issues)

    lines: List[str] = [
        f"# SIFT Sentinel Triage Report: {case.title}",
        "",
        f"- Case ID: `{case.case_id}`",
        f"- Run ID: `{run_id}`",
        f"- Generated UTC: `{utc_now()}`",
        f"- Confirmed findings: `{len(confirmed)}`",
        f"- Inferred findings: `{len(inferred)}`",
        f"- Refuted leads: `{len(refuted)}`",
        f"- Evidence integrity: `{_integrity_status(integrity)}`",
        "",
        "## Executive Summary",
        "",
    ]
    if confirmed:
        lines.append(
            "SIFT Sentinel confirmed malicious execution, memory injection, external command-and-control, "
            "and Run key persistence after iterating through missing evidence checks."
        )
    else:
        lines.append("No findings reached confirmed status in this run.")
    lines.extend(["", "## Confirmed Findings", ""])
    lines.extend(_finding_lines(confirmed))
    lines.extend(["", "## Inferred Or Refuted Leads", ""])
    lines.extend(_finding_lines(inferred + refuted))
    lines.extend(["", "## Self-Correction And Validation", ""])
    if issues:
        for issue in issues:
            lines.extend(
                [
                    f"### {issue.issue_id}: {issue.title}",
                    "",
                    f"- Severity: `{issue.severity}`",
                    f"- Finding: `{issue.finding_id or 'global'}`",
                    f"- Required action: `{issue.required_action}`",
                    f"- Reason: {issue.reason}",
                    "",
                ]
            )
    else:
        lines.append("No validation gaps remained at the end of the run.")
    lines.extend(["", "## Evidence Integrity", ""])
    if integrity:
        comparison = integrity.get("comparison", {})
        if comparison.get("ok"):
            lines.append("Pre-run and post-run evidence manifests match. No configured evidence artifact changed.")
        else:
            lines.append("Evidence integrity check failed. Review changed, missing, and added artifacts before relying on this run.")
        lines.extend(
            [
                "",
                f"- Before artifacts: `{comparison.get('before_artifact_count', 'unknown')}`",
                f"- After artifacts: `{comparison.get('after_artifact_count', 'unknown')}`",
                f"- Changed: `{len(comparison.get('changed', []))}`",
                f"- Missing: `{len(comparison.get('missing', []))}`",
                f"- Added: `{len(comparison.get('added', []))}`",
            ]
        )
    else:
        lines.append("Evidence integrity details were not provided for this report.")
    lines.extend(["", "## Tool Execution Audit", ""])
    for name, result in sorted(tool_results.items()):
        status = "ok" if result.ok else "error"
        lines.extend(
            [
                f"- `{name}` `{result.tool_call_id}`: {status}; rows={len(result.rows)}; started={result.started_at}; ended={result.ended_at}",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def _integrity_status(integrity: Optional[Dict[str, Any]]) -> str:
    if not integrity:
        return "not checked"
    return "ok" if integrity.get("comparison", {}).get("ok") else "failed"


def _finding_lines(findings: Iterable[Finding]) -> List[str]:
    lines: List[str] = []
    any_finding = False
    for finding in findings:
        any_finding = True
        lines.extend(
            [
                f"### {finding.finding_id}: {finding.title}",
                "",
                f"- Severity: `{finding.severity}`",
                f"- Status: `{finding.status}`",
                f"- Confidence: `{finding.confidence:.2f}`",
                f"- Hypothesis: {finding.hypothesis}",
                f"- MITRE: `{', '.join(finding.mitre) if finding.mitre else 'none'}`",
                "",
                "Evidence:",
            ]
        )
        if finding.evidence:
            for ref in finding.evidence:
                row = f" row {ref.row}" if ref.row is not None else ""
                lines.append(f"- `{ref.artifact}`{row} `{ref.field}` = `{ref.value}` via `{ref.tool_call_id}`")
        else:
            lines.append("- No evidence references attached.")
        if finding.details:
            lines.extend(["", "Notes:"])
            for key, value in sorted(finding.details.items()):
                lines.append(f"- `{key}`: {value}")
        lines.append("")
    if not any_finding:
        lines.append("None.")
    return lines
