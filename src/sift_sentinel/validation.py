"""Case validation and adversarial guardrail checks."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from .case import CaseConfig
from .evidence import build_manifest
from .policies import EvidencePolicy, PolicyViolation


def validate_case(case_file: str | Path) -> Dict[str, Any]:
    issues: List[Dict[str, str]] = []
    case = CaseConfig.load(case_file)
    policy = EvidencePolicy(case.case_dir, case.evidence_root, case.output_root)

    if not case.evidence_root.exists():
        issues.append({"severity": "critical", "message": f"Evidence root does not exist: {case.evidence_root}"})
    if policy._is_within(case.output_root, case.evidence_root):  # noqa: SLF001 - explicit validation report
        issues.append({"severity": "critical", "message": "Output root must not be inside evidence root"})

    for name, artifact_path in sorted(case.artifacts.items()):
        try:
            policy.assert_readable_evidence_path(artifact_path)
        except PolicyViolation as exc:
            issues.append({"severity": "high", "artifact": name, "message": str(exc)})

    if case.ground_truth and not case.ground_truth.exists():
        issues.append({"severity": "medium", "message": f"Ground truth file is configured but missing: {case.ground_truth}"})

    manifest = None
    if not issues:
        manifest = build_manifest(case, policy)

    return {
        "ok": not any(issue["severity"] in {"critical", "high"} for issue in issues),
        "case_id": case.case_id,
        "case_file": str(case.case_file),
        "artifact_count": len(case.artifacts),
        "issues": issues,
        "manifest": manifest,
    }


def spoliation_check(case_file: str | Path) -> Dict[str, Any]:
    case = CaseConfig.load(case_file)
    policy = EvidencePolicy(case.case_dir, case.evidence_root, case.output_root)
    checks: List[Dict[str, Any]] = []

    checks.append(_expect_denied("write_probe_inside_evidence_root", lambda: policy.assert_output_path(case.evidence_root / "sentinel_spoliation_probe.txt")))

    for name, artifact_path in sorted(case.artifacts.items())[:3]:
        checks.append(_expect_denied(f"write_probe_over_artifact:{name}", lambda p=artifact_path: policy.assert_output_path(p)))

    output_probe = policy.assert_output_path(case.output_root / "spoliation-check" / "allowed-output.txt")
    checks.append(
        {
            "name": "write_probe_inside_output_root",
            "ok": True,
            "expected": "allowed",
            "observed": "allowed",
            "path": str(output_probe),
        }
    )

    return {
        "ok": all(check["ok"] for check in checks),
        "case_id": case.case_id,
        "checks": checks,
    }


def _expect_denied(name: str, fn) -> Dict[str, Any]:
    try:
        fn()
    except PolicyViolation as exc:
        return {
            "name": name,
            "ok": True,
            "expected": "denied",
            "observed": "denied",
            "reason": str(exc),
        }
    return {
        "name": name,
        "ok": False,
        "expected": "denied",
        "observed": "allowed",
    }
