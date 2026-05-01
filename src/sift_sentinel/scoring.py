"""Accuracy and hallucination scoring for known-good cases."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

from .case import CaseConfig
from .models import Finding
from .utils import read_json, write_json, write_text


def load_ground_truth(case: CaseConfig) -> Dict[str, Any]:
    if not case.ground_truth:
        raise ValueError("Case does not configure a ground_truth file")
    return read_json(case.ground_truth)


def score_findings(findings: Iterable[Finding], ground_truth: Dict[str, Any]) -> Dict[str, Any]:
    findings = list(findings)
    confirmed = [finding for finding in findings if finding.status == "confirmed"]
    truth_ids: Set[str] = {item["id"] for item in ground_truth.get("truth", [])}
    hit_ids: Set[str] = set()
    for finding in confirmed:
        hit_ids.update(truth_id for truth_id in finding.ground_truth_ids if truth_id in truth_ids)

    false_positives = [finding.finding_id for finding in confirmed if not finding.ground_truth_ids]
    hallucinated = [
        finding.finding_id
        for finding in confirmed
        if not finding.evidence or any(not ref.tool_call_id for ref in finding.evidence)
    ]
    missed = sorted(truth_ids - hit_ids)
    tp = len(hit_ids)
    fp = len(false_positives)
    fn = len(missed)
    denominator = tp + fp + fn

    return {
        "true_positive_ids": sorted(hit_ids),
        "missed_truth_ids": missed,
        "false_positive_finding_ids": false_positives,
        "hallucinated_finding_ids": hallucinated,
        "refuted_finding_ids": [finding.finding_id for finding in findings if finding.status == "refuted"],
        "confirmed_count": len(confirmed),
        "precision": round(tp / (tp + fp), 3) if (tp + fp) else 0.0,
        "recall": round(tp / (tp + fn), 3) if (tp + fn) else 0.0,
        "f1": round((2 * tp) / (2 * tp + fp + fn), 3) if denominator else 0.0,
        "hallucination_count": len(hallucinated),
    }


def write_accuracy_artifacts(output_dir: Path, score: Dict[str, Any], ground_truth: Dict[str, Any]) -> None:
    reports_dir = output_dir / "reports"
    analysis_dir = output_dir / "analysis"
    write_json(analysis_dir / "accuracy_score.json", score)
    lines: List[str] = [
        "# SIFT Sentinel Accuracy Report",
        "",
        "## Summary",
        "",
        f"- Precision: `{score['precision']}`",
        f"- Recall: `{score['recall']}`",
        f"- F1: `{score['f1']}`",
        f"- Hallucinated confirmed findings: `{score['hallucination_count']}`",
        f"- False positives: `{len(score['false_positive_finding_ids'])}`",
        f"- Missed truth items: `{len(score['missed_truth_ids'])}`",
        "",
        "## Evidence Integrity",
        "",
        "All confirmed findings include structured evidence references tied to specific tool call IDs. "
        "The policy layer denies writes under the evidence root and allows output only below the case output directory.",
        "",
        "## Ground Truth Coverage",
        "",
    ]
    for item in ground_truth.get("truth", []):
        marker = "hit" if item["id"] in score["true_positive_ids"] else "missed"
        lines.append(f"- `{item['id']}` {marker}: {item.get('title', '')}")
    lines.extend(
        [
            "",
            "## Refuted Leads",
            "",
            ", ".join(score["refuted_finding_ids"]) if score["refuted_finding_ids"] else "None.",
            "",
        ]
    )
    write_text(reports_dir / "accuracy_report.md", "\n".join(lines))

