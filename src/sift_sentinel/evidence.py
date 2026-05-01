"""Evidence hashing and manifest generation."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List

from .case import CaseConfig
from .policies import EvidencePolicy


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_directory(path: Path) -> Dict[str, Any]:
    digest = hashlib.sha256()
    file_count = 0
    total_size = 0
    for child in sorted(item for item in path.rglob("*") if item.is_file()):
        relative = child.relative_to(path).as_posix()
        digest.update(relative.encode("utf-8"))
        stat = child.stat()
        digest.update(str(stat.st_size).encode("ascii"))
        with child.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        file_count += 1
        total_size += stat.st_size
    return {"sha256": digest.hexdigest(), "file_count": file_count, "size_bytes": total_size}


def build_manifest(case: CaseConfig, policy: EvidencePolicy) -> Dict[str, Any]:
    artifacts = {}
    for name, artifact_path in sorted(case.artifacts.items()):
        path = policy.assert_readable_evidence_path(artifact_path)
        if path.is_dir():
            directory_hash = sha256_directory(path)
            artifacts[name] = {
                "path": str(path),
                "type": "directory",
                "size_bytes": directory_hash["size_bytes"],
                "file_count": directory_hash["file_count"],
                "sha256": directory_hash["sha256"],
            }
            continue
        stat = path.stat()
        artifacts[name] = {
            "path": str(path),
            "type": "file",
            "size_bytes": stat.st_size,
            "sha256": sha256_file(path),
        }
    return {
        "case_id": case.case_id,
        "title": case.title,
        "evidence_root": str(case.evidence_root),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }


def compare_manifests(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    before_artifacts = before.get("artifacts", {})
    after_artifacts = after.get("artifacts", {})
    changed: List[Dict[str, Any]] = []
    missing: List[str] = []
    added: List[str] = []

    for name, before_record in sorted(before_artifacts.items()):
        after_record = after_artifacts.get(name)
        if after_record is None:
            missing.append(name)
            continue
        if before_record.get("sha256") != after_record.get("sha256") or before_record.get("size_bytes") != after_record.get("size_bytes"):
            changed.append(
                {
                    "artifact": name,
                    "before": {
                        "sha256": before_record.get("sha256"),
                        "size_bytes": before_record.get("size_bytes"),
                    },
                    "after": {
                        "sha256": after_record.get("sha256"),
                        "size_bytes": after_record.get("size_bytes"),
                    },
                }
            )

    for name in sorted(after_artifacts):
        if name not in before_artifacts:
            added.append(name)

    return {
        "ok": not changed and not missing and not added,
        "changed": changed,
        "missing": missing,
        "added": added,
        "before_artifact_count": len(before_artifacts),
        "after_artifact_count": len(after_artifacts),
    }


def evidence_integrity_report(case: CaseConfig, policy: EvidencePolicy) -> Dict[str, Any]:
    manifest = build_manifest(case, policy)
    return {
        "case_id": case.case_id,
        "policy": {
            "evidence_root": str(policy.evidence_root),
            "output_root": str(policy.output_root),
            "mode": "read-only evidence, output-root writes only",
        },
        "manifest": manifest,
    }
