"""Case configuration loading and path resolution."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .utils import read_json


@dataclass(frozen=True)
class CaseConfig:
    case_file: Path
    case_dir: Path
    case_id: str
    title: str
    description: str
    evidence_root: Path
    output_root: Path
    artifacts: Dict[str, Path]
    internal_networks: List[str] = field(default_factory=list)
    allowlisted_paths: List[str] = field(default_factory=list)
    ground_truth: Optional[Path] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, case_file: str | Path) -> "CaseConfig":
        path = Path(case_file).expanduser().resolve()
        data = read_json(path)
        case_dir = path.parent

        evidence_root = _resolve(case_dir, data.get("evidence_root", "evidence"))
        output_root = _resolve(case_dir, data.get("output_root", "outputs"))

        artifacts = {
            name: _resolve(case_dir, rel_path)
            for name, rel_path in data.get("artifacts", {}).items()
        }
        ground_truth = data.get("ground_truth")

        return cls(
            case_file=path,
            case_dir=case_dir,
            case_id=data["case_id"],
            title=data.get("title", data["case_id"]),
            description=data.get("description", ""),
            evidence_root=evidence_root,
            output_root=output_root,
            artifacts=artifacts,
            internal_networks=list(data.get("known_good", {}).get("internal_networks", [])),
            allowlisted_paths=list(data.get("known_good", {}).get("allowlisted_paths", [])),
            ground_truth=_resolve(case_dir, ground_truth) if ground_truth else None,
            metadata=dict(data.get("metadata", {})),
        )

    def artifact(self, name: str) -> Path:
        if name not in self.artifacts:
            raise KeyError(f"Artifact '{name}' is not configured for case {self.case_id}")
        return self.artifacts[name]


def _resolve(base: Path, value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base / path
    return path.resolve()

