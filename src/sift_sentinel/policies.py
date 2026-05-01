"""Evidence integrity and execution boundary enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List


class PolicyViolation(RuntimeError):
    """Raised when a requested action would cross an evidence boundary."""


@dataclass(frozen=True)
class EvidencePolicy:
    """Strict path policy for case evidence and generated output.

    The agent can read configured evidence files and write only below the case
    output root. This moves the key safety control out of the language model's
    prompt and into deterministic code.
    """

    case_dir: Path
    evidence_root: Path
    output_root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "case_dir", self.case_dir.resolve())
        object.__setattr__(self, "evidence_root", self.evidence_root.resolve())
        object.__setattr__(self, "output_root", self.output_root.resolve())

    def assert_readable_evidence(self, path: Path) -> Path:
        resolved = path.resolve()
        if not self._is_within(resolved, self.evidence_root):
            raise PolicyViolation(f"Read denied outside evidence root: {resolved}")
        if not resolved.exists():
            raise PolicyViolation(f"Evidence artifact does not exist: {resolved}")
        if not resolved.is_file():
            raise PolicyViolation(f"Evidence artifact is not a file: {resolved}")
        return resolved

    def assert_readable_evidence_path(self, path: Path) -> Path:
        resolved = path.resolve()
        if not self._is_within(resolved, self.evidence_root):
            raise PolicyViolation(f"Read denied outside evidence root: {resolved}")
        if not resolved.exists():
            raise PolicyViolation(f"Evidence path does not exist: {resolved}")
        return resolved

    def assert_readable_case_file(self, path: Path) -> Path:
        resolved = path.resolve()
        if not self._is_within(resolved, self.case_dir):
            raise PolicyViolation(f"Read denied outside case directory: {resolved}")
        if not resolved.exists():
            raise PolicyViolation(f"Case file does not exist: {resolved}")
        if not resolved.is_file():
            raise PolicyViolation(f"Case path is not a file: {resolved}")
        return resolved

    def assert_output_path(self, path: Path) -> Path:
        resolved = path.resolve()
        if self._is_within(resolved, self.evidence_root):
            raise PolicyViolation(f"Write denied inside evidence root: {resolved}")
        if not self._is_within(resolved, self.output_root):
            raise PolicyViolation(f"Write denied outside output root: {resolved}")
        return resolved

    def assert_all_outputs(self, paths: Iterable[Path]) -> List[Path]:
        return [self.assert_output_path(path) for path in paths]

    @staticmethod
    def _is_within(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False
