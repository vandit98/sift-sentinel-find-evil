"""Structured records used by the autonomous loop, reports, and MCP tools."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .utils import utc_now


@dataclass
class EvidenceRef:
    artifact: str
    row: Optional[int]
    field: str
    value: str
    tool_call_id: str

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToolResult:
    tool_call_id: str
    name: str
    ok: bool
    started_at: str
    ended_at: str
    inputs: Dict[str, Any]
    summary: Dict[str, Any]
    rows: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    finding_id: str
    title: str
    severity: str
    status: str
    confidence: float
    hypothesis: str
    evidence: List[EvidenceRef] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    mitre: List[str] = field(default_factory=list)
    ground_truth_ids: List[str] = field(default_factory=list)
    corrected_from: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["evidence"] = [ref.as_dict() for ref in self.evidence]
        return data


@dataclass
class ValidationIssue:
    issue_id: str
    severity: str
    title: str
    finding_id: Optional[str]
    required_action: str
    reason: str
    created_at: str = field(default_factory=utc_now)

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

