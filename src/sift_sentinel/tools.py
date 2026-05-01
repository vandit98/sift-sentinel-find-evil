"""Typed forensic tools exposed to the agent and MCP server."""

from __future__ import annotations

import ipaddress
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .case import CaseConfig
from .evidence import build_manifest
from .models import EvidenceRef, ToolResult
from .policies import EvidencePolicy
from .utils import normalize_windows_path, read_csv, utc_now


class SentinelTools:
    """Read-only forensic artifact tools.

    Each method returns structured rows and summary data. There is intentionally
    no generic shell command tool here; the language model can only ask for
    typed operations with policy-checked paths.
    """

    def __init__(self, case: CaseConfig, policy: EvidencePolicy):
        self.case = case
        self.policy = policy

    def case_manifest(self) -> ToolResult:
        return self._wrap("case_manifest", {}, lambda: (build_manifest(self.case, self.policy), []))

    def memory_processes(self) -> ToolResult:
        return self._csv_tool("memory_processes", "memory_processes", summary_fields=["name", "image_path", "user"])

    def memory_netstat(self) -> ToolResult:
        def load():
            rows = self._read_artifact_csv("memory_netstat")
            for row in rows:
                row["network_scope"] = self._network_scope(row.get("remote_ip", ""))
                row["is_external"] = row["network_scope"] == "external"
            summary = {
                "connections": len(rows),
                "external_connections": sum(1 for row in rows if row.get("is_external")),
                "remote_ips": sorted({row.get("remote_ip", "") for row in rows if row.get("remote_ip")}),
            }
            return summary, rows

        return self._wrap("memory_netstat", {"artifact": "memory_netstat"}, load)

    def memory_malfind(self) -> ToolResult:
        def load():
            rows = self._read_artifact_csv("memory_malfind")
            for row in rows:
                row["mz_header_bool"] = row.get("mz_header", "").strip().lower() in {"true", "yes", "1"}
                row["rwx_bool"] = "execute" in row.get("protection", "").lower() and "write" in row.get("protection", "").lower()
            summary = {
                "regions": len(rows),
                "mz_regions": sum(1 for row in rows if row.get("mz_header_bool")),
                "rwx_regions": sum(1 for row in rows if row.get("rwx_bool")),
            }
            return summary, rows

        return self._wrap("memory_malfind", {"artifact": "memory_malfind"}, load)

    def disk_prefetch(self) -> ToolResult:
        return self._csv_tool("disk_prefetch", "disk_prefetch", summary_fields=["executable_name", "path"])

    def disk_amcache(self) -> ToolResult:
        def load():
            rows = self._read_artifact_csv("disk_amcache")
            for row in rows:
                row["signed_bool"] = row.get("signed", "").strip().lower() in {"true", "yes", "1"}
                row["normalized_path"] = normalize_windows_path(row.get("path", ""))
            summary = {
                "entries": len(rows),
                "unsigned_entries": sum(1 for row in rows if not row.get("signed_bool")),
                "sha1s": sorted({row.get("sha1", "") for row in rows if row.get("sha1")}),
            }
            return summary, rows

        return self._wrap("disk_amcache", {"artifact": "disk_amcache"}, load)

    def disk_timeline(self) -> ToolResult:
        return self._csv_tool("disk_timeline", "disk_timeline", summary_fields=["source", "path", "event"])

    def windows_events(self) -> ToolResult:
        def load():
            rows = self._read_artifact_csv("windows_events")
            summary = {
                "events": len(rows),
                "event_ids": sorted({row.get("event_id", "") for row in rows if row.get("event_id")}),
                "commands": sum(1 for row in rows if row.get("command_line")),
            }
            return summary, rows

        return self._wrap("windows_events", {"artifact": "windows_events"}, load)

    def registry_run_keys(self) -> ToolResult:
        return self._csv_tool("registry_run_keys", "registry_run_keys", summary_fields=["hive", "key", "value_name"])

    def evidence_ref(
        self,
        tool_result: ToolResult,
        artifact: str,
        row: Optional[int],
        field: str,
        value: str,
    ) -> EvidenceRef:
        return EvidenceRef(
            artifact=artifact,
            row=row,
            field=field,
            value=value,
            tool_call_id=tool_result.tool_call_id,
        )

    def _csv_tool(self, name: str, artifact: str, *, summary_fields: Iterable[str]) -> ToolResult:
        def load():
            rows = self._read_artifact_csv(artifact)
            fields = list(summary_fields)
            summary = {
                "rows": len(rows),
                "fields": fields,
                "distinct": {
                    field: sorted({row.get(field, "") for row in rows if row.get(field)})
                    for field in fields
                },
            }
            return summary, rows

        return self._wrap(name, {"artifact": artifact}, load)

    def _read_artifact_csv(self, artifact: str) -> List[Dict[str, Any]]:
        path = self.policy.assert_readable_evidence(self.case.artifact(artifact))
        rows = read_csv(path)
        for index, row in enumerate(rows, start=1):
            row["__artifact"] = artifact
            row["__row"] = index
        return rows

    def _wrap(self, name: str, inputs: Dict[str, Any], fn) -> ToolResult:
        started = utc_now()
        started_clock = time.perf_counter()
        try:
            summary, rows = fn()
            summary = dict(summary)
            summary["duration_ms"] = int((time.perf_counter() - started_clock) * 1000)
            return ToolResult(
                tool_call_id=f"{name}-{uuid.uuid4().hex[:10]}",
                name=name,
                ok=True,
                started_at=started,
                ended_at=utc_now(),
                inputs=inputs,
                summary=summary,
                rows=list(rows),
            )
        except Exception as exc:  # noqa: BLE001 - tool errors are logged as data
            return ToolResult(
                tool_call_id=f"{name}-{uuid.uuid4().hex[:10]}",
                name=name,
                ok=False,
                started_at=started,
                ended_at=utc_now(),
                inputs=inputs,
                summary={"duration_ms": int((time.perf_counter() - started_clock) * 1000)},
                rows=[],
                error=str(exc),
            )

    def _finished(
        self,
        name: str,
        inputs: Dict[str, Any],
        summary: Dict[str, Any],
        rows: List[Dict[str, Any]],
    ) -> ToolResult:
        return self._wrap(name, inputs, lambda: (summary, rows))

    def _network_scope(self, address: str) -> str:
        if not address:
            return "unknown"
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return "unknown"
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return "local"
        for network in self.case.internal_networks:
            try:
                if ip in ipaddress.ip_network(network, strict=False):
                    return "internal"
            except ValueError:
                continue
        return "external"
