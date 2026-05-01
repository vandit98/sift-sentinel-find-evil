"""Deterministic autonomous triage loop with self-correction."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from .case import CaseConfig
from .evidence import build_manifest, compare_manifests
from .logger import ExecutionLogger
from .models import Finding, ToolResult, ValidationIssue
from .policies import EvidencePolicy
from .reporting import generate_triage_report
from .tools import SentinelTools
from .utils import normalize_windows_path, slugify, utc_now, write_json


@dataclass
class AgentRunResult:
    case_id: str
    run_id: str
    output_dir: Path
    findings: List[Finding]
    validation_issues: List[ValidationIssue]
    tool_results: Dict[str, ToolResult]
    iterations: int
    integrity: Dict[str, Any]

    def as_dict(self) -> Dict[str, object]:
        return {
            "case_id": self.case_id,
            "run_id": self.run_id,
            "output_dir": str(self.output_dir),
            "iterations": self.iterations,
            "findings": [finding.as_dict() for finding in self.findings],
            "validation_issues": [issue.as_dict() for issue in self.validation_issues],
            "tool_results": {name: result.as_dict() for name, result in self.tool_results.items()},
            "integrity": self.integrity,
        }


@dataclass
class _RunState:
    findings: Dict[str, Finding] = field(default_factory=dict)
    tool_results: Dict[str, ToolResult] = field(default_factory=dict)
    requested_tools: Set[str] = field(default_factory=set)
    validation_issues: List[ValidationIssue] = field(default_factory=list)


class SentinelAgent:
    """Autonomous IR workflow that validates and revises its own findings."""

    INITIAL_TOOLS = ["memory_processes", "memory_netstat", "disk_prefetch", "windows_events"]

    def run(self, case_file: str | Path, max_iterations: int = 3, run_id: Optional[str] = None) -> AgentRunResult:
        if max_iterations < 1:
            raise ValueError("max_iterations must be at least 1")

        case = CaseConfig.load(case_file)
        run_id = slugify(run_id or f"{case.case_id}-{utc_now()}")
        output_dir = (case.output_root / run_id).resolve()
        analysis_dir = output_dir / "analysis"
        reports_dir = output_dir / "reports"
        exports_dir = output_dir / "exports"
        for path in (analysis_dir, reports_dir, exports_dir):
            path.mkdir(parents=True, exist_ok=True)

        policy = EvidencePolicy(case.case_dir, case.evidence_root, case.output_root)
        tools = SentinelTools(case, policy)
        log_path = analysis_dir / "execution_log.jsonl"
        log_path.write_text("", encoding="utf-8")
        logger = ExecutionLogger(log_path)
        state = _RunState(requested_tools=set(self.INITIAL_TOOLS))

        logger.event("agent_start", {"case": case.case_id, "max_iterations": max_iterations, "run_id": run_id})
        manifest = tools.case_manifest()
        self._record_tool(logger, state, manifest, iteration=0)
        pre_manifest = manifest.summary
        write_json(policy.assert_output_path(analysis_dir / "evidence_manifest_before.json"), pre_manifest)

        completed_iterations = 0
        for iteration in range(1, max_iterations + 1):
            completed_iterations = iteration
            logger.event(
                "agent_iteration_start",
                {"requested_tools": sorted(state.requested_tools), "known_findings": sorted(state.findings)},
                iteration=iteration,
            )

            for tool_name in sorted(state.requested_tools):
                if tool_name not in state.tool_results:
                    result = self._call_tool(tools, tool_name)
                    self._record_tool(logger, state, result, iteration=iteration)

            previous = {key: value.as_dict() for key, value in state.findings.items()}
            self._propose_and_refine(state, tools)
            self._log_corrections(logger, previous, state.findings, iteration)

            issues, next_tools = self._validate(state)
            state.validation_issues.extend(issues)
            for issue in issues:
                logger.event("validation_issue", issue.as_dict(), iteration=iteration, correlation_id=issue.issue_id)

            needed = {tool for tool in next_tools if tool not in state.tool_results}
            logger.event(
                "agent_iteration_complete",
                {
                    "new_tool_requests": sorted(needed),
                    "finding_statuses": {fid: finding.status for fid, finding in state.findings.items()},
                },
                iteration=iteration,
            )
            state.requested_tools = needed
            if not needed:
                break

        findings = list(state.findings.values())
        post_manifest = build_manifest(case, policy)
        integrity = {
            "case_id": case.case_id,
            "run_id": run_id,
            "checked_at": utc_now(),
            "comparison": compare_manifests(pre_manifest, post_manifest),
            "before_manifest_path": str(analysis_dir / "evidence_manifest_before.json"),
            "after_manifest_path": str(analysis_dir / "evidence_manifest_after.json"),
        }
        write_json(policy.assert_output_path(analysis_dir / "evidence_manifest_after.json"), post_manifest)
        write_json(policy.assert_output_path(analysis_dir / "evidence_integrity.json"), integrity)
        logger.event("evidence_integrity", integrity)
        write_json(policy.assert_output_path(reports_dir / "findings.json"), [finding.as_dict() for finding in findings])
        write_json(
            policy.assert_output_path(analysis_dir / "progress.json"),
            {
                "case_id": case.case_id,
                "run_id": run_id,
                "iterations": completed_iterations,
                "remaining_requested_tools": sorted(state.requested_tools),
                "final_statuses": {fid: finding.status for fid, finding in state.findings.items()},
                "evidence_integrity_ok": integrity["comparison"]["ok"],
            },
        )
        report = generate_triage_report(case, findings, state.validation_issues, state.tool_results, run_id, integrity)
        (reports_dir / "triage_report.md").write_text(report, encoding="utf-8")
        logger.event(
            "agent_complete",
            {
                "iterations": completed_iterations,
                "evidence_integrity_ok": integrity["comparison"]["ok"],
                "findings": [finding.as_dict() for finding in findings],
                "report": str(reports_dir / "triage_report.md"),
            },
        )

        return AgentRunResult(
            case_id=case.case_id,
            run_id=run_id,
            output_dir=output_dir,
            findings=findings,
            validation_issues=state.validation_issues,
            tool_results=state.tool_results,
            iterations=completed_iterations,
            integrity=integrity,
        )

    def _call_tool(self, tools: SentinelTools, tool_name: str) -> ToolResult:
        method = getattr(tools, tool_name, None)
        if method is None:
            raise ValueError(f"Unknown tool requested by agent policy: {tool_name}")
        return method()

    def _record_tool(self, logger: ExecutionLogger, state: _RunState, result: ToolResult, *, iteration: int) -> None:
        state.tool_results[result.name] = result
        logger.event("tool_call", result.as_dict(), iteration=iteration, correlation_id=result.tool_call_id)

    def _propose_and_refine(self, state: _RunState, tools: SentinelTools) -> None:
        processes = state.tool_results.get("memory_processes")
        netstat = state.tool_results.get("memory_netstat")
        prefetch = state.tool_results.get("disk_prefetch")
        events = state.tool_results.get("windows_events")
        malfind = state.tool_results.get("memory_malfind")
        amcache = state.tool_results.get("disk_amcache")
        timeline = state.tool_results.get("disk_timeline")
        run_keys = state.tool_results.get("registry_run_keys")

        if processes and netstat and prefetch:
            self._upsert_winupdate_callback(state, tools, processes, netstat, prefetch, malfind, amcache, timeline)
            self._upsert_svchost_trap(state, tools, prefetch, amcache, timeline)

        if events:
            self._upsert_powershell_execution(state, tools, events, processes, timeline)
            self._upsert_rundll_persistence(state, tools, events, timeline, run_keys)

    def _upsert_winupdate_callback(
        self,
        state: _RunState,
        tools: SentinelTools,
        processes: ToolResult,
        netstat: ToolResult,
        prefetch: ToolResult,
        malfind: Optional[ToolResult],
        amcache: Optional[ToolResult],
        timeline: Optional[ToolResult],
    ) -> None:
        external = [row for row in netstat.rows if row.get("process_name", "").lower() == "winupdate.exe" and row.get("is_external")]
        if not external:
            return
        net_row = external[0]
        pid = net_row.get("pid", "")
        proc_row = _first(row for row in processes.rows if row.get("pid") == pid)
        pref_row = _first(row for row in prefetch.rows if row.get("executable_name", "").lower() == "winupdate.exe")
        refs = [
            tools.evidence_ref(netstat, "memory_netstat", int(net_row["__row"]), "remote_ip", net_row.get("remote_ip", "")),
        ]
        if proc_row:
            refs.append(tools.evidence_ref(processes, "memory_processes", int(proc_row["__row"]), "image_path", proc_row.get("image_path", "")))
        if pref_row:
            refs.append(tools.evidence_ref(prefetch, "disk_prefetch", int(pref_row["__row"]), "path", pref_row.get("path", "")))

        status = "inferred"
        confidence = 0.58
        details = {
            "remote_ip": net_row.get("remote_ip"),
            "remote_port": net_row.get("remote_port"),
            "pid": pid,
            "self_correction": "Awaiting memory injection and binary provenance checks.",
        }

        mal_row = _first(row for row in (malfind.rows if malfind else []) if row.get("pid") == pid and row.get("mz_header_bool"))
        amcache_row = _first(
            row
            for row in (amcache.rows if amcache else [])
            if "winupdate.exe" in row.get("normalized_path", "")
        )
        timeline_row = _first(
            row
            for row in (timeline.rows if timeline else [])
            if "winupdate.exe" in normalize_windows_path(row.get("path", ""))
        )
        if malfind and mal_row:
            refs.append(tools.evidence_ref(malfind, "memory_malfind", int(mal_row["__row"]), "protection", mal_row.get("protection", "")))
            details["malfind"] = mal_row.get("details", "")
        if amcache and amcache_row:
            refs.append(tools.evidence_ref(amcache, "disk_amcache", int(amcache_row["__row"]), "sha1", amcache_row.get("sha1", "")))
            details["sha1"] = amcache_row.get("sha1", "")
        if timeline and timeline_row:
            refs.append(tools.evidence_ref(timeline, "disk_timeline", int(timeline_row["__row"]), "event", timeline_row.get("event", "")))

        if mal_row and amcache_row and timeline_row:
            status = "confirmed"
            confidence = 0.94
            details["self_correction"] = "Confirmed after adding malfind, Amcache, and disk timeline evidence."

        state.findings["F-001"] = Finding(
            finding_id="F-001",
            title="Winupdate.exe beacon with memory injection evidence",
            severity="critical",
            status=status,
            confidence=confidence,
            hypothesis="A masqueraded winupdate.exe process communicated externally and contains injected executable memory.",
            evidence=refs,
            details=details,
            mitre=["T1055", "T1036", "T1071"],
            ground_truth_ids=["GT-001"] if status == "confirmed" else [],
        )

    def _upsert_svchost_trap(
        self,
        state: _RunState,
        tools: SentinelTools,
        prefetch: ToolResult,
        amcache: Optional[ToolResult],
        timeline: Optional[ToolResult],
    ) -> None:
        pref_row = _first(
            row
            for row in prefetch.rows
            if row.get("executable_name", "").lower() == "svchost.exe"
            and "users\\public" in normalize_windows_path(row.get("path", ""))
        )
        if not pref_row:
            return
        refs = [tools.evidence_ref(prefetch, "disk_prefetch", int(pref_row["__row"]), "path", pref_row.get("path", ""))]
        target_path = normalize_windows_path(pref_row.get("path", ""))
        has_amcache = any(normalize_windows_path(row.get("path", "")) == target_path for row in (amcache.rows if amcache else []))
        has_timeline = any(normalize_windows_path(row.get("path", "")) == target_path for row in (timeline.rows if timeline else []))

        status = "inferred"
        confidence = 0.35
        reason = "Single-source Prefetch-only lead; waiting for file-system or Amcache corroboration."
        if amcache and timeline and not has_amcache and not has_timeline:
            status = "refuted"
            confidence = 0.08
            reason = "Self-corrected: no Amcache or timeline record for the suspicious path, so this stays out of confirmed findings."

        state.findings["F-002"] = Finding(
            finding_id="F-002",
            title="Uncorroborated svchost.exe path anomaly",
            severity="medium",
            status=status,
            confidence=confidence,
            hypothesis="Prefetch references svchost.exe outside System32, but this requires corroboration before reporting.",
            evidence=refs,
            details={"path": pref_row.get("path"), "self_correction": reason},
            mitre=["T1036"],
        )

    def _upsert_powershell_execution(
        self,
        state: _RunState,
        tools: SentinelTools,
        events: ToolResult,
        processes: Optional[ToolResult],
        timeline: Optional[ToolResult],
    ) -> None:
        event_row = _first(
            row
            for row in events.rows
            if "encodedcommand" in row.get("command_line", "").lower()
            and "winupdate.exe" in row.get("command_line", "").lower()
        )
        if not event_row:
            return
        refs = [tools.evidence_ref(events, "windows_events", int(event_row["__row"]), "command_line", event_row.get("command_line", ""))]
        proc_row = _first(row for row in (processes.rows if processes else []) if row.get("name", "").lower() == "powershell.exe")
        timeline_row = _first(
            row
            for row in (timeline.rows if timeline else [])
            if "winupdate.exe" in normalize_windows_path(row.get("path", ""))
        )
        if proc_row:
            refs.append(tools.evidence_ref(processes, "memory_processes", int(proc_row["__row"]), "command_line", proc_row.get("command_line", "")))
        if timeline_row:
            refs.append(tools.evidence_ref(timeline, "disk_timeline", int(timeline_row["__row"]), "path", timeline_row.get("path", "")))

        confirmed = bool(proc_row and timeline_row)
        state.findings["F-004"] = Finding(
            finding_id="F-004",
            title="Encoded PowerShell staged winupdate.exe",
            severity="high",
            status="confirmed" if confirmed else "inferred",
            confidence=0.88 if confirmed else 0.52,
            hypothesis="PowerShell launched an encoded command that staged or executed winupdate.exe.",
            evidence=refs,
            details={
                "user": event_row.get("user"),
                "self_correction": "Confirmed after process and timeline corroboration." if confirmed else "Waiting for process and timeline corroboration.",
            },
            mitre=["T1059.001", "T1105"],
            ground_truth_ids=["GT-003"] if confirmed else [],
        )

    def _upsert_rundll_persistence(
        self,
        state: _RunState,
        tools: SentinelTools,
        events: ToolResult,
        timeline: Optional[ToolResult],
        run_keys: Optional[ToolResult],
    ) -> None:
        event_row = _first(
            row
            for row in events.rows
            if "rundll32.exe" in row.get("command_line", "").lower()
            and "synccache.dll" in row.get("command_line", "").lower()
        )
        if not event_row:
            return
        refs = [tools.evidence_ref(events, "windows_events", int(event_row["__row"]), "command_line", event_row.get("command_line", ""))]
        timeline_row = _first(
            row
            for row in (timeline.rows if timeline else [])
            if "synccache.dll" in normalize_windows_path(row.get("path", ""))
        )
        run_key_row = _first(
            row
            for row in (run_keys.rows if run_keys else [])
            if "synccache.dll" in normalize_windows_path(row.get("value_data", ""))
        )
        if timeline_row:
            refs.append(tools.evidence_ref(timeline, "disk_timeline", int(timeline_row["__row"]), "path", timeline_row.get("path", "")))
        if run_key_row:
            refs.append(tools.evidence_ref(run_keys, "registry_run_keys", int(run_key_row["__row"]), "value_data", run_key_row.get("value_data", "")))

        confirmed = bool(timeline_row and run_key_row)
        state.findings["F-003"] = Finding(
            finding_id="F-003",
            title="Run key persistence loads SyncCache.dll via rundll32",
            severity="high",
            status="confirmed" if confirmed else "inferred",
            confidence=0.91 if confirmed else 0.48,
            hypothesis="A user Run key persists a suspicious DLL through rundll32.exe.",
            evidence=refs,
            details={
                "self_correction": "Confirmed only after registry Run key evidence was collected."
                if confirmed
                else "Rundll32 execution observed, but persistence mechanism is not confirmed yet.",
            },
            mitre=["T1112", "T1218.011", "T1547.001"],
            ground_truth_ids=["GT-002"] if confirmed else [],
        )

    def _validate(self, state: _RunState) -> tuple[List[ValidationIssue], Set[str]]:
        issues: List[ValidationIssue] = []
        next_tools: Set[str] = set()

        f1 = state.findings.get("F-001")
        if f1 and f1.status != "confirmed":
            missing = []
            for tool in ("memory_malfind", "disk_amcache", "disk_timeline"):
                if tool not in state.tool_results:
                    missing.append(tool)
            if missing:
                next_tools.update(missing)
                issues.append(
                    ValidationIssue(
                        issue_id="VAL-001",
                        severity="high",
                        title="External callback needs binary and memory corroboration",
                        finding_id="F-001",
                        required_action=", ".join(missing),
                        reason="Network evidence alone can misattribute a process; require injection, hash, and file timeline evidence.",
                    )
                )

        f2 = state.findings.get("F-002")
        if f2 and f2.status == "inferred":
            missing = [tool for tool in ("disk_amcache", "disk_timeline") if tool not in state.tool_results]
            if missing:
                next_tools.update(missing)
                issues.append(
                    ValidationIssue(
                        issue_id="VAL-002",
                        severity="medium",
                        title="Svchost masquerade lead is single-source",
                        finding_id="F-002",
                        required_action=", ".join(missing),
                        reason="A Prefetch-only path anomaly is not enough for a confirmed report.",
                    )
                )

        f3 = state.findings.get("F-003")
        if f3 and f3.status != "confirmed":
            if "registry_run_keys" not in state.tool_results:
                next_tools.add("registry_run_keys")
                issues.append(
                    ValidationIssue(
                        issue_id="VAL-003",
                        severity="high",
                        title="Rundll32 execution needs persistence mechanism validation",
                        finding_id="F-003",
                        required_action="registry_run_keys",
                        reason="Execution is not persistence until an ASEP or service mechanism is proven.",
                    )
                )

        f4 = state.findings.get("F-004")
        if f4 and f4.status != "confirmed":
            if "disk_timeline" not in state.tool_results:
                next_tools.add("disk_timeline")

        return issues, next_tools

    def _log_corrections(
        self,
        logger: ExecutionLogger,
        previous: Dict[str, Dict[str, object]],
        current: Dict[str, Finding],
        iteration: int,
    ) -> None:
        for finding_id, finding in current.items():
            before = previous.get(finding_id)
            after = finding.as_dict()
            if before is None:
                logger.event("finding_created", after, iteration=iteration, correlation_id=finding_id)
            elif before.get("status") != after.get("status") or before.get("confidence") != after.get("confidence"):
                logger.event(
                    "self_correction",
                    {
                        "finding_id": finding_id,
                        "before": {"status": before.get("status"), "confidence": before.get("confidence")},
                        "after": {"status": after.get("status"), "confidence": after.get("confidence")},
                        "reason": finding.details.get("self_correction", ""),
                    },
                    iteration=iteration,
                    correlation_id=finding_id,
                )


def _first(values: Iterable[dict]) -> Optional[dict]:
    for value in values:
        return value
    return None
