"""Minimal MCP stdio server exposing SIFT Sentinel typed tools."""

from __future__ import annotations

import json
import sys
from typing import Any, Callable, Dict, Optional

from .agent import SentinelAgent
from .case import CaseConfig
from .evidence import build_manifest, evidence_integrity_report
from .policies import EvidencePolicy
from .scoring import load_ground_truth, score_findings, write_accuracy_artifacts
from .sift_wrappers import SiftWrappers
from .tools import SentinelTools
from .validation import spoliation_check, validate_case


JSONDict = Dict[str, Any]


class SentinelMCPServer:
    def __init__(self) -> None:
        self.tools: Dict[str, Callable[[JSONDict], JSONDict]] = {
            "sift_sentinel_case_manifest": self._case_manifest,
            "sift_sentinel_validate_case": self._validate_case,
            "sift_sentinel_integrity_report": self._integrity_report,
            "sift_sentinel_spoliation_check": self._spoliation_check,
            "sift_sentinel_tool_contracts": self._tool_contracts,
            "sift_sentinel_run_triage": self._run_triage,
            "sift_sentinel_benchmark": self._benchmark,
            "sift_sentinel_memory_processes": self._memory_processes,
            "sift_sentinel_memory_netstat": self._memory_netstat,
            "sift_sentinel_memory_malfind": self._memory_malfind,
            "sift_sentinel_disk_prefetch": self._disk_prefetch,
            "sift_sentinel_disk_amcache": self._disk_amcache,
            "sift_sentinel_disk_timeline": self._disk_timeline,
            "sift_sentinel_windows_events": self._windows_events,
            "sift_sentinel_registry_run_keys": self._registry_run_keys,
        }

    def serve(self) -> None:
        while True:
            message = _read_message(sys.stdin.buffer)
            if message is None:
                break
            response = self._handle(message)
            if response is not None:
                _write_message(sys.stdout.buffer, response)

    def _handle(self, message: JSONDict) -> Optional[JSONDict]:
        request_id = message.get("id")
        method = message.get("method")
        try:
            if method == "initialize":
                return _result(
                    request_id,
                    {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "sift-sentinel", "version": "0.1.0"},
                    },
                )
            if method == "notifications/initialized":
                return None
            if method == "ping":
                return _result(request_id, {})
            if method == "tools/list":
                return _result(request_id, {"tools": self._tool_descriptions()})
            if method == "tools/call":
                params = message.get("params", {})
                name = params.get("name")
                arguments = params.get("arguments", {})
                if name not in self.tools:
                    raise ValueError(f"Unknown tool: {name}")
                payload = self.tools[name](arguments)
                return _result(
                    request_id,
                    {"content": [{"type": "text", "text": json.dumps(payload, indent=2, sort_keys=True)}]},
                )
            if request_id is None:
                return None
            return _error(request_id, -32601, f"Method not found: {method}")
        except Exception as exc:  # noqa: BLE001 - MCP surfaces tool errors as JSON
            if request_id is None:
                return None
            return _result(
                request_id,
                {
                    "content": [{"type": "text", "text": json.dumps({"error": str(exc)}, indent=2)}],
                    "isError": True,
                },
            )

    def _tool_descriptions(self) -> list[JSONDict]:
        case_schema = {
            "type": "object",
            "properties": {"case_file": {"type": "string", "description": "Absolute or relative path to case.json"}},
            "required": ["case_file"],
        }
        return [
            {
                "name": "sift_sentinel_case_manifest",
                "description": "Hash and inventory configured evidence without modifying it.",
                "inputSchema": case_schema,
            },
            {
                "name": "sift_sentinel_validate_case",
                "description": "Validate case configuration, artifact paths, and output/evidence root separation.",
                "inputSchema": case_schema,
            },
            {
                "name": "sift_sentinel_integrity_report",
                "description": "Generate the current evidence hash manifest and integrity policy statement.",
                "inputSchema": case_schema,
            },
            {
                "name": "sift_sentinel_spoliation_check",
                "description": "Run adversarial policy checks proving writes into evidence paths are denied.",
                "inputSchema": case_schema,
            },
            {
                "name": "sift_sentinel_tool_contracts",
                "description": "List typed SIFT wrapper contracts and their security boundaries.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "sift_sentinel_run_triage",
                "description": "Run the autonomous self-correcting triage loop with a hard max iteration cap.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "case_file": {"type": "string"},
                        "max_iterations": {"type": "integer", "minimum": 1, "maximum": 10, "default": 3},
                        "run_id": {"type": "string"},
                    },
                    "required": ["case_file"],
                },
            },
            {
                "name": "sift_sentinel_benchmark",
                "description": "Run triage and score confirmed findings against documented ground truth.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "case_file": {"type": "string"},
                        "run_id": {"type": "string"},
                        "max_iterations": {"type": "integer", "minimum": 1, "maximum": 10, "default": 3},
                    },
                    "required": ["case_file"],
                },
            },
            {
                "name": "sift_sentinel_memory_processes",
                "description": "Return structured process rows from the configured memory process artifact.",
                "inputSchema": case_schema,
            },
            {
                "name": "sift_sentinel_memory_netstat",
                "description": "Return structured memory network rows with internal/external classification.",
                "inputSchema": case_schema,
            },
            {
                "name": "sift_sentinel_memory_malfind",
                "description": "Return structured memory malfind rows with executable-region annotations.",
                "inputSchema": case_schema,
            },
            {
                "name": "sift_sentinel_disk_prefetch",
                "description": "Return structured Windows Prefetch execution rows.",
                "inputSchema": case_schema,
            },
            {
                "name": "sift_sentinel_disk_amcache",
                "description": "Return structured Amcache rows with signing and normalized-path annotations.",
                "inputSchema": case_schema,
            },
            {
                "name": "sift_sentinel_disk_timeline",
                "description": "Return structured disk timeline rows.",
                "inputSchema": case_schema,
            },
            {
                "name": "sift_sentinel_windows_events",
                "description": "Return structured Windows event rows.",
                "inputSchema": case_schema,
            },
            {
                "name": "sift_sentinel_registry_run_keys",
                "description": "Return structured Windows Run key persistence rows.",
                "inputSchema": case_schema,
            },
        ]

    def _case_manifest(self, args: JSONDict) -> JSONDict:
        case, policy, _tools = _load_tools(args)
        return build_manifest(case, policy)

    def _validate_case(self, args: JSONDict) -> JSONDict:
        return validate_case(args["case_file"])

    def _integrity_report(self, args: JSONDict) -> JSONDict:
        case, policy, _tools = _load_tools(args)
        return evidence_integrity_report(case, policy)

    def _spoliation_check(self, args: JSONDict) -> JSONDict:
        return spoliation_check(args["case_file"])

    def _tool_contracts(self, _args: JSONDict) -> JSONDict:
        return SiftWrappers.tool_contracts()

    def _run_triage(self, args: JSONDict) -> JSONDict:
        result = SentinelAgent().run(
            args["case_file"],
            max_iterations=int(args.get("max_iterations", 3)),
            run_id=args.get("run_id"),
        )
        return result.as_dict()

    def _benchmark(self, args: JSONDict) -> JSONDict:
        result = SentinelAgent().run(
            args["case_file"],
            max_iterations=int(args.get("max_iterations", 3)),
            run_id=args.get("run_id"),
        )
        case = CaseConfig.load(args["case_file"])
        truth = load_ground_truth(case)
        score = score_findings(result.findings, truth)
        write_accuracy_artifacts(result.output_dir, score, truth)
        return {"run": result.as_dict(), "score": score}

    def _memory_processes(self, args: JSONDict) -> JSONDict:
        _case, _policy, tools = _load_tools(args)
        return tools.memory_processes().as_dict()

    def _memory_netstat(self, args: JSONDict) -> JSONDict:
        _case, _policy, tools = _load_tools(args)
        return tools.memory_netstat().as_dict()

    def _memory_malfind(self, args: JSONDict) -> JSONDict:
        _case, _policy, tools = _load_tools(args)
        return tools.memory_malfind().as_dict()

    def _disk_prefetch(self, args: JSONDict) -> JSONDict:
        _case, _policy, tools = _load_tools(args)
        return tools.disk_prefetch().as_dict()

    def _disk_amcache(self, args: JSONDict) -> JSONDict:
        _case, _policy, tools = _load_tools(args)
        return tools.disk_amcache().as_dict()

    def _disk_timeline(self, args: JSONDict) -> JSONDict:
        _case, _policy, tools = _load_tools(args)
        return tools.disk_timeline().as_dict()

    def _windows_events(self, args: JSONDict) -> JSONDict:
        _case, _policy, tools = _load_tools(args)
        return tools.windows_events().as_dict()

    def _registry_run_keys(self, args: JSONDict) -> JSONDict:
        _case, _policy, tools = _load_tools(args)
        return tools.registry_run_keys().as_dict()


def _load_tools(args: JSONDict) -> tuple[CaseConfig, EvidencePolicy, SentinelTools]:
    case = CaseConfig.load(args["case_file"])
    policy = EvidencePolicy(case.case_dir, case.evidence_root, case.output_root)
    return case, policy, SentinelTools(case, policy)


def _result(request_id: Any, result: JSONDict) -> JSONDict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> JSONDict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _read_message(stream) -> Optional[JSONDict]:
    header = b""
    while b"\r\n\r\n" not in header and b"\n\n" not in header:
        char = stream.read(1)
        if not char:
            return None
        header += char
    separator = b"\r\n\r\n" if b"\r\n\r\n" in header else b"\n\n"
    header_text = header.split(separator, 1)[0].decode("ascii", errors="replace")
    content_length = None
    for line in header_text.splitlines():
        if line.lower().startswith("content-length:"):
            content_length = int(line.split(":", 1)[1].strip())
            break
    if content_length is None:
        raise ValueError("MCP message missing Content-Length header")
    body = stream.read(content_length)
    if not body:
        return None
    return json.loads(body.decode("utf-8"))


def _write_message(stream, message: JSONDict) -> None:
    body = json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
    stream.write(body)
    stream.flush()


def main() -> None:
    SentinelMCPServer().serve()


if __name__ == "__main__":
    main()
