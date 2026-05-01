"""Structured audit logging for agent decisions and tool execution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from .utils import append_jsonl, estimate_tokens, utc_now


@dataclass
class ExecutionLogger:
    log_path: Path

    def event(
        self,
        event_type: str,
        payload: Dict[str, Any],
        *,
        iteration: Optional[int] = None,
        correlation_id: Optional[str] = None,
    ) -> None:
        record = {
            "timestamp": utc_now(),
            "event_type": event_type,
            "iteration": iteration,
            "correlation_id": correlation_id,
            "token_usage": {
                "prompt_estimate": estimate_tokens(payload),
                "completion_estimate": 0,
                "source": "deterministic-local-estimate",
            },
            "payload": payload,
        }
        append_jsonl(self.log_path, record)

