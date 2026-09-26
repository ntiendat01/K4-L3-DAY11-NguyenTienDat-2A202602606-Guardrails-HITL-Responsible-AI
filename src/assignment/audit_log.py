"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """TODO: store input + start timestamp keyed by request_id/user_id."""
        req_id = request_id or f"{user_id}_{len(self.logs)}"
        self._open[req_id] = datetime.now(timezone.utc).timestamp()
        self.logs.append({
            "request_id": req_id,
            "user_id": user_id,
            "input": text,
            "timestamp_start": utc_now_iso(),
        })

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """TODO: store output, layer decision, latency; append to self.logs."""
        req_id = request_id or f"{user_id}_{len(self.logs) - 1}"
        latency = 0.0
        if req_id in self._open:
            latency = datetime.now(timezone.utc).timestamp() - self._open[req_id]
            del self._open[req_id]
            
        for log in self.logs:
            if log.get("request_id") == req_id:
                log.update({
                    "output": text,
                    "blocked": blocked,
                    "layer": layer,
                    "latency": latency,
                    "timestamp_end": utc_now_iso(),
                })
                return
        self.logs.append({
            "request_id": req_id,
            "user_id": user_id,
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency": latency,
            "timestamp_end": utc_now_iso(),
        })

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        # TODO: path = filepath or default_audit_log_path()
        #       ensure parent dirs exist, dump self.logs with indent=2
        path = filepath or default_audit_log_path()
        path_obj = Path(path)
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        path_obj.write_text(json.dumps(self.logs, indent=2, ensure_ascii=False), encoding="utf-8")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
