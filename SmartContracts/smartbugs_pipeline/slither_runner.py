"""Isolated, timeout-safe Slither execution."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SlitherRun:
    status: str
    elapsed: float
    payload: dict | None = None
    error_type: str = ""
    error_message: str = ""


def run_slither(contract_path: Path, raw_path: Path, timeout: int) -> SlitherRun:
    started = time.monotonic()
    if not shutil.which("slither"):
        return SlitherRun("FAILED", 0.0, error_type="missing_tool", error_message="slither is not installed or not on PATH")
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="slither-") as temp_dir:
        output_path = Path(temp_dir) / "output.json"
        try:
            result = subprocess.run(
                ["slither", str(contract_path), "--json", str(output_path)],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return SlitherRun("FAILED", time.monotonic() - started, error_type="timeout", error_message=str(exc))
        except OSError as exc:
            return SlitherRun("FAILED", time.monotonic() - started, error_type="execution_error", error_message=str(exc))
        elapsed = time.monotonic() - started
        if not output_path.exists():
            message = (result.stderr or result.stdout).strip()
            return SlitherRun("FAILED", elapsed, error_type="execution_error", error_message=message or f"Slither exited {result.returncode}")
        try:
            payload = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            return SlitherRun("FAILED", elapsed, error_type="json_parse_error", error_message=str(exc))
        # Slither exits nonzero when detectors are reported. Structured JSON is the
        # source of truth: only an explicit unsuccessful payload is an execution error.
        if payload.get("success") is False:
            error = payload.get("error") or (result.stderr or result.stdout).strip() or f"Slither exited {result.returncode}"
            return SlitherRun("FAILED", elapsed, payload=payload, error_type="execution_error", error_message=str(error))
        raw_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return SlitherRun("SUCCESS", elapsed, payload=payload)
