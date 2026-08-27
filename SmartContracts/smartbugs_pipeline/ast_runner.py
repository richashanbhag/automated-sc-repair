"""Compiler AST extraction for the collection pipeline."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AstRun:
    status: str
    elapsed: float
    ast: dict | None = None
    source_compilation_status: str = "NOT_RUN"
    error_type: str = ""
    error_message: str = ""


def _extract_json(stdout: str) -> dict:
    start = stdout.find("{")
    end = stdout.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("solc did not emit a JSON AST object")
    return json.loads(stdout[start : end + 1])


def _run_solc(command: list[str], timeout: int, solc_version: str = "") -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if solc_version:
        env["SOLC_VERSION"] = solc_version
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False, env=env)


def run_ast(contract_path: Path, timeout: int, solc_version: str = "") -> AstRun:
    started = time.monotonic()
    if not shutil.which("solc"):
        return AstRun("FAILED", 0.0, source_compilation_status="NOT_RUN", error_type="missing_tool", error_message="solc is not installed or not on PATH")
    attempts = [
        ["solc", "--ast-compact-json", str(contract_path)],
        ["solc", "--combined-json", "ast", str(contract_path)],
    ]
    messages: list[str] = []
    compilation_messages: list[str] = []
    last_elapsed = 0.0
    for command in attempts:
        try:
            result = _run_solc(command, timeout, solc_version)
        except subprocess.TimeoutExpired as exc:
            return AstRun("FAILED", time.monotonic() - started, source_compilation_status="FAILED", error_type="timeout", error_message=str(exc))
        except OSError as exc:
            return AstRun("FAILED", time.monotonic() - started, source_compilation_status="FAILED", error_type="execution_error", error_message=str(exc))
        last_elapsed = time.monotonic() - started
        if result.returncode != 0:
            compilation_messages.append((result.stderr or result.stdout or f"solc exited {result.returncode}").strip())
            continue
        try:
            ast = _extract_json(result.stdout)
            return AstRun("SUCCESS", last_elapsed, ast=ast, source_compilation_status="SUCCESS")
        except (ValueError, json.JSONDecodeError) as exc:
            messages.append((result.stderr or result.stdout or str(exc)).strip())
    if compilation_messages:
        return AstRun("FAILED", last_elapsed, source_compilation_status="FAILED", error_type="compilation_error", error_message="\n".join(compilation_messages))
    message = "\n".join(message for message in messages if message) or "solc did not emit a JSON AST object"
    return AstRun("FAILED", last_elapsed, source_compilation_status="SUCCESS", error_type="json_parse_error", error_message=message)
