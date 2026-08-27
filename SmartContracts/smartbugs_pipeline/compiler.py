"""Resolve Solidity pragma constraints and manage solc-select sequentially."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass


Version = tuple[int, int, int]
VERSION_RE = re.compile(r"(?<![\w.])(0\.\d+\.\d+)(?![\w.])")


def _normalize_constraint(value: str) -> str:
    """Normalize harmless spacing around version dots found in Wild sources."""
    return re.sub(r"\s*\.\s*", ".", value or "")


@dataclass
class CompilerResolution:
    pragma: str
    version: str = ""
    status: str = "FAILED"
    error_type: str = ""
    error_message: str = ""


def version_tuple(value: str) -> Version:
    match = VERSION_RE.search(value or "")
    if not match:
        raise ValueError(f"No Solidity version found in {value!r}")
    return tuple(int(part) for part in match.group(1).split("."))  # type: ignore[return-value]


def _compatible(version: Version, constraint: str) -> bool:
    text = re.sub(r"^\s*pragma\s+solidity\s+", "", _normalize_constraint(constraint), flags=re.I)
    text = text.replace(";", "").strip()
    if not text:
        return False
    # Solidity OR constraints: any branch may match.
    if "||" in text:
        return any(_compatible(version, branch) for branch in text.split("||"))
    matches = list(re.finditer(r"(\^|~|>=|<=|>|<|=)?\s*(0\.\d+(?:\.\d+)?)", text))
    if not matches:
        return False
    for match in matches:
        operator = match.group(1) or "="
        pieces = [int(value) for value in match.group(2).split(".")]
        while len(pieces) < 3:
            pieces.append(0)
        target = tuple(pieces[:3])
        if operator == "^":
            upper = (target[0] + 1, 0, 0) if target[0] else (
                (0, target[1] + 1, 0) if target[1] else (0, 0, target[2] + 1)
            )
            ok = target <= version < upper
        elif operator == "~":
            ok = target <= version < (target[0], target[1] + 1, 0)
        elif operator == ">=":
            ok = version >= target
        elif operator == "<=":
            ok = version <= target
        elif operator == ">":
            ok = version > target
        elif operator == "<":
            ok = version < target
        else:
            # A two-component bare version denotes that minor release line.
            ok = version == target if len(match.group(2).split(".")) == 3 else version[:2] == target[:2]
        if not ok:
            return False
    return True


def _run(command: list[str], timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)


def installed_versions() -> list[str]:
    result = _run(["solc-select", "versions"])
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout).strip() or "solc-select versions failed")
    versions = {match.group(1) for match in VERSION_RE.finditer(result.stdout)}
    return sorted(versions, key=version_tuple)


def resolve_compiler(pragma: str) -> CompilerResolution:
    resolution = CompilerResolution(pragma=pragma)
    normalized = _normalize_constraint(pragma)
    if not normalized or not VERSION_RE.search(normalized):
        resolution.error_type = "unresolved_constraint"
        resolution.error_message = "No usable Solidity compiler constraint in index.csv"
        return resolution
    if not shutil.which("solc-select"):
        resolution.error_type = "missing_tool"
        resolution.error_message = "solc-select is not installed or not on PATH"
        return resolution
    try:
        installed = installed_versions()
        compatible = [item for item in installed if _compatible(version_tuple(item), normalized)]
        if compatible:
            selected = compatible[-1]
        else:
            # Installing the highest patch in the pragma's first minor line is reproducible and
            # avoids silently crossing minor-version boundaries for old contracts.
            base = version_tuple(VERSION_RE.search(normalized).group(1))  # type: ignore[union-attr]
            selected = f"{base[0]}.{base[1]}.{base[2]}"
            install = _run(["solc-select", "install", selected])
            if install.returncode != 0:
                raise RuntimeError((install.stderr or install.stdout).strip() or f"Could not install solc {selected}")
        if not _compatible(version_tuple(selected), normalized):
            raise RuntimeError(f"Resolved solc {selected} is incompatible with {pragma}")
        activate = _run(["solc-select", "use", selected])
        if activate.returncode != 0:
            raise RuntimeError((activate.stderr or activate.stdout).strip() or f"Could not activate solc {selected}")
        resolution.version = selected
        resolution.status = "SUCCESS"
        return resolution
    except subprocess.TimeoutExpired as exc:
        resolution.error_type = "timeout"
        resolution.error_message = str(exc)
    except (OSError, RuntimeError, ValueError) as exc:
        resolution.error_type = "resolution_error"
        resolution.error_message = str(exc)
    return resolution
