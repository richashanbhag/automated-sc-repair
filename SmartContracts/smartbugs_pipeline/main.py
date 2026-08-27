from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager
from pathlib import Path

from ast_runner import run_ast
from compiler import extract_pragmas, resolve_compiler
from config import (
    ANALYSIS_FIELDS,
    ANALYSIS_PATH,
    AST_JSONL_PATH,
    FAILED_FIELDS,
    FAILED_PATH,
    FINDING_FIELDS,
    FINDINGS_PATH,
    INDEX_PATH,
    LOG_PATH,
    RAW_DIR,
    ensure_directories,
)
from parser import parse_findings
from slither_runner import run_slither


_COMPILER_LOCK = None


def args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sequential SmartBugs Wild collection pipeline")
    parser.add_argument("--limit", type=int, default=100, help="number of valid contracts to process")
    parser.add_argument("--full", action="store_true", help="process every valid contract in index.csv")
    parser.add_argument("--timeout", type=int, default=120, help="timeout per AST or Slither command")
    parser.add_argument("--workers", type=int, default=1, help="number of worker processes")
    parser.add_argument("--force", action="store_true", help="rerun selected successful contracts")
    parser.add_argument("--ast-only", action="store_true", help="refresh AST/source-compilation state without running Slither")
    parser.add_argument("--filenames", help="comma-separated contract filenames to process")
    parser.add_argument("--retry-failed-ast", action="store_true", help="retry only contracts listed in data/ast_failure_investigation_first_500.json")
    return parser.parse_args()


def init_worker(compiler_lock) -> None:
    global _COMPILER_LOCK
    _COMPILER_LOCK = compiler_lock


def ident(row: dict[str, str]) -> str:
    return str(Path(row["filepath"]).resolve()).lower()


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists() or not path.stat().st_size:
        return []
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        # Preserve legacy artifacts while migrating the schema at the next checkpoint.
        if "compiler_resolution_status" not in row:
            row["compiler_resolution_status"] = row.get("compiler_status", "")
        if "source_compilation_status" not in row:
            row["source_compilation_status"] = "SUCCESS" if row.get("ast_status") == "SUCCESS" else "UNKNOWN"
    return rows


def write_rows(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def select_contracts(limit: int | None) -> list[dict[str, str]]:
    if limit is not None and limit < 1:
        raise ValueError("--limit must be at least 1")
    if not INDEX_PATH.exists():
        raise FileNotFoundError(f"Required index is missing: {INDEX_PATH}")
    selected: list[dict[str, str]] = []
    with INDEX_PATH.open(newline="", encoding="utf-8-sig") as stream:
        for row in csv.DictReader(stream):
            if "valid" in row and row["valid"].strip().lower() in {"", "0", "false", "no", "invalid"}:
                continue
            filepath = row.get("filepath") or row.get("path") or ""
            if not filepath:
                continue
            row["filepath"] = filepath
            row["filename"] = row.get("filename") or Path(filepath).name
            row["pragma"] = row.get("pragma") or row.get("compiler_constraint") or ""
            selected.append(row)
            if limit is not None and len(selected) == limit:
                break
    return selected


def read_ast_keys(path: Path) -> set[str]:
    keys: set[str] = set()
    if not path.exists():
        return keys
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            filepath = payload.get("filepath")
            if filepath:
                keys.add(str(Path(filepath).resolve()).lower())
    return keys


def rewrite_ast_jsonl_without(path: Path, selected_ids: set[str]) -> None:
    if not path.exists() or not selected_ids:
        return
    kept: list[str] = []
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                key = str(Path(payload.get("filepath", "")).resolve()).lower()
            except (json.JSONDecodeError, OSError):
                key = ""
            if key not in selected_ids:
                kept.append(line)
    path.write_text("".join(kept), encoding="utf-8")


def append_ast_record(contract: dict[str, str], solc_version: str, ast: dict) -> None:
    record = {
        "filename": contract["filename"],
        "filepath": contract["filepath"],
        "pragma": contract["pragma"],
        "solc_version": solc_version,
        "ast": ast,
    }
    with AST_JSONL_PATH.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")


def append_ast_json_record(record: dict[str, object]) -> None:
    with AST_JSONL_PATH.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")


def make_ast_record(contract: dict[str, str], solc_version: str, ast: dict) -> dict[str, object]:
    return {
        "filename": contract["filename"],
        "filepath": contract["filepath"],
        "pragma": contract["pragma"],
        "solc_version": solc_version,
        "ast": ast,
    }


def process_contract(contract: dict[str, str], timeout: int) -> dict[str, object]:
    path = Path(contract["filepath"])
    failures: list[dict[str, object]] = []
    findings_out: list[dict[str, object]] = []
    started = time.monotonic()
    try:
        if not path.is_file():
            failure = {**contract, "stage": "input", "error_type": "unreadable_file", "error_message": "Contract path is not a readable file", "resolved_solc_version": ""}
            analysis = {**contract, "resolved_solc_version": "", "analysis_status": "FAILED", "compiler_resolution_status": "FAILED", "source_compilation_status": "NOT_RUN", "ast_status": "NOT_RUN", "slither_status": "NOT_RUN", "detector_count": 0, "execution_time_seconds": "0.000"}
            return {"contract": contract, "analysis": analysis, "findings": [], "failures": [failure], "ast_record": None}

        source = path.read_text(encoding="utf-8", errors="replace")
        source_pragmas = extract_pragmas(source)
        contract = {**contract, "pragma": " ".join(source_pragmas) or contract.get("pragma", "")}

        if _COMPILER_LOCK is None:
            compiler = resolve_compiler(source_pragmas or contract["pragma"])
        else:
            with _COMPILER_LOCK:
                compiler = resolve_compiler(contract["pragma"])
        if compiler.status != "SUCCESS":
            failure = {**contract, "stage": "compiler", "error_type": compiler.error_type, "error_message": compiler.error_message, "resolved_solc_version": compiler.version}
            analysis = {**contract, "resolved_solc_version": compiler.version, "analysis_status": "FAILED", "compiler_resolution_status": "FAILED", "source_compilation_status": "NOT_RUN", "ast_status": "NOT_RUN", "slither_status": "NOT_RUN", "detector_count": 0, "execution_time_seconds": "0.000"}
            return {"contract": contract, "analysis": analysis, "findings": [], "failures": [failure], "ast_record": None}

        ast = run_ast(path, timeout, compiler.version)
        ast_record = None
        if ast.status == "SUCCESS" and ast.ast is not None:
            ast_record = make_ast_record(contract, compiler.version, ast.ast)
        else:
            failures.append({**contract, "stage": "ast", "error_type": ast.error_type, "error_message": ast.error_message, "resolved_solc_version": compiler.version})

        detector_count = 0
        if ast.source_compilation_status == "FAILED":
            slither_status = "NOT_RUN"
        else:
            slither = run_slither(path, RAW_DIR / f"{path.stem}.json", timeout, compiler.version)
            slither_status = slither.status
            if slither.status == "SUCCESS":
                findings = parse_findings(slither.payload or {})
                detector_count = len(findings)
                findings_out.extend({**contract, **finding} for finding in findings)
            else:
                failures.append({**contract, "stage": "slither", "error_type": slither.error_type, "error_message": slither.error_message, "resolved_solc_version": compiler.version})

        analysis_status = "SUCCESS" if ast.status == "SUCCESS" and slither_status == "SUCCESS" else "FAILED"
        analysis = {
            **contract,
            "resolved_solc_version": compiler.version,
            "analysis_status": analysis_status,
            "compiler_resolution_status": "SUCCESS",
            "source_compilation_status": ast.source_compilation_status,
            "ast_status": ast.status,
            "slither_status": slither_status,
            "detector_count": detector_count,
            "execution_time_seconds": f"{time.monotonic() - started:.3f}",
        }
        return {"contract": contract, "analysis": analysis, "findings": findings_out, "failures": failures, "ast_record": ast_record}
    except Exception as exc:
        failure = {**contract, "stage": "worker", "error_type": type(exc).__name__, "error_message": str(exc), "resolved_solc_version": ""}
        analysis = {**contract, "resolved_solc_version": "", "analysis_status": "FAILED", "compiler_resolution_status": "FAILED", "source_compilation_status": "NOT_RUN", "ast_status": "FAILED", "slither_status": "FAILED", "detector_count": 0, "execution_time_seconds": f"{time.monotonic() - started:.3f}"}
        return {"contract": contract, "analysis": analysis, "findings": [], "failures": [failure], "ast_record": None}


def checkpoint(
    analysis_rows: list[dict[str, object]],
    finding_rows: list[dict[str, object]],
    failure_rows: list[dict[str, object]],
) -> None:
    write_rows(ANALYSIS_PATH, ANALYSIS_FIELDS, analysis_rows)
    write_rows(FINDINGS_PATH, FINDING_FIELDS, finding_rows)
    write_rows(FAILED_PATH, FAILED_FIELDS, failure_rows)


def remove_selected_rows(rows: list[dict[str, object]], selected_ids: set[str]) -> list[dict[str, object]]:
    return [row for row in rows if ident(row) not in selected_ids]


def count_selected_ast_records(selected_ids: set[str]) -> tuple[int, int]:
    keys: list[str] = []
    if AST_JSONL_PATH.exists():
        with AST_JSONL_PATH.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                    key = str(Path(payload.get("filepath", "")).resolve()).lower()
                except (json.JSONDecodeError, OSError):
                    continue
                if key in selected_ids:
                    keys.append(key)
    return len(keys), len(keys) - len(set(keys))


def final_summary(selected: list[dict[str, str]]) -> None:
    selected_ids = {ident(row) for row in selected}
    analysis = [row for row in read_rows(ANALYSIS_PATH) if ident(row) in selected_ids]
    findings = [row for row in read_rows(FINDINGS_PATH) if ident(row) in selected_ids]
    failures = [row for row in read_rows(FAILED_PATH) if ident(row) in selected_ids]
    ast_records, duplicate_ast_records = count_selected_ast_records(selected_ids)
    duplicate_contracts = len(analysis) - len({ident(row) for row in analysis})
    print("\n========================================")
    print("PIPELINE SUMMARY")
    print("========================================")
    print(f"Contracts selected: {len(selected)}")
    print(f"Compiler resolution successes: {sum(row.get('compiler_resolution_status') == 'SUCCESS' for row in analysis)}")
    print(f"Source compilation successes: {sum(row.get('source_compilation_status') == 'SUCCESS' for row in analysis)}")
    print(f"Compiler failures: {sum(row.get('stage') == 'compiler' for row in failures)}")
    print(f"AST successes: {sum(row.get('ast_status') == 'SUCCESS' for row in analysis)}")
    print(f"AST failures: {sum(row.get('stage') == 'ast' for row in failures)}")
    print(f"Slither successes: {sum(row.get('slither_status') == 'SUCCESS' for row in analysis)}")
    print(f"Slither failures: {sum(row.get('stage') == 'slither' for row in failures)}")
    print(f"Total findings: {len(findings)}")
    print(f"AST records: {ast_records}")
    print(f"Duplicate contracts: {duplicate_contracts}")
    print(f"Duplicate AST records: {duplicate_ast_records}")
    print("========================================")


def apply_worker_result(
    result: dict[str, object],
    analysis_rows: list[dict[str, object]],
    finding_rows: list[dict[str, object]],
    failure_rows: list[dict[str, object]],
    ast_keys: set[str],
) -> tuple[bool, int]:
    contract = result["contract"]
    key = ident(contract)
    analysis_rows[:] = [row for row in analysis_rows if ident(row) != key]
    finding_rows[:] = [row for row in finding_rows if ident(row) != key]
    failure_rows[:] = [row for row in failure_rows if ident(row) != key]
    analysis = result["analysis"]
    analysis_rows.append(analysis)
    finding_rows.extend(result["findings"])
    failure_rows.extend(result["failures"])
    ast_record = result.get("ast_record")
    if ast_record is not None and key not in ast_keys:
        append_ast_json_record(ast_record)
        ast_keys.add(key)
    return analysis.get("analysis_status") == "SUCCESS", len(result["findings"])


def retry_failed_ast(timeout: int) -> int:
    """Refresh only the AST state for the investigated failures; never invoke Slither."""
    ensure_directories()
    report_path = ANALYSIS_PATH.parent / "ast_failure_investigation_first_500.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    names = {item["filename"] for item in report["contracts"]}
    selected = [row for row in select_contracts(None) if row["filename"] in names]
    if len(selected) != len(names):
        raise RuntimeError(f"Expected {len(names)} retry contracts, found {len(selected)} in index.csv")
    analysis_rows: list[dict[str, object]] = read_rows(ANALYSIS_PATH)
    finding_rows: list[dict[str, object]] = read_rows(FINDINGS_PATH)
    failure_rows: list[dict[str, object]] = read_rows(FAILED_PATH)
    ast_keys = read_ast_keys(AST_JSONL_PATH)
    compiler_cache = {}
    recovered: list[str] = []
    remaining: list[str] = []
    for contract in selected:
        key = ident(contract)
        existing = next((row for row in analysis_rows if ident(row) == key), None)
        if existing is None:
            raise RuntimeError(f"Missing existing analysis row for {contract['filename']}")
        path = Path(contract["filepath"])
        source_pragmas = extract_pragmas(path.read_text(encoding="utf-8", errors="replace"))
        contract = {**contract, "pragma": " ".join(source_pragmas) or contract.get("pragma", "")}
        try:
            constraint_key = tuple(source_pragmas or [contract["pragma"]])
            compiler = compiler_cache.get(constraint_key)
            if compiler is None:
                compiler = resolve_compiler(list(constraint_key))
                compiler_cache[constraint_key] = compiler
            if compiler.status != "SUCCESS":
                raise RuntimeError(compiler.error_message or compiler.error_type)
            ast = run_ast(path, timeout, compiler.version)
            existing.update({
                "pragma": contract["pragma"], "resolved_solc_version": compiler.version,
                "compiler_resolution_status": "SUCCESS", "source_compilation_status": ast.source_compilation_status,
                "ast_status": ast.status,
            })
            failure_rows[:] = [row for row in failure_rows if not (ident(row) == key and row.get("stage") == "ast")]
            if ast.status == "SUCCESS" and ast.ast is not None:
                if key not in ast_keys:
                    append_ast_json_record(make_ast_record(contract, compiler.version, ast.ast))
                    ast_keys.add(key)
                recovered.append(contract["filename"])
            else:
                failure_rows.append({**contract, "stage": "ast", "error_type": ast.error_type, "error_message": ast.error_message, "resolved_solc_version": compiler.version})
                remaining.append(contract["filename"])
        except Exception as exc:
            existing.update({"compiler_resolution_status": "FAILED", "source_compilation_status": "NOT_RUN", "ast_status": "NOT_RUN"})
            failure_rows[:] = [row for row in failure_rows if not (ident(row) == key and row.get("stage") == "ast")]
            failure_rows.append({**contract, "stage": "compiler", "error_type": type(exc).__name__, "error_message": str(exc), "resolved_solc_version": ""})
            remaining.append(contract["filename"])
        checkpoint(analysis_rows, finding_rows, failure_rows)
    print(json.dumps({"retried": len(selected), "ast_recovered": len(recovered), "recovered": recovered, "remaining_failed": remaining}, indent=2))
    return 0


def run(limit: int = 100, full: bool = False, timeout: int = 120, force: bool = False, workers: int = 1) -> int:
    ensure_directories()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(LOG_PATH, encoding="utf-8"), logging.StreamHandler(sys.stdout)],
        force=True,
    )
    log = logging.getLogger("pipeline")
    selected = select_contracts(None if full else limit)
    print(f"Selected {len(selected)} contracts for analysis.")
    if workers < 1:
        raise ValueError("--workers must be at least 1")
    print(f"Workers: {workers}")
    selected_ids = {ident(row) for row in selected}
    analysis_rows: list[dict[str, object]] = read_rows(ANALYSIS_PATH)
    finding_rows: list[dict[str, object]] = read_rows(FINDINGS_PATH)
    failure_rows: list[dict[str, object]] = read_rows(FAILED_PATH) if ANALYSIS_PATH.exists() else []

    if force:
        analysis_rows = remove_selected_rows(analysis_rows, selected_ids)
        finding_rows = remove_selected_rows(finding_rows, selected_ids)
        failure_rows = remove_selected_rows(failure_rows, selected_ids)
        rewrite_ast_jsonl_without(AST_JSONL_PATH, selected_ids)

    completed = {ident(row) for row in analysis_rows if row.get("analysis_status") == "SUCCESS"}
    todo = [contract for contract in selected if ident(contract) not in completed]
    retry_ids = {ident(contract) for contract in todo}
    analysis_rows = remove_selected_rows(analysis_rows, retry_ids)
    finding_rows = remove_selected_rows(finding_rows, retry_ids)
    failure_rows = remove_selected_rows(failure_rows, retry_ids)
    rewrite_ast_jsonl_without(AST_JSONL_PATH, retry_ids)
    ast_keys = read_ast_keys(AST_JSONL_PATH)

    skipped = len(selected) - len(todo)
    for number, contract in enumerate(selected, 1):
        if ident(contract) in completed:
            print(f"[{number}/{len(selected)}] Skipping {contract['filename']} (already SUCCESS)")
    if skipped:
        checkpoint(analysis_rows, finding_rows, failure_rows)

    progress_completed = skipped
    progress_successful = sum(row.get("analysis_status") == "SUCCESS" for row in analysis_rows if ident(row) in selected_ids)
    progress_failed = sum(row.get("analysis_status") == "FAILED" for row in analysis_rows if ident(row) in selected_ids)

    if workers == 1:
        for contract in todo:
            log.info("Processing %s", contract["filepath"])
            result = process_contract(contract, timeout)
            success, _ = apply_worker_result(result, analysis_rows, finding_rows, failure_rows, ast_keys)
            progress_completed += 1
            progress_successful += 1 if success else 0
            progress_failed += 0 if success else 1
            checkpoint(analysis_rows, finding_rows, failure_rows)
            active = 0
            print(f"[{progress_completed}/{len(selected)}] completed | successful: {progress_successful} | failed: {progress_failed} | active: {active}")
    elif todo:
        with Manager() as manager:
            compiler_lock = manager.Lock()
            with ProcessPoolExecutor(max_workers=workers, initializer=init_worker, initargs=(compiler_lock,)) as executor:
                futures = {executor.submit(process_contract, contract, timeout): contract for contract in todo}
                for future in as_completed(futures):
                    contract = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            "contract": contract,
                            "analysis": {**contract, "resolved_solc_version": "", "analysis_status": "FAILED", "compiler_resolution_status": "FAILED", "source_compilation_status": "NOT_RUN", "ast_status": "FAILED", "slither_status": "FAILED", "detector_count": 0, "execution_time_seconds": "0.000"},
                            "findings": [],
                            "failures": [{**contract, "stage": "worker", "error_type": type(exc).__name__, "error_message": str(exc), "resolved_solc_version": ""}],
                            "ast_record": None,
                        }
                    success, _ = apply_worker_result(result, analysis_rows, finding_rows, failure_rows, ast_keys)
                    progress_completed += 1
                    progress_successful += 1 if success else 0
                    progress_failed += 0 if success else 1
                    checkpoint(analysis_rows, finding_rows, failure_rows)
                    active = len(futures) - (progress_completed - skipped)
                    print(f"[{progress_completed}/{len(selected)}] completed | successful: {progress_successful} | failed: {progress_failed} | active: {active}")

    checkpoint(analysis_rows, finding_rows, failure_rows)
    final_summary(selected)
    return 0


if __name__ == "__main__":
    parsed = args()
    try:
        raise SystemExit(retry_failed_ast(parsed.timeout) if parsed.retry_failed_ast else run(parsed.limit, parsed.full, parsed.timeout, parsed.force, parsed.workers))
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
