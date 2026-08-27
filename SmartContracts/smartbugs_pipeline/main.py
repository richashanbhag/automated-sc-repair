from __future__ import annotations
import argparse, csv, logging, sys
from collections import Counter
from pathlib import Path
from compiler import resolve_compiler
from config import (FAILED_FIELDS, FAILED_PATH, INDEX_PATH, LOG_PATH, RAW_DIR,
                    RESULT_FIELDS, RESULTS_PATH, SUMMARY_FIELDS, SUMMARY_PATH,
                    ensure_directories)
from mapper import FindingMapper
from parser import parse_findings
from slither_runner import run_slither

def args():
    p = argparse.ArgumentParser(description="Sequential SmartBugs Wild Slither pipeline")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--force", action="store_true")
    return p.parse_args()

def ident(row): return str(Path(row["filepath"]).resolve()).lower()

def read_rows(path):
    if not path.exists() or not path.stat().st_size: return []
    with path.open(newline="", encoding="utf-8") as f: return list(csv.DictReader(f))

def write_rows(path, fields, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader(); w.writerows(rows)

def select(limit):
    if limit < 1: raise ValueError("--limit must be at least 1")
    if not INDEX_PATH.exists(): raise FileNotFoundError(f"Required Phase 1 artifact missing: {INDEX_PATH}")
    chosen = []
    with INDEX_PATH.open(newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if "valid" in row and row["valid"].strip().lower() in {"", "0", "false", "no", "invalid"}: continue
            path = row.get("filepath") or row.get("path") or ""
            if not path: continue
            row["filepath"] = path
            row["filename"] = row.get("filename") or Path(path).name
            row["pragma"] = row.get("pragma") or row.get("compiler_constraint") or ""
            chosen.append(row)
            if len(chosen) == limit: break
    return chosen

def checkpoint(results, summaries, failures):
    write_rows(RESULTS_PATH, RESULT_FIELDS, results)
    write_rows(SUMMARY_PATH, SUMMARY_FIELDS, summaries)
    write_rows(FAILED_PATH, FAILED_FIELDS, failures)

def run(limit=100, timeout=120, force=False):
    ensure_directories()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(LOG_PATH, encoding="utf-8"), logging.StreamHandler(sys.stdout)], force=True)
    log = logging.getLogger("pipeline"); chosen = select(limit)
    print(f"Selected {len(chosen)} contracts for analysis.")
    mapper = FindingMapper(); summaries = read_rows(SUMMARY_PATH)
    results, failures = read_rows(RESULTS_PATH), read_rows(FAILED_PATH)
    chosen_ids = {ident(x) for x in chosen}
    if force:
        summaries = [x for x in summaries if ident(x) not in chosen_ids]
        results = [x for x in results if ident(x) not in chosen_ids]
        failures = [x for x in failures if ident(x) not in chosen_ids]
    done = {ident(x) for x in summaries if x.get("analysis_status") == "SUCCESS"}
    counts, detector_counts = Counter(), Counter()
    for number, contract in enumerate(chosen, 1):
        path, key = Path(contract["filepath"]), ident(contract)
        if key in done:
            print(f"[{number}/{len(chosen)}] Skipping {contract['filename']} (already SUCCESS)")
            counts["skipped"] += 1; continue
        # A retry replaces the contract's previous terminal state instead of duplicating it.
        summaries = [x for x in summaries if ident(x) != key]
        results = [x for x in results if ident(x) != key]
        failures = [x for x in failures if ident(x) != key]
        print(f"\n[{number}/{len(chosen)}] Processing {contract['filename']}"); log.info("Processing %s", path)
        if not path.is_file():
            failures.append({**contract, "stage":"input", "error_type":"unreadable_file",
                "error_message":"Contract path is not a readable file", "resolved_solc_version":""})
            summaries.append({**contract, "resolved_solc_version":"", "analysis_status":"FAILED",
                "detector_count":0, "detectors":"", "SWCs":"", "CWEs":"", "execution_time_seconds":"0.000"})
            counts["slither_failures"] += 1; checkpoint(results, summaries, failures); continue
        compiler = resolve_compiler(contract["pragma"])
        print(f"Compiler: {compiler.version or 'FAILED'}"); log.info("Compiler %s (%s)", compiler.version or "unresolved", compiler.status)
        if compiler.status != "SUCCESS":
            failures.append({**contract, "stage":"compiler", "error_type":compiler.error_type,
                "error_message":compiler.error_message, "resolved_solc_version":compiler.version})
            summaries.append({**contract, "resolved_solc_version":compiler.version, "analysis_status":"FAILED",
                "detector_count":0, "detectors":"", "SWCs":"", "CWEs":"", "execution_time_seconds":"0.000"})
            counts["compiler_failures"] += 1; print("Slither: NOT RUN")
            log.error("Compiler failure: %s", compiler.error_message); checkpoint(results, summaries, failures); continue
        log.info("Slither start: %s", path)
        outcome = run_slither(path, RAW_DIR / f"{path.stem}.json", timeout)
        if outcome.status != "SUCCESS":
            failures.append({**contract, "stage":"slither", "error_type":outcome.error_type,
                "error_message":outcome.error_message, "resolved_solc_version":compiler.version})
            summaries.append({**contract, "resolved_solc_version":compiler.version, "analysis_status":"FAILED",
                "detector_count":0, "detectors":"", "SWCs":"", "CWEs":"",
                "execution_time_seconds":f"{outcome.elapsed:.3f}"})
            counts["timeouts" if outcome.error_type == "timeout" else "slither_failures"] += 1
            print(f"Slither: {'TIMEOUT' if outcome.error_type == 'timeout' else 'FAILED'}")
            log.error("Slither failure: %s", outcome.error_message); checkpoint(results, summaries, failures); continue
        findings, enriched = parse_findings(outcome.payload or {}), []
        for finding in findings:
            swc, cwe = mapper.map(finding["detector"]); detector_counts[finding["detector"]] += 1
            enriched.append({**contract, "resolved_solc_version":compiler.version,
                "analysis_status":"SUCCESS", **finding, "SWC":swc, "CWE":cwe})
        results.extend(enriched or [{**contract, "resolved_solc_version":compiler.version,
            "analysis_status":"SUCCESS", "detector":"", "impact":"", "confidence":"",
            "description":"", "contract":"", "function":"", "source_lines":"", "SWC":"UNKNOWN", "CWE":"UNKNOWN"}])
        summaries.append({**contract, "resolved_solc_version":compiler.version, "analysis_status":"SUCCESS",
            "detector_count":len(findings), "detectors":";".join(sorted({x["detector"] for x in enriched})),
            "SWCs":";".join(sorted({x["SWC"] for x in enriched})), "CWEs":";".join(sorted({x["CWE"] for x in enriched})),
            "execution_time_seconds":f"{outcome.elapsed:.3f}"})
        counts["success"] += 1; counts["findings"] += len(findings)
        print(f"Slither: SUCCESS\nFindings: {len(findings)}")
        log.info("Slither completion; findings=%d; seconds=%.3f", len(findings), outcome.elapsed)
        checkpoint(results, summaries, failures)
    checkpoint(results, summaries, failures)
    final_summaries = [x for x in summaries if ident(x) in chosen_ids]
    final_failures = [x for x in failures if ident(x) in chosen_ids]
    final_results = [x for x in results if ident(x) in chosen_ids and x.get("detector")]
    all_detectors = Counter(x["detector"] for x in final_results)
    success_total = sum(x.get("analysis_status") == "SUCCESS" for x in final_summaries)
    compiler_failed = sum(x.get("stage") == "compiler" for x in final_failures)
    timeouts = sum(x.get("error_type") == "timeout" for x in final_failures)
    slither_failed = sum(x.get("stage") in {"slither", "input"} and x.get("error_type") != "timeout" for x in final_failures)
    print("\n========================================\nPIPELINE SUMMARY\n========================================")
    print(f"Contracts selected: {len(chosen)}\nSuccessfully analyzed: {success_total} (skipped existing: {counts['skipped']})")
    print(f"Compiler failures: {compiler_failed}\nSlither failures: {slither_failed}")
    print(f"Timeouts: {timeouts}\nTotal findings: {len(final_results)}\n\nTop 10 Slither detectors:")
    for name, count in all_detectors.most_common(10): print(f"  {name}: {count}")
    print("========================================")
    return 0

if __name__ == "__main__":
    a = args()
    try: raise SystemExit(run(a.limit, a.timeout, a.force))
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr); raise SystemExit(2)
