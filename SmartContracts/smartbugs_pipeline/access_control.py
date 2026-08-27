"""Build the one-row-per-contract Access Control dataset without running Slither."""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from config import DATA_DIR, FAILED_PATH, RAW_DIR, RESULTS_PATH
from mapper import FindingMapper

OUTPUT_PATH = DATA_DIR / "access_control_results.csv"
SUMMARY_OUTPUT_PATH = DATA_DIR / "access_control_summary.json"

OUTPUT_FIELDS = [
    "filename", "filepath", "pragma", "resolved_solc_version", "analysis_status",
    "access_control_category", "access_control_detected", "slither_detectors", "SWC",
    "CWE", "severity", "confidence", "evidence", "relevance_notes",
]

# Strong authorization/access-control weaknesses.
DEFINITE_DETECTORS = {
    "controlled-delegatecall",
    "delegatecall-loop",
    "suicidal",
    "tx-origin",
    "unprotected-upgrade",
}

# Asset-transfer/control-flow findings that require contract-specific authorization review.
POTENTIAL_DETECTORS = {
    "arbitrary-send-erc20",
    "arbitrary-send-eth",
}

ACCESS_CONTROL_DETECTORS = DEFINITE_DETECTORS | POTENTIAL_DETECTORS


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Required existing artifact is missing: {path}")
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def _unique(values) -> list[str]:
    return list(dict.fromkeys(value.strip() for value in values if value and value.strip()))


def build_access_control_dataset() -> dict[str, object]:
    results = _read_csv(RESULTS_PATH)
    failures = _read_csv(FAILED_PATH)
    failed_by_path = {row["filepath"].lower(): row for row in failures}
    # Establish the contract universe only from the requested existing artifacts. A
    # successful no-finding placeholder in results.csv still contributes one contract.
    contracts_by_path: dict[str, dict[str, str]] = {}
    for row in results:
        contracts_by_path.setdefault(row["filepath"].lower(), row)
    for row in failures:
        contracts_by_path.setdefault(row["filepath"].lower(), row)
    contracts = list(contracts_by_path.values())
    raw_contracts = {path.stem.lower() for path in RAW_DIR.glob("*.json")}
    findings_by_path: dict[str, list[dict[str, str]]] = defaultdict(list)
    for finding in results:
        if finding.get("detector", "").strip() in ACCESS_CONTROL_DETECTORS:
            findings_by_path[finding["filepath"].lower()].append(finding)

    mapper = FindingMapper()
    output_rows: list[dict[str, str]] = []
    detector_counts: Counter[str] = Counter()
    swc_counts: Counter[str] = Counter()
    cwe_counts: Counter[str] = Counter()

    for contract in contracts:
        key = contract["filepath"].lower()
        findings = findings_by_path.get(key, [])
        detectors = _unique(item["detector"] for item in findings)
        if any(detector in DEFINITE_DETECTORS for detector in detectors):
            category = "DEFINITE"
            relevance_notes = "Strong static evidence of an Access Control-related weakness."
        elif any(detector in POTENTIAL_DETECTORS for detector in detectors):
            category = "POTENTIAL"
            relevance_notes = "Candidate requiring BERT/LLM/manual contextual analysis; POTENTIAL is not a vulnerability determination."
        else:
            category = "NONE"
            relevance_notes = "No relevant Slither Access Control finding; this does not prove the contract is safe."
        mapped = [mapper.map(item["detector"]) for item in findings]
        swcs = _unique(swc for swc, _ in mapped)
        cwes = _unique(cwe for _, cwe in mapped)
        for item, (swc, cwe) in zip(findings, mapped):
            detector_counts[item["detector"]] += 1
            swc_counts[swc] += 1
            cwe_counts[cwe] += 1
        evidence = _unique(
            f"[{item['detector']}] {item.get('description', '').strip()}"
            for item in findings
        )
        status = contract.get("analysis_status", "SUCCESS")
        if key in failed_by_path:
            status = "FAILED"
        output_rows.append({
            "filename": contract.get("filename", ""),
            "filepath": contract.get("filepath", ""),
            "pragma": contract.get("pragma", ""),
            "resolved_solc_version": contract.get("resolved_solc_version", ""),
            "analysis_status": status,
            "access_control_category": category,
            "access_control_detected": "NO" if category == "NONE" else "YES",
            "slither_detectors": "; ".join(detectors),
            "SWC": "; ".join(swcs),
            "CWE": "; ".join(cwes),
            "severity": "; ".join(_unique(item.get("impact", "") for item in findings)),
            "confidence": "; ".join(_unique(item.get("confidence", "") for item in findings)),
            "evidence": " || ".join(evidence),
            "relevance_notes": relevance_notes,
        })

    # The requested output is always rebuilt from scratch, never updated in place.
    if OUTPUT_PATH.exists():
        OUTPUT_PATH.unlink()
    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(output_rows)

    unique_contracts = len({row["filepath"].lower() for row in output_rows})
    duplicates = len(output_rows) - unique_contracts
    category_counts = Counter(row["access_control_category"] for row in output_rows)
    summary: dict[str, object] = {
        "total_contracts": len(output_rows),
        "DEFINITE_count": category_counts["DEFINITE"],
        "POTENTIAL_count": category_counts["POTENTIAL"],
        "NONE_count": category_counts["NONE"],
        "detector_counts": dict(sorted(detector_counts.items())),
        "SWC_counts": dict(sorted(swc_counts.items())),
        "CWE_counts": dict(sorted(cwe_counts.items())),
        "category_interpretation": {
            "DEFINITE": "Strong static evidence of an Access Control-related weakness.",
            "POTENTIAL": "Candidate requiring BERT/LLM/manual contextual analysis; not a vulnerability determination.",
            "NONE": "No relevant Slither Access Control finding.",
        },
        "validation": {"rows": len(output_rows), "unique_contracts": unique_contracts, "duplicates": duplicates},
        "no_finding_note": "NO means Slither did not identify an Access Control pattern; it does not prove the contract is safe.",
    }
    summary["validation"]["raw_json_files"] = len(raw_contracts)
    SUMMARY_OUTPUT_PATH.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if len(output_rows) != unique_contracts or duplicates:
        raise RuntimeError(f"One-row-per-contract validation failed: rows={len(output_rows)}, unique={unique_contracts}, duplicates={duplicates}")
    return summary


if __name__ == "__main__":
    report = build_access_control_dataset()
    validation = report["validation"]
    print(f"rows == unique contracts: {validation['rows']} == {validation['unique_contracts']}")
    print(f"duplicates == {validation['duplicates']}")
