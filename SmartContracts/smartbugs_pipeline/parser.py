"""Convert Slither detector JSON into stable tabular finding records."""

from __future__ import annotations

from typing import Any


def _element_details(elements: list[dict[str, Any]]) -> tuple[str, str, str]:
    contracts: set[str] = set()
    functions: set[str] = set()
    locations: set[str] = set()
    for element in elements:
        fields = element.get("source_mapping") or {}
        lines = fields.get("lines") or []
        filename = fields.get("filename_relative") or fields.get("filename_short") or ""
        if lines:
            locations.add(f"{filename}:{','.join(str(line) for line in lines)}".lstrip(":"))
        name = str(element.get("name") or "")
        kind = str(element.get("type") or "").lower()
        parent = element.get("type_specific_fields") or {}
        parent_contract = parent.get("parent") or {}
        if isinstance(parent_contract, dict) and parent_contract.get("name"):
            contracts.add(str(parent_contract["name"]))
        if kind == "contract" and name:
            contracts.add(name)
        elif kind in {"function", "modifier"} and name:
            functions.add(name)
    return ";".join(sorted(contracts)), ";".join(sorted(functions)), ";".join(sorted(locations))


def parse_findings(payload: dict[str, Any]) -> list[dict[str, str]]:
    detectors = ((payload.get("results") or {}).get("detectors") or [])
    findings: list[dict[str, str]] = []
    for detector in detectors:
        contract, function, source_lines = _element_details(detector.get("elements") or [])
        findings.append({
            "detector": str(detector.get("check") or ""),
            "impact": str(detector.get("impact") or ""),
            "confidence": str(detector.get("confidence") or ""),
            "description": str(detector.get("description") or "").strip(),
            "contract": contract,
            "function": function,
            "source_lines": source_lines,
        })
    return findings
