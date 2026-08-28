from dataclasses import dataclass
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
DATA_DIR = PROJECT_DIR / "data"
INDEX_PATH = DATA_DIR / "index.csv"
RESULTS_PATH = DATA_DIR / "results.csv"
SUMMARY_PATH = DATA_DIR / "contract_summary.csv"
ANALYSIS_PATH = DATA_DIR / "analysis.csv"
FINDINGS_PATH = DATA_DIR / "findings.csv"
AST_JSONL_PATH = DATA_DIR / "ast.jsonl"
FAILED_PATH = DATA_DIR / "failed.csv"
RAW_DIR = DATA_DIR / "slither_raw"
LOG_DIR = DATA_DIR / "logs"
LOG_PATH = LOG_DIR / "slither_pipeline.log"
MAPPINGS_DIR = PROJECT_DIR / "mappings"
DEFAULT_CONTRACTS_DIR = PROJECT_DIR.parent / "smartbugs-wild" / "contracts"

RESULT_FIELDS = [
    "filename", "filepath", "pragma", "resolved_solc_version", "analysis_status",
    "detector", "impact", "confidence", "description", "contract", "function",
    "source_lines", "SWC", "CWE",
]
SUMMARY_FIELDS = [
    "filename", "filepath", "pragma", "resolved_solc_version", "analysis_status",
    "detector_count", "detectors", "SWCs", "CWEs", "execution_time_seconds",
]
FAILED_FIELDS = [
    "filename", "filepath", "stage", "error_type", "error_message", "pragma",
    "resolved_solc_version",
]
ANALYSIS_FIELDS = [
    "filename", "filepath", "pragma", "resolved_solc_version", "analysis_status",
    "compiler_resolution_status", "source_compilation_status", "ast_status", "slither_status", "detector_count",
    "execution_time_seconds",
]
FINDING_FIELDS = [
    "filename", "filepath", "detector", "impact", "confidence", "description",
    "contract", "function", "source_lines",
]


@dataclass(frozen=True)
class OutputPaths:
    """All mutable artifacts for one pipeline run."""

    analysis: Path
    findings: Path
    ast_jsonl: Path
    failed: Path
    raw_dir: Path
    log_path: Path


def output_paths(start: int | None = None, end: int | None = None) -> OutputPaths:
    """Return default outputs or an isolated, inclusive index-row range chunk."""
    if (start is None) != (end is None):
        raise ValueError("Both range bounds are required")
    if start is None:
        return OutputPaths(ANALYSIS_PATH, FINDINGS_PATH, AST_JSONL_PATH, FAILED_PATH, RAW_DIR, LOG_PATH)
    suffix = f"{start}_{end}"
    return OutputPaths(
        DATA_DIR / f"analysis_{suffix}.csv",
        DATA_DIR / f"findings_{suffix}.csv",
        DATA_DIR / f"ast_{suffix}.jsonl",
        DATA_DIR / f"failed_{suffix}.csv",
        DATA_DIR / f"slither_raw_{suffix}",
        LOG_DIR / f"slither_pipeline_{suffix}.log",
    )


def ensure_directories() -> None:
    for directory in (DATA_DIR, RAW_DIR, LOG_DIR):
        directory.mkdir(parents=True, exist_ok=True)
