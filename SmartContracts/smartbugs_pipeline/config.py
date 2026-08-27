from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
DATA_DIR = PROJECT_DIR / "data"
INDEX_PATH = DATA_DIR / "index.csv"
RESULTS_PATH = DATA_DIR / "results.csv"
SUMMARY_PATH = DATA_DIR / "contract_summary.csv"
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


def ensure_directories() -> None:
    for directory in (DATA_DIR, RAW_DIR, LOG_DIR):
        directory.mkdir(parents=True, exist_ok=True)
