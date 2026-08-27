"""Recover the Phase 1 CSV artifact missing from the supplied workspace."""
import csv
import re
from pathlib import Path
from config import DEFAULT_CONTRACTS_DIR, INDEX_PATH, ensure_directories

PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.I)

def build_index(contracts_dir: Path = DEFAULT_CONTRACTS_DIR, output: Path = INDEX_PATH) -> int:
    ensure_directories()
    paths = sorted(contracts_dir.glob("*.sol"), key=lambda path: path.name.lower())
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["filename", "filepath", "pragma", "compiler_constraint", "valid"])
        writer.writeheader()
        for path in paths:
            try:
                match = PRAGMA_RE.search(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                match = None
            pragma = f"pragma solidity {match.group(1).strip()};" if match else ""
            writer.writerow({"filename": path.name, "filepath": str(path.resolve()), "pragma": pragma,
                             "compiler_constraint": pragma, "valid": str(bool(match)).lower()})
    return len(paths)

if __name__ == "__main__":
    print(f"Indexed {build_index()} contracts into {INDEX_PATH}")
