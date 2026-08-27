from __future__ import annotations

import json
from pathlib import Path

from config import MAPPINGS_DIR


class FindingMapper:
    def __init__(self, mapping_dir: Path = MAPPINGS_DIR) -> None:
        self.detector_to_swc = json.loads((mapping_dir / "detector_to_swc.json").read_text(encoding="utf-8"))
        self.swc_to_cwe = json.loads((mapping_dir / "swc_to_cwe.json").read_text(encoding="utf-8"))

    def map(self, detector: str) -> tuple[str, str]:
        swc = self.detector_to_swc.get(detector)
        if swc is None and detector.startswith("reentrancy-"):
            swc = self.detector_to_swc.get("reentrancy-*")
        swc = swc or "UNKNOWN"
        return swc, self.swc_to_cwe.get(swc, "UNKNOWN")
