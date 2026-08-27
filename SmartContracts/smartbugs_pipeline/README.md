# SmartBugs Wild analysis pipeline

Phase 2 reads `data/index.csv` in its existing order, resolves and activates a compatible
Solidity compiler through `solc-select`, runs Slither sequentially with JSON output, maps
reliable detectors to SWC/CWE identifiers, and checkpoints every terminal contract state.
Unknown mappings remain `UNKNOWN`; Slither terminal text is never parsed as findings.

## Requirements

```powershell
python -m pip install slither-analyzer solc-select
```

## Run

```powershell
python main.py --limit 5
python main.py --limit 100
python main.py --limit 100 --timeout 120 --force
```

Successful contracts in `data/contract_summary.csv` are skipped unless `--force` is used.
Failures are retried on the next ordinary run and replaced rather than duplicated. Outputs
are `results.csv`, `contract_summary.csv`, `failed.csv`, `slither_raw/*.json`, and
`logs/slither_pipeline.log` under `data/`.

The supplied workspace was missing the Phase 1 `index.csv`. `bootstrap_index.py` was used
once to recover it deterministically from the contract directory; normal Phase 2 execution
does not invoke that utility or rescan the dataset.

## Dataset outputs

- `data/results.csv` is the detailed detector-level dataset, with one row per Slither finding.
- `data/access_control_results.csv` is the derived one-row-per-contract Access Control
  dataset. `DEFINITE` means a strong authorization/access-control detector was found;
  `POTENTIAL` means an asset-transfer/control-flow finding requires contextual review; and
  `NONE` means no relevant pattern was identified. Its `NO` value means Slither did not
  identify an Access Control pattern; it does not prove the contract is safe. Aggregate
  counts and row-uniqueness validation are in `data/access_control_summary.json`.
