# SmartBugs Wild analysis pipeline

Phase 2 reads `data/index.csv` in its existing order, resolves and activates a compatible
Solidity compiler through `solc-select`, captures compiler ASTs, runs Slither sequentially
with JSON output, and checkpoints every terminal contract state. Classification is kept out
of this collection step.

## Requirements

```powershell
python -m pip install slither-analyzer solc-select
```

## Run

```powershell
python main.py --limit 10
python main.py --limit 100
python main.py --limit 500 --workers 4
python main.py --full --workers 4
python main.py --full --workers 4 --force
```

The default command does not process the full dataset; only `--full` selects every valid
contract. `--workers` uses a process-based worker pool; the default is `1` for the original
sequential behavior. Successful contracts in `data/analysis.csv` are skipped unless
`--force` is used. Failures are retried on the next ordinary run and replaced rather than
duplicated.

The active scale-out outputs are:

- `data/analysis.csv`: one row per selected contract.
- `data/findings.csv`: one row per Slither finding, without filtering or classification.
- `data/ast.jsonl`: one compiler-produced AST JSON object per successfully compiled contract.
- `data/slither_raw/*.json`: raw Slither JSON, one file per successfully analyzed contract.
- `data/failed.csv`: recorded failures with stage and reason.

The supplied workspace was missing the Phase 1 `index.csv`. `bootstrap_index.py` was used
once to recover it deterministically from the contract directory; normal Phase 2 execution
does not invoke that utility or rescan the dataset.

## Dataset outputs

- `data/results.csv` is the previous 100-contract detailed detector-level experiment.
- `data/access_control_results.csv` is the derived one-row-per-contract Access Control
  dataset. `DEFINITE` means a strong authorization/access-control detector was found;
  `POTENTIAL` means an asset-transfer/control-flow finding requires contextual review; and
  `NONE` means no relevant pattern was identified. Its `NO` value means Slither did not
  identify an Access Control pattern; it does not prove the contract is safe. Aggregate
  counts and row-uniqueness validation are in `data/access_control_summary.json`.
