# Private Evaluation Harness

Measures AutoASM-NG against an expert ground truth (the findings you produced by
hand on real engagements). Powers the Chapter Five experiments.

## Confidentiality

- `eval/private/` is **git-ignored**. Real client domains and findings never get
  committed or pushed.
- Use **anonymised codes** (`bankA`, `bankB`, ...) as the `code` field. The
  dissertation refers to "Bank A", "Bank B", etc. No client is ever named.
- Only aggregate metrics go into the report.

## Setup

1. Copy `private/bankA.example.json` to `private/bankA.json` (drop `.example`).
2. Fill in the real `domains`, `known_assets`, `known_exposures`, and optional
   `expert_ranking` from your engagement notes for that client.
3. Repeat per client: `bankB.json`, `bankC.json`, ...

## Run

```bash
python -m eval.harness run eval/private/bankA.json     # one target
python -m eval.harness all eval/private/               # all + aggregate
```

## Metrics (mapped to objectives)

| Field | Experiment | Target |
|-------|-----------|--------|
| `E1_asset_recall` | Asset discovery recall | >= 0.90 |
| `E3_exposure_coverage` | Known exposures the tool flagged | >= 0.70 |
| `E4_risk_spearman` | Risk ranking vs your expert ranking | >= 0.85 |
| `E5_scan_under_4h` | Full scan under 4 hours | true |

Precision (E2) and false-positive rate: review
`unmatched_for_precision_triage` in the output. Confirm each as a true or false
positive, then precision = true / (true + false).
