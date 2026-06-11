"""Private evaluation harness for AutoASM-NG (Chapter Five experiments).

Measures the platform against an expert ground truth that the operator built by
hand on real engagements. This file is generic and safe to commit. The actual
client data lives in eval/private/ which is git-ignored and never leaves the
machine. No client name, domain, or finding is hard-coded here.

Ground-truth file format (eval/private/<code>.json):
{
  "code": "bankA",                       # anonymised label used in the dissertation
  "organisation": "Bank A",
  "domains": ["example.com", "example.ng"],
  "default_criticality": 4,
  "known_assets": ["api.example.com", "..."],            # for recall (E1)
  "known_exposures": [                                    # for coverage (E3)
    {"asset": "api.example.com", "class": "exposed-admin-panel"}
  ],
  "expert_ranking": ["api.example.com:exposed-admin-panel", "..."]  # for E4 (optional)
}

Usage:
  python -m eval.harness run  eval/private/bankA.json
  python -m eval.harness all  eval/private/
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from autoasm.orchestrator import Orchestrator
from autoasm.reporting import scan_summary


def _norm(s: str) -> str:
    s = s.strip().lower()
    s = s.split("//")[-1]
    return s.split("/")[0]


def recall(found: set, known: set) -> float:
    if not known:
        return 0.0
    return round(len(found & known) / len(known), 4)


def spearman(rank_a: list[str], rank_b: list[str]) -> float:
    """Spearman rank correlation between two orderings of overlapping items."""
    common = [x for x in rank_a if x in rank_b]
    n = len(common)
    if n < 2:
        return 0.0
    pos_a = {x: i for i, x in enumerate(rank_a) if x in rank_b}
    pos_b = {x: i for i, x in enumerate(rank_b)}
    d2 = sum((pos_a[x] - pos_b[x]) ** 2 for x in common)
    return round(1 - (6 * d2) / (n * (n * n - 1)), 4)


def evaluate(gt_path: str) -> dict:
    gt = json.loads(Path(gt_path).read_text(encoding="utf-8"))
    org = gt.get("organisation", gt.get("code", "target"))
    domains = gt["domains"]

    t0 = time.monotonic()
    orch = Orchestrator(org, domains,
                        default_criticality=gt.get("default_criticality", 3),
                        progress=lambda m: print("   ", m))
    scan_id = orch.run()
    scan_secs = round(time.monotonic() - t0, 1)

    data = scan_summary(scan_id)
    found_assets = {_norm(f["asset"]) for f in data["findings"]}
    known_assets = {_norm(a) for a in gt.get("known_assets", [])}
    e1 = recall(found_assets, known_assets) if known_assets else None

    known_exp = {(_norm(e["asset"]), e["class"]) for e in gt.get("known_exposures", [])}
    found_exp = {(_norm(f["asset"]), f["class"]) for f in data["findings"]}
    e3 = recall(found_exp, known_exp) if known_exp else None

    e4 = None
    if gt.get("expert_ranking"):
        platform_rank = [f"{_norm(f['asset'])}:{f['class']}" for f in data["findings"]]
        expert_rank = [r.lower() for r in gt["expert_ranking"]]
        e4 = spearman(expert_rank, platform_rank)

    # exposures the tool reported that are NOT in the ground truth: triage for precision (E2)
    extra = [{"asset": _norm(f["asset"]), "class": f["class"], "band": f["band"]}
             for f in data["findings"]
             if (_norm(f["asset"]), f["class"]) not in known_exp]

    return {
        "code": gt.get("code", org),
        "organisation": org,
        "scan_id": scan_id,
        "scan_seconds": scan_secs,
        "scan_hours": round(scan_secs / 3600, 2),
        "assets_discovered": data["asset_count"],
        "exposures_found": data["exposure_count"],
        "E1_asset_recall": e1,
        "E3_exposure_coverage": e3,
        "E4_risk_spearman": e4,
        "E5_scan_under_4h": scan_secs < 4 * 3600,
        "known_assets_n": len(known_assets),
        "known_exposures_n": len(known_exp),
        "unmatched_for_precision_triage": extra,
    }


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print(__doc__)
        return 1
    cmd = argv[0]
    if cmd == "run" and len(argv) > 1:
        print(json.dumps(evaluate(argv[1]), indent=2))
        return 0
    if cmd == "all" and len(argv) > 1:
        folder = Path(argv[1])
        results = [evaluate(str(p)) for p in sorted(folder.glob("*.json"))
                   if not p.name.startswith("_")]
        (folder / "_results.json").write_text(json.dumps(results, indent=2),
                                              encoding="utf-8")

        def avg(key):
            vals = [r[key] for r in results if r.get(key) is not None]
            return round(sum(vals) / len(vals), 4) if vals else None

        print("\n=== AGGREGATE ===")
        print(json.dumps({
            "n_targets": len(results),
            "mean_E1_asset_recall": avg("E1_asset_recall"),
            "mean_E3_exposure_coverage": avg("E3_exposure_coverage"),
            "mean_E4_risk_spearman": avg("E4_risk_spearman"),
            "all_under_4h": all(r["E5_scan_under_4h"] for r in results) if results else None,
        }, indent=2))
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
