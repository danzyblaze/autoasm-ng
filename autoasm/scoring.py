"""Risk-scoring engine (Chapter 3, §3.4.6; FR9).

RiskScore(e) = C(a) x S(e) x B(e)
  C(a) = normalised asset criticality        in [0.2, 1.0]
  S(e) = CVSS base / 10                       in [0.0, 1.0]
  B(e) = breach-relevance multiplier          in [1.0, 2.0]

B(e) is built from KEV membership, EPSS probability, and the regional
breach-pattern corpus match — the component that distinguishes AutoASM-NG from a
generic CVSS-only scanner.
"""
from __future__ import annotations

from dataclasses import dataclass

from .config import SCORING


@dataclass
class ScoredExposure:
    asset_value: str
    cls: str
    description: str
    criticality: float
    severity: float
    breach_relevance: float
    composite_score: float
    rank: int = 0


def breach_relevance(correlations: list[dict]) -> float:
    """Combine KEV / EPSS / corpus signals into a [1.0, 2.0] multiplier."""
    uplift = 0.0
    if any(c.get("kev_flag") for c in correlations):
        uplift += SCORING.kev_uplift
    epss_vals = [c.get("epss") for c in correlations if c.get("epss") is not None]
    if epss_vals:
        uplift += SCORING.epss_uplift_max * max(epss_vals)
    corpus_weights = [c.get("weight", 0.0) for c in correlations
                      if c.get("source") == "CORPUS"]
    if corpus_weights:
        # normalise the corpus weight (max realistic ~0.47) into its uplift band
        norm = min(1.0, max(corpus_weights) / 0.47)
        uplift += SCORING.corpus_uplift_max * norm
    b = SCORING.breach_relevance_floor + uplift
    return round(min(SCORING.breach_relevance_ceil, b), 4)


def score_one(asset_criticality: int, cvss_base: float,
              correlations: list[dict], asset_value: str = "",
              cls: str = "", description: str = "") -> ScoredExposure:
    c = SCORING.criticality_norm.get(asset_criticality, 0.6)
    s = max(0.0, min(1.0, cvss_base / 10.0))
    b = breach_relevance(correlations)
    composite = round(c * s * b, 4)
    return ScoredExposure(asset_value, cls, description, c, s, b, composite)


def rank(scored: list[ScoredExposure]) -> list[ScoredExposure]:
    ordered = sorted(scored, key=lambda x: x.composite_score, reverse=True)
    for i, se in enumerate(ordered, start=1):
        se.rank = i
    return ordered
