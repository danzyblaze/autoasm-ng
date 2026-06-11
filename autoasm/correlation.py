"""Correlation subsystem (Chapter 3, §3.3 stage 3; FR7-FR8).

Enriches exposures with:
  - NVD CVE matches (by product/version when available)
  - CISA KEV membership (in-the-wild exploitation signal)
  - HIBP domain breach presence
  - anonymised regional breach-pattern corpus (by exposure class)

Returns a list of correlation dicts per exposure. Network calls are cached and
rate-limited; the breach corpus is local.
"""
from __future__ import annotations

import datetime as _dt
import json
from functools import lru_cache
from pathlib import Path

from . import config
from .core import ExposureRecord, http_get


# --------------------------------------------------------------------------
# Local breach-pattern corpus
# --------------------------------------------------------------------------
@lru_cache(maxsize=1)
def load_breach_corpus() -> dict:
    path = config.BREACH_CORPUS_PATH
    if not Path(path).exists():
        return {"patterns": []}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def corpus_match(exposure_cls: str) -> dict | None:
    """Return the best-matching breach pattern for an exposure class, or None."""
    best = None
    for pat in load_breach_corpus().get("patterns", []):
        if exposure_cls in pat.get("maps_exposure_classes", []):
            # prefer the highest prevalence x criticality pattern
            score = pat["prevalence"] * (1 + pat["critical_ratio"])
            if best is None or score > best[0]:
                best = (score, pat)
    return best[1] if best else None


# --------------------------------------------------------------------------
# CISA KEV catalogue (cached daily)
# --------------------------------------------------------------------------
def _cache_file(name: str) -> Path:
    return config.TI_CACHE_DIR / name


def _cache_fresh(path: Path) -> bool:
    if not path.exists():
        return False
    age = _dt.datetime.now().timestamp() - path.stat().st_mtime
    return age < config.TI_CACHE_TTL_HOURS * 3600


@lru_cache(maxsize=1)
def load_kev() -> set[str]:
    cache = _cache_file("kev.json")
    data = None
    if _cache_fresh(cache):
        try:
            data = json.loads(cache.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = None
    if data is None:
        resp = http_get(config.CISA_KEV_URL)
        if resp is not None and resp.status_code == 200:
            try:
                data = resp.json()
                cache.write_text(json.dumps(data), encoding="utf-8")
            except (json.JSONDecodeError, ValueError, OSError):
                data = None
    if not data:
        return set()
    return {v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")}


# --------------------------------------------------------------------------
# NVD CVE lookup by product/version (best-effort, optional)
# --------------------------------------------------------------------------
def nvd_lookup(product: str, version: str | None = None) -> list[dict]:
    if not product:
        return []
    query = product if not version else f"{product} {version}"
    headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else None
    resp = http_get(f"{config.NVD_API}?keywordSearch={query}&resultsPerPage=5",
                    headers=headers)
    if resp is None or resp.status_code != 200:
        return []
    out = []
    try:
        for item in resp.json().get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id")
            metrics = cve.get("metrics", {})
            base = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    base = metrics[key][0]["cvssData"].get("baseScore", 0.0)
                    break
            if cid:
                out.append({"cve_id": cid, "cvss_base": base})
    except (json.JSONDecodeError, ValueError, KeyError):
        pass
    return out


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------
def correlate(exposure: ExposureRecord) -> list[dict]:
    """Return a list of correlation dicts for one exposure."""
    correlations: list[dict] = []
    kev = load_kev()

    # 1. Regional breach-pattern corpus (always local, always attempted)
    pat = corpus_match(exposure.cls)
    if pat:
        weight = pat["prevalence"] * (1 + pat["critical_ratio"])
        correlations.append({"source": "CORPUS", "breach_tag": pat["tag"],
                             "weight": round(weight, 4),
                             "cve_id": None, "kev_flag": False, "epss": None})

    # 2. NVD + KEV when we have a product/version (from service banners)
    product = exposure.extra.get("product", "")
    version = exposure.extra.get("version")
    for cve in nvd_lookup(product, version):
        in_kev = cve["cve_id"] in kev
        correlations.append({"source": "KEV" if in_kev else "NVD",
                             "cve_id": cve["cve_id"], "kev_flag": in_kev,
                             "epss": None, "breach_tag": None,
                             "weight": cve["cvss_base"] / 10.0})

    return correlations


def hibp_domain_breaches(domain: str) -> list[str]:
    """List public breaches associated with a domain (HIBP)."""
    headers = {"hibp-api-key": config.HIBP_API_KEY} if config.HIBP_API_KEY else None
    resp = http_get(f"{config.HIBP_API}?domain={domain}", headers=headers)
    if resp is None or resp.status_code != 200:
        return []
    try:
        return [b.get("Name", "") for b in resp.json()]
    except (json.JSONDecodeError, ValueError):
        return []
