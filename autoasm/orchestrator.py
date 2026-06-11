"""Orchestrator (Chapter 3, §3.3) — wires the pipeline and persists results.

Flow: scope-validate seed -> discover -> assess -> correlate -> score/rank ->
persist. Returns the Scan id. Passive/non-intrusive throughout.
"""
from __future__ import annotations

import datetime as _dt
import re
import time

from . import discovery, assessment, correlation, scoring
from .core import AssetRecord, ScopeGuard

# Org-type / filler words that must NOT become cloud-bucket keywords. Using the org
# DISPLAY name ("Bank S" -> "banks") matched strangers' public buckets; brand tokens
# from the registrable domains are the reliable signal.
_GENERIC_ORG_WORDS = {"bank", "banks", "mfb", "ltd", "plc", "limited", "the",
                      "group", "holdings", "microfinance", "fintech", "company",
                      "co", "inc", "services", "digital", "nigeria", "global"}
from .models import (Asset, Correlation, Exposure, Organisation, RiskScore,
                     Scan, get_session, init_db)


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


class Orchestrator:
    def __init__(self, org_name: str, root_domains: list[str],
                 default_criticality: int = 3, allowed_ips: list[str] | None = None,
                 progress=print, on_assets=None):
        self.org_name = org_name
        self.root_domains = [d.strip().lower() for d in root_domains if d.strip()]
        self.default_criticality = default_criticality
        self.scope = ScopeGuard(self.root_domains, allowed_ips)
        self.progress = progress
        # Called with each discovery phase's AssetRecord list as soon as the phase
        # finishes, so the live UI can show found assets mid-scan instead of waiting
        # for the whole pipeline. Optional; defaults to a no-op.
        self.on_assets = on_assets or (lambda _records: None)

    # -- cloud keyword derivation (brand tokens, not the org-type word) ----
    def _cloud_keywords(self) -> tuple[list[str], set[str]]:
        brands = [d.split(".")[0].lower() for d in self.root_domains if d]
        org_tokens = [t for t in re.findall(r"[a-z0-9]+", self.org_name.lower())
                      if len(t) >= 4 and t not in _GENERIC_ORG_WORDS]
        kw = list(dict.fromkeys(brands + org_tokens))
        return kw, set(brands + org_tokens)

    # -- discovery --------------------------------------------------------
    def _discover(self, on_phase=None) -> list[AssetRecord]:
        """Run the four discovery connectors. After EACH phase, hand its records to
        on_phase(records) so the caller can persist and surface them immediately —
        the user should see subdomains during phase 1, not after the whole scan."""
        emit = on_phase or (lambda _records: None)

        self.progress("[*] Discovery: subdomains ...")
        sub = discovery.SubdomainConnector(
            self.scope, progress=self.progress).run(self.root_domains, on_batch=emit)
        self.progress(f"    {len(sub)} subdomains")
        emit(sub)

        self.progress("[*] Discovery: network / ASN ...")
        net = discovery.NetworkConnector(self.scope).run(sub)
        self.progress(f"    {len(net)} IPs")
        emit(net)

        self.progress("[*] Discovery: cloud buckets ...")
        kw, brands = self._cloud_keywords()
        cloud = discovery.CloudConnector(self.scope, brand_tokens=brands).run(kw)
        self.progress(f"    {len(cloud)} buckets")
        emit(cloud)

        self.progress("[*] Discovery: API endpoints ...")
        api = discovery.ApiConnector(self.scope).run(sub)
        self.progress(f"    {len(api)} endpoints")
        emit(api)

        # de-duplicate by (type, value)
        seen, merged = set(), []
        for a in sub + net + cloud + api:
            key = (a.type, a.value)
            if key not in seen:
                seen.add(key)
                merged.append(a)
        return merged

    # -- run --------------------------------------------------------------
    def run(self, existing_scan_id: int | None = None) -> int:
        init_db()
        t0 = time.monotonic()
        session = get_session()
        try:
            org = session.query(Organisation).filter_by(name=self.org_name).first()
            if org is None:
                org = Organisation(name=self.org_name,
                                   root_domains=",".join(self.root_domains),
                                   default_criticality=self.default_criticality)
                session.add(org)
                session.commit()

            if existing_scan_id is not None:
                scan = session.get(Scan, existing_scan_id)
                scan.notes = "running"
            else:
                scan = Scan(org_id=org.id, started_at=_utcnow())
                session.add(scan)
            session.commit()

            # Persist each discovery phase the moment it finishes, and update the
            # scan's live asset_count + the in-memory sink. This is what lets the UI
            # show "286 assets" during phase 1 instead of "0" for hours, and it means
            # a scan that is stopped or stalls in a later phase keeps what it found.
            asset_rows: dict[str, Asset] = {}
            persisted: set[tuple[str, str]] = set()

            def _persist_phase(records):
                added = 0
                for ar in records:
                    key = (ar.type, ar.value)
                    if key in persisted:
                        continue
                    persisted.add(key)
                    row = Asset(org_id=org.id, type=ar.type, value=ar.value,
                                source=ar.source, criticality=ar.criticality)
                    session.add(row)
                    asset_rows[ar.value] = row
                    added += 1
                if added:
                    session.commit()
                    scan.asset_count = len(persisted)   # live count for the UI
                    session.commit()
                self.on_assets(records)                  # feed the live asset list

            assets = self._discover(on_phase=_persist_phase)

            self.progress("[*] Assessment: non-intrusive checks ...")
            exposures = assessment.assess(assets, progress=self.progress)
            self.progress(f"    {len(exposures)} exposures")

            self.progress("[*] Correlation + scoring ...")
            scored_rows: list[tuple[Exposure, scoring.ScoredExposure]] = []
            for er in exposures:
                asset_row = asset_rows.get(er.asset_value)
                if asset_row is None:
                    # exposure on a path-bearing asset value; attach to host root
                    host = er.asset_value.split("//")[-1].split("/")[0]
                    asset_row = asset_rows.get(host)
                crit = asset_row.criticality if asset_row else self.default_criticality
                aid = asset_row.id if asset_row else None
                if aid is None:
                    # create a lightweight asset for orphan exposures
                    asset_row = Asset(org_id=org.id, type="endpoint",
                                      value=er.asset_value, source="assessment",
                                      criticality=self.default_criticality)
                    session.add(asset_row)
                    session.commit()
                    aid = asset_row.id

                exp = Exposure(asset_id=aid, cls=er.cls, description=er.description,
                               evidence_ref=er.evidence_ref, cvss_base=er.cvss_base)
                session.add(exp)
                session.commit()

                cors = correlation.correlate(er)
                for c in cors:
                    session.add(Correlation(exposure_id=exp.id, source=c["source"],
                        cve_id=c.get("cve_id"), kev_flag=bool(c.get("kev_flag")),
                        epss=c.get("epss"), breach_tag=c.get("breach_tag"),
                        weight=c.get("weight", 0.0)))

                se = scoring.score_one(crit, er.cvss_base, cors,
                                       er.asset_value, er.cls, er.description)
                scored_rows.append((exp, se))
            session.commit()

            ranked = scoring.rank([se for _, se in scored_rows])
            rank_by_obj = {id(se): se.rank for se in ranked}
            for exp, se in scored_rows:
                session.add(RiskScore(exposure_id=exp.id, criticality=se.criticality,
                    severity=se.severity, breach_relevance=se.breach_relevance,
                    composite_score=se.composite_score,
                    rank=rank_by_obj.get(id(se), 0)))
            session.commit()

            scan.finished_at = _utcnow()
            scan.asset_count = len(assets)
            scan.exposure_count = len(exposures)
            scan.duration_seconds = round(time.monotonic() - t0, 2)
            session.commit()
            self.progress(f"[+] Scan {scan.id} done in {scan.duration_seconds}s "
                          f"({len(assets)} assets, {len(exposures)} exposures)")
            return scan.id
        finally:
            session.close()
