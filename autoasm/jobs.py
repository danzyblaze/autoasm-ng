"""Async scan-job runner.

A scan can run for minutes to hours, so the web request that starts it must not
block. start_scan() creates the Scan row, kicks discovery off in a background
thread, and returns immediately. The UI then polls job_status() for live
progress. For production scale this can be swapped for Celery or RQ without
touching the web layer.
"""
from __future__ import annotations

import datetime as _dt
import threading
import traceback
from typing import Optional

from .models import Organisation, Scan, get_session, init_db
from .orchestrator import Orchestrator

_PROGRESS: dict[int, list[str]] = {}
_ASSETS: dict[int, list[dict]] = {}
_ASSET_KEYS: dict[int, set] = {}
_LOCK = threading.Lock()


def progress_for(scan_id: int) -> list[str]:
    with _LOCK:
        return list(_PROGRESS.get(scan_id, []))


def _record(scan_id: int, line: str) -> None:
    with _LOCK:
        _PROGRESS.setdefault(scan_id, []).append(str(line))


def _record_assets(scan_id: int, records) -> None:
    """Append a discovery phase's assets to the live list shown while a scan runs.
    De-duplicated by (type, value): phases re-emit (passive then final subdomains),
    so without this the live per-type counts would inflate past the real total."""
    with _LOCK:
        bucket = _ASSETS.setdefault(scan_id, [])
        keys = _ASSET_KEYS.setdefault(scan_id, set())
        for ar in records:
            k = (ar.type, ar.value)
            if k in keys:
                continue
            keys.add(k)
            bucket.append({"type": ar.type, "value": ar.value, "source": ar.source})


def assets_for(scan_id: int) -> list[dict]:
    with _LOCK:
        return list(_ASSETS.get(scan_id, []))


def start_scan(org_name: str, root_domains: list[str],
               default_criticality: int = 3,
               allowed_ips: Optional[list[str]] = None) -> int:
    """Create the Scan row now, run the pipeline in a thread, return scan_id."""
    init_db()
    session = get_session()
    try:
        org = session.query(Organisation).filter_by(name=org_name).first()
        if org is None:
            org = Organisation(name=org_name,
                               root_domains=",".join(root_domains),
                               default_criticality=default_criticality)
            session.add(org)
            session.commit()
        scan = Scan(org_id=org.id,
                    started_at=_dt.datetime.now(_dt.timezone.utc),
                    notes="queued")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    finally:
        session.close()

    def _worker():
        try:
            orch = Orchestrator(org_name, root_domains,
                                default_criticality=default_criticality,
                                allowed_ips=allowed_ips,
                                progress=lambda m: _record(scan_id, m),
                                on_assets=lambda recs: _record_assets(scan_id, recs))
            orch.run(existing_scan_id=scan_id)
            _record(scan_id, "DONE")
        except Exception:  # surfaced to the user via job_status
            _record(scan_id, "ERROR: " + traceback.format_exc().splitlines()[-1])
            _mark_failed(scan_id)

    threading.Thread(target=_worker, daemon=True).start()
    return scan_id


def _mark_failed(scan_id: int) -> None:
    session = get_session()
    try:
        scan = session.get(Scan, scan_id)
        if scan:
            scan.notes = "failed"
            session.commit()
    finally:
        session.close()


def job_status(scan_id: int) -> dict:
    session = get_session()
    try:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return {"scan_id": scan_id, "state": "unknown"}
        lines = progress_for(scan_id)
        if scan.finished_at is not None:
            state = "completed"
        elif scan.notes == "failed" or (lines and lines[-1].startswith("ERROR")):
            state = "failed"
        else:
            state = "running"
        live_assets = assets_for(scan_id)
        breakdown: dict[str, int] = {}
        for a in live_assets:
            breakdown[a["type"]] = breakdown.get(a["type"], 0) + 1
        return {
            "scan_id": scan_id,
            "state": state,
            "asset_count": scan.asset_count,
            "exposure_count": scan.exposure_count,
            "duration_seconds": scan.duration_seconds,
            "progress": lines[-15:],
            "assets": live_assets[-300:],      # live discovered-asset list for the UI
            "asset_breakdown": breakdown,
        }
    finally:
        session.close()
