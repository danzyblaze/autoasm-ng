"""Core utilities shared across AutoASM-NG subsystems.

Includes: normalised result dataclasses, the scope guard (NFR7), a global rate
limiter (NFR2 non-intrusiveness), external-tool detection (NFR4 graceful fallback),
and small HTTP/DNS helpers.
"""
from __future__ import annotations

import re
import shutil
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

from . import config

# --------------------------------------------------------------------------
# Normalised result types passed between pipeline stages
# --------------------------------------------------------------------------
@dataclass
class AssetRecord:
    type: str            # subdomain | ip | bucket | endpoint | service
    value: str
    source: str = ""
    criticality: int = config.SCORING.default_asset_criticality
    meta: dict = field(default_factory=dict)   # e.g. {"evidence": "...", "attribution": "brand"}


@dataclass
class ExposureRecord:
    asset_value: str
    cls: str             # exposure class (see breach_patterns maps_exposure_classes)
    description: str = ""
    evidence_ref: str = ""
    cvss_base: float = 0.0
    extra: dict = field(default_factory=dict)   # e.g. {"product": "...", "version": "..."}


# --------------------------------------------------------------------------
# Scope guard — hard enforcement (NFR7). Out-of-scope target => reject.
# --------------------------------------------------------------------------
class ScopeGuard:
    """Allow a target only if it belongs to one of the seed root domains
    (or their subdomains), or is an IP the caller explicitly authorised."""

    def __init__(self, root_domains: list[str], allowed_ips: Optional[list[str]] = None):
        self.roots = [d.lower().lstrip(".") for d in root_domains if d.strip()]
        self.allowed_ips = set(allowed_ips or [])

    def in_scope(self, target: str) -> bool:
        t = target.lower().strip()
        t = re.sub(r"^[a-z]+://", "", t)          # strip scheme
        t = t.split("/")[0].split(":")[0]          # strip path + port
        if t in self.allowed_ips:
            return True
        for root in self.roots:
            if t == root or t.endswith("." + root):
                return True
        # bucket names embedding the org name are validated by the caller separately
        return False

    def filter(self, targets: list[str]) -> list[str]:
        return [t for t in targets if self.in_scope(t)]


# --------------------------------------------------------------------------
# Global rate limiter — token-bucket, thread-safe (NFR2)
# --------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, per_second: float = config.RATE_LIMIT_PER_SEC):
        self.min_interval = 1.0 / per_second if per_second > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            sleep_for = self._last + self.min_interval - now
            if sleep_for > 0:
                time.sleep(sleep_for)
            self._last = time.monotonic()


_global_limiter = RateLimiter()


# --------------------------------------------------------------------------
# HTTP helper — rate-limited, timeout-bounded, never raises to caller
# --------------------------------------------------------------------------
def http_get(url: str, *, headers: Optional[dict] = None,
             timeout: int = config.HTTP_TIMEOUT,
             allow_redirects: bool = True,
             retries: int = config.HTTP_RETRIES) -> Optional[requests.Response]:
    """Rate-limited GET that retries transient failures with exponential back-off.

    Retries on connection errors/timeouts and on 5xx/429 responses, which is what
    made the single CT source unreliable in the Chapter 5 evaluation. Returns the
    last response (even if 5xx) so callers can inspect it, or None if every attempt
    raised. Never raises to the caller.
    """
    h = {"User-Agent": config.HTTP_USER_AGENT}
    if headers:
        h.update(headers)
    last: Optional[requests.Response] = None
    for attempt in range(retries + 1):
        _global_limiter.wait()
        try:
            resp = requests.get(url, headers=h, timeout=timeout,
                                allow_redirects=allow_redirects, verify=True)
            if resp.status_code >= 500 or resp.status_code == 429:
                last = resp
                if attempt < retries:
                    time.sleep(config.HTTP_BACKOFF * (2 ** attempt))
                    continue
            return resp
        except requests.RequestException:
            if attempt < retries:
                time.sleep(config.HTTP_BACKOFF * (2 ** attempt))
                continue
            return None
    return last


# --------------------------------------------------------------------------
# External tool detection (NFR4) — pipeline degrades gracefully if absent
# --------------------------------------------------------------------------
def available_tools() -> dict[str, bool]:
    return {t: shutil.which(t) is not None for t in config.OPTIONAL_TOOLS}


def has_tool(name: str) -> bool:
    return shutil.which(name) is not None
