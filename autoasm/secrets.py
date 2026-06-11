"""Secret-exposure scanning (addresses the advisory concerns on hardcoded
secrets in web/mobile applications and leaked credentials in deployment
artifacts).

This module passively fetches the HTML of a discovered web asset, follows the
JavaScript bundles it references, and scans the response bodies for high-signal
secret patterns: API keys, tokens, private keys, and cloud credentials. It also
checks for JavaScript source maps (.js.map), which routinely leak original
source and embedded secrets in production deployments.

All requests are GETs against assets already in scope. Nothing is exploited; the
module only reads what the server already serves to any visitor.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from .core import ExposureRecord, http_get

# Third-party CDNs / analytics hosts. Their files are public open-source libraries,
# not the target's secrets, so we never fetch or flag them. Only FIRST-PARTY code
# (same registrable domain as the target) is scanned.
_THIRD_PARTY_HOSTS = (
    "jsdelivr.net", "cdnjs.cloudflare.com", "cloudflare.com", "cloudfront.net",
    "googleapis.com", "gstatic.com", "google-analytics.com", "googletagmanager.com",
    "unpkg.com", "jquery.com", "bootstrapcdn.com", "fontawesome.com", "akamaihd.net",
    "cdn.shopify.com", "polyfill.io", "typekit.net", "etracker.com", "usercentrics.eu",
    "facebook.net", "hotjar.com", "segment.com", "newrelic.com", "sentry.io",
    "doubleclick.net", "cloudflareinsights.com", "jsdelivr.com", "fontawesome.io",
)


def _registrable(host: str) -> str:
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _is_first_party(url: str, host: str) -> bool:
    """True only for same-registrable-domain assets; third-party CDNs are excluded."""
    h = (urlparse(url).hostname or "").lower()
    if not h:
        return True                       # relative URL -> same host
    if any(cdn in h for cdn in _THIRD_PARTY_HOSTS):
        return False
    return h == host.lower() or h.endswith("." + _registrable(host))

# High-signal secret patterns. Each entry: (label, compiled regex, cvss).
# Patterns are deliberately specific to keep the false-positive rate low (NFR3).
_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 9.1),
    ("AWS secret access key",
     re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"), 9.1),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), 7.5),
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[0-9A-Za-z\-_]{20,}\b"), 8.2),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), 7.5),
    ("Stripe live secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"), 9.1),
    ("Stripe restricted key", re.compile(r"\brk_live_[0-9A-Za-z]{20,}\b"), 7.5),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), 8.2),
    ("Paystack secret key", re.compile(r"\bsk_live_[0-9a-f]{40}\b"), 9.1),
    ("Flutterwave secret key", re.compile(r"\bFLWSECK-[0-9a-f]{32}-X\b"), 9.1),
    ("Private key block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), 9.1),
    ("JWT (hardcoded)", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), 5.3),
    ("Generic API secret assignment",
     re.compile(r"(?i)(?:api[_-]?key|secret|token|passwd|password)\s*[=:]\s*"
                r"['\"]([A-Za-z0-9_\-]{16,})['\"]"), 6.5),
    ("Bearer token (hardcoded)",
     re.compile(r"(?i)authorization\s*[=:]\s*['\"]?bearer\s+[A-Za-z0-9._\-]{20,}"), 6.5),
    ("MongoDB connection string",
     re.compile(r"\bmongodb(?:\+srv)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"), 8.6),
    ("Postgres connection string",
     re.compile(r"\bpostgres(?:ql)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"), 8.6),
]

# Obvious placeholders we should not report (keeps precision high).
_PLACEHOLDER = re.compile(r"(?i)(example|xxxx|placeholder|your[_-]?(key|token|secret)|"
                          r"dummy|sample|test[_-]?key|changeme|<.+>)")

_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
_MAX_JS = 12          # cap JS bundles fetched per host (non-intrusive, bounded)
_MAX_BODY = 2_000_000  # don't scan absurdly large bodies


def _scan_body(body: str, source_url: str) -> list[ExposureRecord]:
    out: list[ExposureRecord] = []
    seen: set[str] = set()
    body = body[:_MAX_BODY]
    for label, rx, cvss in _PATTERNS:
        for m in rx.finditer(body):
            snippet = m.group(0)
            if _PLACEHOLDER.search(snippet):
                continue
            key = label + ":" + snippet[:24]
            if key in seen:
                continue
            seen.add(key)
            redacted = snippet[:6] + "…" + snippet[-2:] if len(snippet) > 12 else "…"
            out.append(ExposureRecord(
                source_url, "hardcoded-secret",
                f"{label} exposed in client-delivered code ({redacted})",
                evidence_ref=source_url, cvss_base=cvss,
                extra={"secret_type": label}))
    return out


def scan_web_secrets(host: str) -> list[ExposureRecord]:
    """Fetch a host's page + JS bundles and scan for secrets and source maps."""
    out: list[ExposureRecord] = []
    for scheme in ("https", "http"):
        base = f"{scheme}://{host}"
        resp = http_get(base)
        if resp is None:
            continue
        html = resp.text or ""
        out.extend(_scan_body(html, base))

        # follow referenced JS bundles — FIRST-PARTY only (skip CDN libraries)
        scripts = [s for s in _SCRIPT_SRC.findall(html) if _is_first_party(
            s if s.startswith("http") else urljoin(base + "/", s), host)][:_MAX_JS]
        for src in scripts:
            js_url = src if src.startswith("http") else urljoin(base + "/", src)
            jr = http_get(js_url)
            if jr is None or jr.status_code != 200:
                continue
            out.extend(_scan_body(jr.text or "", js_url))

            # source map leak: only meaningful for first-party application bundles
            map_url = js_url + ".map"
            mr = http_get(map_url)
            if mr is not None and mr.status_code == 200 and \
                    '"sources"' in (mr.text[:2000] or ""):
                out.append(ExposureRecord(map_url, "exposed-sourcemap",
                    "First-party JavaScript source map exposed in production "
                    "(leaks original application source)",
                    evidence_ref=map_url, cvss_base=5.3))
                out.extend(_scan_body(mr.text or "", map_url))
        break  # one working scheme per host is enough
    return out
