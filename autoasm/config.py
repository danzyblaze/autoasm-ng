"""Central configuration for AutoASM-NG.

All tunable parameters live here so the rest of the codebase reads cleanly and the
evaluation experiments (Chapter Five) can adjust behaviour from one place.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# --- Paths -----------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "autoasm.db"

def _normalise_db_url(url: str) -> str:
    # Render/Heroku hand out postgres:// which SQLAlchemy 2.0 no longer accepts.
    if url.startswith("postgres://"):
        return "postgresql+psycopg2://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        return "postgresql+psycopg2://" + url[len("postgresql://"):]
    return url

DB_URL = _normalise_db_url(os.environ.get("AUTOASM_DB_URL", f"sqlite:///{DB_PATH}"))

# Anonymised regional breach-pattern corpus (seed data for the correlation engine).
BREACH_CORPUS_PATH = BASE_DIR / "autoasm" / "data" / "breach_patterns.json"

# Consultant-style findings XLSX reporter (synopsis / category / impact /
# resolution / status / appendix). Lives in the workspace root; reused, not copied.
FINDINGS2DE_PATH = BASE_DIR.parent / "findings2de.py"

# --- Network behaviour (NON-INTRUSIVE by design) ---------------------------
HTTP_TIMEOUT = 10           # seconds per request
HTTP_USER_AGENT = "AutoASM-NG/0.1 (+research; passive scanner)"
RATE_LIMIT_PER_SEC = 5.0    # global cap on outbound requests — avoid disruption (NFR2)
DNS_TIMEOUT = 3.0          # non-resolving brute/permutation candidates fail fast
MAX_CONCURRENCY = 10        # bounded worker pool for HTTP (kept low — non-intrusive)
# DNS lookups are cheap and hit the resolver, not the target, so brute-force /
# permutation candidate resolution can use far more parallelism than HTTP. This is
# the single biggest lever on subdomain-phase wall-clock (1500 words at a 5s timeout
# with only 10 workers was minutes of waiting on non-resolving candidates).
DNS_CONCURRENCY = 40

# Resilience for slow/flaky external sources (the Chapter 5 CT-outage lesson):
# retry transient failures (5xx / 429 / timeouts) with exponential back-off, and
# give certificate-transparency / OSINT sources a longer timeout since they are slow.
HTTP_RETRIES = 2
HTTP_BACKOFF = 1.5          # base seconds; attempt n waits HTTP_BACKOFF * 2**n
CT_HTTP_TIMEOUT = 25        # CT / passive OSINT endpoints are often slow

# API-endpoint discovery used to probe 7 spec paths on EVERY discovered host,
# serially, with the full HTTP timeout + retries. On a domain with a few hundred
# subdomains that is ~2000 serial requests, most against hosts with no web server,
# each waiting out the timeout — a single scan could sit in this phase for hours.
# It now (a) probes a host only if it answers a quick liveness check, (b) runs in
# parallel, (c) uses a short timeout with no retries, and (d) is capped by a hard
# wall-clock budget so it can never dominate a scan.
API_PROBE_TIMEOUT = 4            # seconds per liveness / spec probe
API_DISCOVERY_BUDGET_SEC = 150   # hard cap on the whole API-discovery phase

# Multi-source passive subdomain discovery (free, no API key). Using several
# independent sources removes the single point of failure that crt.sh alone was.
PASSIVE_DISCOVERY_ENABLED = True
PASSIVE_SUBDOMAIN_SOURCES = ["crtsh", "certspotter", "hackertarget", "otx", "anubis"]

# Comprehensive active discovery: a learned wordlist (mined from real engagements),
# permutation/mutation across environment tokens, and one level of recursive
# brute-forcing on discovered parent levels (e.g. service.ENV.domain). This is what
# lets discovery find the multi-level hosts (api.virtualaccount.prod.example.ng) that
# a flat word.domain brute-force misses.
SUBDOMAIN_WORDLIST_PATH = BASE_DIR / "autoasm" / "data" / "subdomains.txt"
ENABLE_PERMUTATION = True
ENABLE_RECURSIVE_BRUTE = True
MAX_BRUTE_CANDIDATES = 4000         # cap on permutation/recursion candidates per domain
# The learned wordlist file is the full corpus (thousands of labels). Brute-forcing
# all of it per domain is impractically slow, so only the top-N most frequent
# (the file is frequency-ranked) are used for live DNS brute-force. Raise for a
# deeper scan, lower for a faster one.
MAX_BRUTE_WORDS = 1500
ENV_TOKENS = ["prod", "prd", "production", "uat", "dev", "development", "stage",
              "staging", "stg", "sandbox", "sbx", "preprod", "pre-prod", "qa",
              "test", "sit", "demo", "internal", "intl"]

# Common ports only — non-intrusive, fast (NFR1). Full top-100 lives in scanner.
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
                1433, 1521, 2082, 2083, 3306, 3389, 5432, 5900, 6379,
                8000, 8080, 8081, 8443, 9200, 27017]

# --- Threat-intelligence sources -------------------------------------------
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HIBP_API = "https://haveibeenpwned.com/api/v3/breaches"   # domain breaches; key optional
NVD_API_KEY = os.environ.get("NVD_API_KEY")               # optional, raises rate limit
HIBP_API_KEY = os.environ.get("HIBP_API_KEY")

# Local cache for TI feeds so repeated scans don't re-hammer the sources.
TI_CACHE_DIR = DATA_DIR / "ti_cache"
TI_CACHE_DIR.mkdir(exist_ok=True)
TI_CACHE_TTL_HOURS = 24

# --- Risk-scoring model (Chapter 3, §3.4.6: RiskScore = C x S x B) ----------
@dataclass
class ScoringConfig:
    # asset criticality 1..5 -> normalised multiplier
    criticality_norm: dict = field(default_factory=lambda: {
        1: 0.2, 2: 0.4, 3: 0.6, 4: 0.8, 5: 1.0,
    })
    # breach-relevance multiplier bounds [1.0, 2.0]
    kev_uplift: float = 0.6          # any correlated CVE in CISA KEV
    epss_uplift_max: float = 0.4     # scaled by EPSS probability
    corpus_uplift_max: float = 0.5   # scaled by regional prevalence x criticality
    breach_relevance_floor: float = 1.0
    breach_relevance_ceil: float = 2.0
    default_asset_criticality: int = 3


SCORING = ScoringConfig()

# --- External CLI tools (auto-detected; graceful fallback if absent) --------
OPTIONAL_TOOLS = ["amass", "subfinder", "assetfinder", "nmap", "nuclei"]
