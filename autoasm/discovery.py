"""Discovery subsystem (Chapter 3, §3.3 stage 1; FR1-FR4).

Four connectors implementing a common interface:
  - SubdomainConnector : multi-source CT/OSINT (crt.sh, certspotter, OTX,
                         HackerTarget, Anubis) + dictionary brute-force
                         (+ amass/subfinder if present), with graceful degradation
  - NetworkConnector   : resolve assets to IPs + ASN/WHOIS via RDAP
  - CloudConnector     : keyword-permutation bucket enumeration (S3/Azure/GCP)
  - ApiConnector       : crawl + OpenAPI/Swagger spec discovery

All connectors are passive/non-intrusive and return normalised AssetRecord lists.
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver

from . import config
from .core import AssetRecord, ScopeGuard, has_tool, http_get

# Small built-in subdomain wordlist; extend via data/subdomains.txt if present.
_DEFAULT_WORDLIST = [
    "www", "api", "dev", "staging", "stage", "test", "uat", "qa", "admin",
    "portal", "app", "apps", "mobile", "m", "secure", "login", "auth", "sso",
    "vpn", "mail", "smtp", "webmail", "remote", "gateway", "gw", "internal",
    "intranet", "git", "gitlab", "jenkins", "ci", "jira", "confluence",
    "dashboard", "status", "monitor", "grafana", "kibana", "prometheus",
    "s3", "storage", "static", "cdn", "assets", "img", "media", "files",
    "download", "uploads", "backup", "db", "database", "sql", "redis",
    "payment", "pay", "checkout", "billing", "invoice", "wallet", "card",
    "transfer", "ussd", "agent", "agency", "partner", "b2b", "corporate",
    "ib", "internetbanking", "onlinebanking", "ebanking", "openbanking",
    "swagger", "docs", "developer", "developers", "sandbox", "demo",
]


def _load_wordlist() -> list[str]:
    """Load the learned wordlist mined from real engagements if present, else the
    built-in default. Keeping it in a data file lets the corpus grow over time."""
    try:
        p = config.SUBDOMAIN_WORDLIST_PATH
        if p.exists():
            words = [w.strip().lower() for w in p.read_text(encoding="utf-8").splitlines()
                     if w.strip() and not w.startswith("#")]
            if words:
                return words
    except OSError:
        pass
    return _DEFAULT_WORDLIST


class SubdomainConnector:
    name = "subdomain"

    def __init__(self, scope: ScopeGuard, wordlist: list[str] | None = None,
                 progress=None):
        self.scope = scope
        # The file is frequency-ranked; cap to the top-N for a practical brute-force.
        self.wordlist = (wordlist or _load_wordlist())[:config.MAX_BRUTE_WORDS]
        self.progress = progress or (lambda *_: None)
        # Per-source outcome for the last run: "ok(N)" | "empty" | "fail".
        # Surfaced so the evaluation can report source availability instead of
        # silently leaning on one source (the Chapter 5 lesson).
        self.source_status: dict[str, str] = {}

    # -- helpers --------------------------------------------------------------
    @staticmethod
    def _clean(name: str, domain: str) -> str | None:
        name = name.strip().lstrip("*.").rstrip(".").lower()
        if name and (name == domain or name.endswith("." + domain)):
            return name
        return None

    # -- passive CT / OSINT sources (each returns a set, or None on failure) --
    def _crtsh(self, domain: str) -> set[str] | None:
        resp = http_get(f"https://crt.sh/?q=%25.{domain}&output=json",
                        timeout=config.CT_HTTP_TIMEOUT)
        if resp is None or resp.status_code != 200:
            return None
        found: set[str] = set()
        try:
            for row in resp.json():
                for raw in str(row.get("name_value", "")).splitlines():
                    h = self._clean(raw, domain)
                    if h:
                        found.add(h)
        except (json.JSONDecodeError, ValueError):
            return None
        return found

    def _certspotter(self, domain: str) -> set[str] | None:
        url = ("https://api.certspotter.com/v1/issuances"
               f"?domain={domain}&include_subdomains=true&expand=dns_names")
        resp = http_get(url, timeout=config.CT_HTTP_TIMEOUT)
        if resp is None or resp.status_code != 200:
            return None
        found: set[str] = set()
        try:
            for row in resp.json():
                for raw in row.get("dns_names", []) or []:
                    h = self._clean(str(raw), domain)
                    if h:
                        found.add(h)
        except (json.JSONDecodeError, ValueError):
            return None
        return found

    def _hackertarget(self, domain: str) -> set[str] | None:
        resp = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                        timeout=config.CT_HTTP_TIMEOUT)
        if resp is None or resp.status_code != 200:
            return None
        text = resp.text or ""
        if "API count exceeded" in text or "error" in text.lower():
            return None
        found: set[str] = set()
        for line in text.splitlines():
            h = self._clean(line.split(",")[0], domain)
            if h:
                found.add(h)
        return found

    def _otx(self, domain: str) -> set[str] | None:
        url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
               f"{domain}/passive_dns")
        resp = http_get(url, timeout=config.CT_HTTP_TIMEOUT)
        if resp is None or resp.status_code != 200:
            return None
        found: set[str] = set()
        try:
            for row in resp.json().get("passive_dns", []) or []:
                h = self._clean(str(row.get("hostname", "")), domain)
                if h:
                    found.add(h)
        except (json.JSONDecodeError, ValueError, AttributeError):
            return None
        return found

    def _anubis(self, domain: str) -> set[str] | None:
        resp = http_get(f"https://jldc.me/anubis/subdomains/{domain}",
                        timeout=config.CT_HTTP_TIMEOUT)
        if resp is None or resp.status_code != 200:
            return None
        found: set[str] = set()
        try:
            for raw in resp.json() or []:
                h = self._clean(str(raw), domain)
                if h:
                    found.add(h)
        except (json.JSONDecodeError, ValueError):
            return None
        return found

    def _passive(self, domain: str) -> dict[str, str]:
        """Query every enabled passive source independently. One source failing
        does not stop the others; the first source to report a host wins the
        attribution. Records per-source status in self.source_status."""
        registry = {
            "crtsh": self._crtsh, "certspotter": self._certspotter,
            "hackertarget": self._hackertarget, "otx": self._otx,
            "anubis": self._anubis,
        }
        results: dict[str, str] = {}
        for label in config.PASSIVE_SUBDOMAIN_SOURCES:
            fn = registry.get(label)
            if fn is None:
                continue
            try:
                hosts = fn(domain)
            except Exception:               # never let one source break discovery
                hosts = None
            if hosts is None:
                self.source_status[label] = "fail"
                continue
            self.source_status[label] = f"ok({len(hosts)})" if hosts else "empty"
            for h in hosts:
                results.setdefault(h, label)
        return results

    def _resolve_many(self, hosts) -> set[str]:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = config.DNS_TIMEOUT
        resolver.timeout = config.DNS_TIMEOUT
        found: set[str] = set()

        def _check(host: str) -> str | None:
            try:
                resolver.resolve(host, "A")
                return host
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout,
                    dns.exception.DNSException):
                return None

        with ThreadPoolExecutor(max_workers=config.DNS_CONCURRENCY) as ex:
            for fut in as_completed(ex.submit(_check, h) for h in hosts):
                r = fut.result()
                if r:
                    found.add(r)
        return found

    def _bruteforce(self, domain: str) -> set[str]:
        return self._resolve_many({f"{w}.{domain}" for w in self.wordlist})

    def _permute_and_recurse(self, domain: str, known: list[str]) -> set[str]:
        """Recover the multi-level subdomains a flat brute-force cannot reach.

        From already-known hosts it (a) mutates environment tokens (prod<->uat<->dev
        ...) and (b) brute-forces the wordlist one level deeper against discovered
        parent levels (service.ENV.domain), e.g. api.virtualaccount.prod.example.ng.
        """
        envset = set(config.ENV_TOKENS)
        candidates: set[str] = set()
        parents: set[str] = set()
        for h in known:
            if not h.endswith("." + domain):
                continue
            sub = h[:-(len(domain) + 1)]
            labs = sub.split(".") if sub else []
            if len(labs) >= 2:                       # parent level under the apex
                parents.add(labs[-1] + "." + domain)
            for i, l in enumerate(labs):             # environment mutation
                if l in envset:
                    for e in config.ENV_TOKENS:
                        if e != l:
                            nl = labs[:]
                            nl[i] = e
                            candidates.add(".".join(nl) + "." + domain)
        if config.ENABLE_RECURSIVE_BRUTE:
            for p in sorted(parents):
                for w in self.wordlist:
                    candidates.add(f"{w}.{p}")
                    if len(candidates) >= config.MAX_BRUTE_CANDIDATES:
                        break
        return self._resolve_many(candidates)

    def _external_tool(self, domain: str) -> set[str]:
        """Use subfinder/assetfinder if available for richer passive enum."""
        found: set[str] = set()
        for tool in ("subfinder", "assetfinder"):
            if not has_tool(tool):
                continue
            cmd = ([tool, "-d", domain, "-silent"] if tool == "subfinder"
                   else [tool, "--subs-only", domain])
            try:
                out = subprocess.run(cmd, capture_output=True, text=True,
                                     timeout=120)
                for line in out.stdout.splitlines():
                    line = line.strip().lower()
                    if line.endswith(domain):
                        found.add(line)
            except (subprocess.SubprocessError, OSError):
                continue
        return found

    def run(self, domains: list[str], on_batch=None) -> list[AssetRecord]:
        """on_batch(records), if given, is called with the in-scope subdomains found
        so far as soon as the (fast) passive sources return — before the slower
        brute-force/permutation. This is what lets the UI show the bulk of the hosts
        within seconds instead of after the whole subdomain phase."""
        emit = on_batch or (lambda _records: None)
        results: dict[str, str] = {}
        self.source_status = {}
        p = self.progress
        for domain in domains:
            if config.PASSIVE_DISCOVERY_ENABLED:
                p(f"   ↳ {domain}: querying CT/OSINT sources (crt.sh, certspotter, "
                  f"hackertarget, otx, anubis) …")
                before = len(results)
                for host, src in self._passive(domain).items():
                    results.setdefault(host, src)
                stat = ", ".join(f"{k}:{v}" for k, v in self.source_status.items())
                p(f"   ↳ {domain}: passive done [{stat}] → +{len(results)-before} hosts")
                # Surface passive hosts immediately (dedup downstream handles overlap).
                emit([AssetRecord("subdomain", h, src) for h, src in results.items()
                      if self.scope.in_scope(h)])
            before = len(results)
            p(f"   ↳ {domain}: brute-forcing {len(self.wordlist)} learned labels …")
            for host in self._bruteforce(domain):
                results.setdefault(host, "bruteforce")
            p(f"   ↳ {domain}: brute-force → +{len(results)-before} hosts")
            for host in self._external_tool(domain):
                results.setdefault(host, "passive-tool")
            if config.ENABLE_PERMUTATION:
                known = [h for h in results
                         if h == domain or h.endswith("." + domain)]
                before = len(results)
                p(f"   ↳ {domain}: permutation + recursion on {len(known)} known hosts …")
                for host in self._permute_and_recurse(domain, known):
                    results.setdefault(host, "permutation")
                p(f"   ↳ {domain}: permutation → +{len(results)-before} hosts")
            results.setdefault(domain, "seed")
        return [AssetRecord("subdomain", h, src)
                for h, src in results.items() if self.scope.in_scope(h)]


class NetworkConnector:
    name = "network"

    def __init__(self, scope: ScopeGuard):
        self.scope = scope

    def _resolve(self, host: str) -> set[str]:
        try:
            _, _, ips = socket.gethostbyname_ex(host)
            return set(ips)
        except (socket.gaierror, socket.herror):
            return set()

    def _asn(self, ip: str) -> dict:
        """Passive ASN/owner lookup via RDAP (no scanning of the target)."""
        resp = http_get(f"https://rdap.org/ip/{ip}")
        if resp is None or resp.status_code != 200:
            return {}
        try:
            data = resp.json()
            return {"name": data.get("name", ""),
                    "handle": data.get("handle", "")}
        except (json.JSONDecodeError, ValueError):
            return {}

    def run(self, subdomain_assets: list[AssetRecord]) -> list[AssetRecord]:
        # Resolve hosts in parallel — sequential gethostbyname_ex over a few hundred
        # subdomains (some non-resolving, each waiting out the DNS timeout) was a
        # needless drag on scan time.
        ips: set[str] = set()
        with ThreadPoolExecutor(max_workers=config.DNS_CONCURRENCY) as ex:
            for fut in as_completed(ex.submit(self._resolve, a.value)
                                    for a in subdomain_assets):
                ips |= fut.result()
        out: dict[str, str] = {}
        for ip in ips:                       # RDAP once per unique IP only
            meta = self._asn(ip)
            src = f"asn:{meta.get('name', '')}" if meta else "dns-resolve"
            out.setdefault(ip, src)
        return [AssetRecord("ip", ip, src) for ip, src in out.items()]


class CloudConnector:
    name = "cloud"
    # Public endpoints used only to test existence/public-read (non-intrusive GET/HEAD).
    _S3 = "https://{b}.s3.amazonaws.com/"
    _AZ = "https://{b}.blob.core.windows.net/?comp=list"
    _GCP = "https://storage.googleapis.com/{b}/"

    def __init__(self, scope: ScopeGuard, brand_tokens: set[str] | None = None):
        self.scope = scope
        self.brand_tokens = {b.lower() for b in (brand_tokens or set()) if b}

    def _permutations(self, keyword: str) -> list[str]:
        kw = keyword.lower().replace(" ", "")
        affixes = ["", "-bank", "bank-", "-prod", "-dev", "-staging", "-backup",
                   "-assets", "-static", "-media", "-data", "-files", "-uploads",
                   "-internal", "-public", "-private", "prod-", "dev-"]
        names = {kw}
        for a in affixes:
            names.add(f"{kw}{a}" if a.startswith("-") else f"{a}{kw}")
        return sorted(names)

    def _probe(self, url: str) -> tuple[bool, bool, str]:
        """Return (exists, public_readable, evidence). Classifies the provider
        response properly instead of treating any HTTP 200 as public-readable."""
        # Short timeout, no retries: most permutated bucket names do not exist, and
        # waiting out the full timeout + 2 retries on each dead name made cloud
        # enumeration take minutes. A real bucket answers fast.
        resp = http_get(url, allow_redirects=False,
                        timeout=config.API_PROBE_TIMEOUT, retries=0)
        if resp is None:
            return False, False, ""
        body = (resp.text or "")[:4000]
        code = resp.status_code
        if code == 404 or "NoSuchBucket" in body or "BucketNotFound" in body:
            return False, False, ""
        if code in (301, 302, 307) or "PermanentRedirect" in body:
            return True, False, ""                         # exists, other region
        if (code in (401, 403) or "AccessDenied" in body
                or "request signature" in body.lower()):
            return True, False, ""                         # exists, private
        if code == 200 and ("ListBucketResult" in body or "<Contents>" in body
                            or body.lstrip().startswith("<?xml")):
            keys = re.findall(r"<Key>([^<]+)</Key>", body)[:5]
            ev = ("public listing; sample keys: " + ", ".join(keys)) if keys \
                 else "public listing (XML, no keys sampled)"
            return True, True, ev
        if code == 200:
            return True, False, ""                          # 200 but not a listing
        return False, False, ""

    def run(self, keywords: list[str]) -> list[AssetRecord]:
        out: list[AssetRecord] = []
        for kw in keywords:
            for name in self._permutations(kw):
                attribution = ("brand"
                               if any(b in name for b in self.brand_tokens)
                               else "weak")
                for provider, tmpl in (("s3", self._S3), ("azure", self._AZ),
                                       ("gcp", self._GCP)):
                    url = tmpl.format(b=name)
                    exists, public, ev = self._probe(url)
                    if not exists:
                        continue
                    src = f"{provider}:{'public' if public else 'private'}:{attribution}"
                    out.append(AssetRecord("bucket", url, src,
                               meta={"evidence": ev, "attribution": attribution,
                                     "public": public}))
        return out


class ApiConnector:
    name = "api"
    _SPEC_PATHS = ["/swagger.json", "/openapi.json", "/v2/api-docs",
                   "/v3/api-docs", "/api-docs", "/swagger/v1/swagger.json",
                   "/.well-known/openapi.json"]

    def __init__(self, scope: ScopeGuard):
        self.scope = scope

    def _live_base(self, host: str) -> str | None:
        """Quick liveness check: return the first scheme that answers, else None.
        Short timeout, no retries — a dead host costs one bounded request, not
        seven full-timeout-plus-retry probes."""
        for scheme in ("https", "http"):
            resp = http_get(f"{scheme}://{host}", timeout=config.API_PROBE_TIMEOUT,
                            retries=0, allow_redirects=True)
            if resp is not None:
                return f"{scheme}://{host}"
        return None

    def _probe_specs(self, base: str) -> list[AssetRecord]:
        out: list[AssetRecord] = []
        for path in self._SPEC_PATHS:
            resp = http_get(base + path, timeout=config.API_PROBE_TIMEOUT, retries=0)
            if resp is not None and resp.status_code == 200 and \
                    "json" in resp.headers.get("content-type", "").lower():
                out.append(AssetRecord("endpoint", base + path, "openapi-spec"))
                out.extend(self._parse_spec(resp, base))
        return out

    def run(self, web_assets: list[AssetRecord]) -> list[AssetRecord]:
        hosts = [a.value for a in web_assets]
        if not hosts:
            return []
        deadline = time.monotonic() + config.API_DISCOVERY_BUDGET_SEC

        # Stage 1: find which hosts actually serve web content (parallel, bounded).
        live: list[str] = []
        with ThreadPoolExecutor(max_workers=config.MAX_CONCURRENCY) as ex:
            for fut in as_completed(ex.submit(self._live_base, h) for h in hosts):
                base = fut.result()
                if base:
                    live.append(base)
                if time.monotonic() > deadline:
                    break

        # Stage 2: probe OpenAPI/Swagger spec paths on the live hosts only.
        out: list[AssetRecord] = []
        if time.monotonic() < deadline and live:
            with ThreadPoolExecutor(max_workers=config.MAX_CONCURRENCY) as ex:
                for fut in as_completed(ex.submit(self._probe_specs, b) for b in live):
                    out.extend(fut.result())
                    if time.monotonic() > deadline:
                        break
        return out

    def _parse_spec(self, resp, base: str) -> list[AssetRecord]:
        out: list[AssetRecord] = []
        try:
            spec = resp.json()
            for path in (spec.get("paths") or {}):
                out.append(AssetRecord("endpoint", base + path, "openapi-path"))
        except (json.JSONDecodeError, ValueError, AttributeError):
            pass
        return out
