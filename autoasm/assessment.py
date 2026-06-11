"""Assessment subsystem (Chapter 3, §3.3 stage 2; FR5-FR6).

Passive / non-intrusive checks producing ExposureRecord objects:
  - port scan (connect scan, common ports, short timeout)
  - TLS/SSL certificate validity + strength
  - exposed config / metadata files
  - public-read cloud storage (flagged at discovery, recorded here)
  - dangling-DNS / subdomain-takeover fingerprints
"""
from __future__ import annotations

import socket
import ssl
import datetime as _dt
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import config
from .core import AssetRecord, ExposureRecord, http_get

# Fingerprints of third-party services that, when a CNAME dangles, allow takeover.
_TAKEOVER_FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp": "No such app",
    "amazonaws": "NoSuchBucket",
    "azurewebsites": "404 Web Site not found",
    "cloudfront": "ERROR: The request could not be satisfied",
    "wordpress.com": "Do you want to register",
    "fastly": "Fastly error: unknown domain",
    "pantheon": "The gods are wise",
    "shopify": "Sorry, this shop is currently unavailable",
    # Unregulated third-party deploy platforms named in regional security advisories.
    "vercel": "The deployment could not be found",
    "netlify": "Not Found - Request ID",
    "render": "x-render-routing",
    "surge.sh": "project not found",
    "readthedocs": "unknown to Read the Docs",
    "bitbucket.io": "Repository not found",
}

# Third-party hosting platforms. If a production banking asset is served from one
# of these, it is an unregulated/uncontrolled deployment (advisory concern #6).
# Detected via response headers or CNAME, not by exploiting anything.
_THIRD_PARTY_HOSTS = {
    "vercel": ["x-vercel-id", "server: vercel"],
    "netlify": ["x-nf-request-id", "server: netlify"],
    "render": ["x-render-origin-server", "x-render-routing"],
    "github-pages": ["server: github.com"],
    "heroku": ["server: cowboy", "via: 1.1 vegur"],
    "firebase": ["x-served-by: firebase", "server: x_gws"],
}

# Hostname tokens that mark a non-production environment exposed in production
# (advisory concern #5: dev/staging environments reachable publicly).
_DEV_ENV_TOKENS = ("dev", "staging", "stage", "uat", "test", "qa", "sandbox",
                   "demo", "preprod", "pre-prod", "beta", "internal", "local")

_EXPOSED_PATHS = [
    # config / secrets
    "/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/.env.production",
    "/config.json", "/appsettings.json", "/web.config", "/.aws/credentials",
    "/wp-config.php.bak", "/.npmrc", "/.dockercfg", "/docker-compose.yml",
    # deployment artifacts (advisory concern #3: leaked deployment artifacts)
    "/.vercel/project.json", "/.netlify/state.json", "/.terraform/terraform.tfstate",
    "/terraform.tfstate", "/.gitlab-ci.yml", "/.github/workflows/",
    "/firebase.json", "/.firebaserc", "/package.json", "/composer.json",
    "/backup.zip", "/backup.tar.gz", "/dump.sql", "/db.sqlite3", "/.DS_Store",
    # admin / docs / debug exposed in production (advisory concern #5)
    "/server-status", "/actuator", "/actuator/health", "/actuator/env",
    "/phpinfo.php", "/swagger-ui.html", "/swagger", "/api-docs", "/graphql",
    "/debug", "/_debug", "/admin", "/.well-known/security.txt",
]


# Service + risk per port. Ordinary web ports (80/443) are EXPECTED on a web host
# and are not a finding on their own, so they are suppressed. Risky/admin/database
# services are reported with a severity that reflects the actual service.
_PORT_INFO = {
    21: ("FTP", 6.5), 23: ("Telnet", 7.5), 445: ("SMB", 7.5), 3389: ("RDP", 7.5),
    5900: ("VNC", 7.5), 1433: ("MSSQL", 7.5), 1521: ("Oracle DB", 7.5),
    3306: ("MySQL", 7.5), 5432: ("PostgreSQL", 7.5), 6379: ("Redis (no-auth risk)", 8.1),
    9200: ("Elasticsearch", 7.5), 27017: ("MongoDB", 8.1), 2082: ("cPanel", 4.3),
    2083: ("cPanel SSL", 4.3), 25: ("SMTP", 3.1), 110: ("POP3", 3.1),
    143: ("IMAP", 3.1), 587: ("SMTP submission", 2.0), 993: ("IMAPS", 2.0),
    995: ("POP3S", 2.0), 53: ("DNS", 3.1), 22: ("SSH", 4.0),
    8080: ("HTTP-alt", 3.1), 8081: ("HTTP-alt", 3.1), 8000: ("HTTP-alt", 3.1),
    8443: ("HTTPS-alt", 3.1),
}
_BENIGN_PORTS = {80, 443}                 # expected web ports; not reported alone
_SENSITIVE_PORTS = {21, 23, 445, 3389, 5900, 1433, 1521, 3306, 5432, 6379, 9200,
                    27017}                # DB / admin / remote-access => higher signal


class PortScanner:
    def __init__(self, ports: list[int] | None = None):
        self.ports = ports or config.COMMON_PORTS

    def _scan_one(self, ip: str, port: int) -> int | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                if s.connect_ex((ip, port)) == 0:
                    return port
        except OSError:
            pass
        return None

    def scan(self, ip: str) -> list[int]:
        open_ports: list[int] = []
        with ThreadPoolExecutor(max_workers=config.MAX_CONCURRENCY) as ex:
            futs = {ex.submit(self._scan_one, ip, p): p for p in self.ports}
            for fut in as_completed(futs):
                r = fut.result()
                if r is not None:
                    open_ports.append(r)
        return sorted(open_ports)


def check_tls(host: str, port: int = 443) -> list[ExposureRecord]:
    out: list[ExposureRecord] = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=config.API_PROBE_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            out.append(ExposureRecord(host, "weak-tls",
                       f"Obsolete protocol {proto} negotiated", cvss_base=5.3,
                       extra={"protocol": proto}))
        if cert:
            not_after = cert.get("notAfter")
            if not_after:
                exp = _dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                if exp < _dt.datetime.utcnow():
                    out.append(ExposureRecord(host, "expired-cert",
                               f"TLS certificate expired on {not_after}",
                               cvss_base=5.3, extra={"notAfter": not_after}))
    except ssl.SSLError as e:
        out.append(ExposureRecord(host, "weak-tls",
                   f"TLS handshake/validation issue: {e}", cvss_base=4.0))
    except (OSError, socket.timeout):
        pass
    return out


def check_exposed_files(host: str) -> list[ExposureRecord]:
    out: list[ExposureRecord] = []
    # Liveness gate: find a scheme that actually serves web before probing ~40
    # paths. Most discovered subdomains do not serve web, and probing every path
    # on a dead host (with full timeout + retries) was the dominant cost of the
    # assessment phase. Short timeout, no retries throughout.
    base = None
    for scheme in ("https", "http"):
        if http_get(f"{scheme}://{host}", timeout=config.API_PROBE_TIMEOUT,
                    retries=0) is not None:
            base = f"{scheme}://{host}"
            break
    if base is None:
        return out
    for path in _EXPOSED_PATHS:
        resp = http_get(base + path, timeout=config.API_PROBE_TIMEOUT, retries=0)
        if resp is None:
            continue
        if resp.status_code == 200 and len(resp.content) > 0:
            cls = "exposed-config"
            cvss = 7.5
            if path.startswith("/.git"):
                cls = "exposed-git"
            elif "actuator" in path:
                cls = "exposed-admin-panel"
                cvss = 8.6
            elif path in ("/.env", "/.aws/credentials"):
                cls = "exposed-config"
                cvss = 9.1
            out.append(ExposureRecord(base + path, cls,
                       f"Sensitive path {path} returned HTTP 200",
                       evidence_ref=base + path, cvss_base=cvss))
    return out


def check_takeover(host: str) -> list[ExposureRecord]:
    resp = http_get(f"http://{host}", timeout=config.API_PROBE_TIMEOUT, retries=0)
    if resp is None:
        return []
    body = (resp.text or "")[:8000]
    for svc, marker in _TAKEOVER_FINGERPRINTS.items():
        if marker.lower() in body.lower():
            return [ExposureRecord(host, "subdomain-takeover",
                    f"Dangling record fingerprint for {svc} ('{marker}')",
                    evidence_ref=f"http://{host}", cvss_base=8.1,
                    extra={"service": svc})]
    return []


def check_third_party_hosting(host: str) -> list[ExposureRecord]:
    """Flag production assets served from unregulated third-party deploy
    platforms (Vercel, Netlify, Render, etc.) - advisory concern #6."""
    resp = http_get(f"https://{host}", timeout=config.API_PROBE_TIMEOUT, retries=0) or http_get(f"http://{host}", timeout=config.API_PROBE_TIMEOUT, retries=0)
    if resp is None:
        return []
    header_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
    for platform, markers in _THIRD_PARTY_HOSTS.items():
        if any(m.lower() in header_blob for m in markers):
            return [ExposureRecord(host, "third-party-hosting",
                    f"Production asset served from third-party platform "
                    f"({platform}); unregulated deployment outside the "
                    f"organisation's controls",
                    evidence_ref=f"https://{host}", cvss_base=4.3,
                    extra={"platform": platform})]
    return []


def check_dev_environment(host: str) -> list[ExposureRecord]:
    """Flag non-production environments reachable in production
    (advisory concern #5: dev/staging/UAT exposed publicly)."""
    label = host.lower().split(".")[0]
    parts = set(host.lower().replace("-", ".").split("."))
    if any(tok in parts or tok == label for tok in _DEV_ENV_TOKENS):
        # only report if it actually responds
        resp = http_get(f"https://{host}", timeout=config.API_PROBE_TIMEOUT, retries=0) or http_get(f"http://{host}", timeout=config.API_PROBE_TIMEOUT, retries=0)
        if resp is not None and resp.status_code < 500:
            return [ExposureRecord(host, "exposed-dev-env",
                    f"Non-production environment publicly reachable "
                    f"(host token suggests dev/staging/test)",
                    evidence_ref=f"https://{host}", cvss_base=5.3,
                    extra={"status": resp.status_code})]
    return []


def assess(assets: list[AssetRecord], scan_secrets: bool = True,
           progress=None) -> list[ExposureRecord]:
    """Run all non-intrusive checks across discovered assets."""
    from .secrets import scan_web_secrets
    p = progress or (lambda *_: None)
    exposures: list[ExposureRecord] = []
    scanner = PortScanner()
    checkable = [a for a in assets if a.type in ("ip", "subdomain")]
    total = len(checkable)
    done = 0
    for asset in assets:
        if asset.type in ("ip", "subdomain"):
            done += 1
            if done == 1 or done % 3 == 0 or done == total:
                p(f"   ↳ assessing {done}/{total}: {asset.value} "
                  f"({len(exposures)} exposures so far)")
        if asset.type == "ip":
            for port in scanner.scan(asset.value):
                if port in _BENIGN_PORTS:
                    continue                       # 80/443 expected; not a finding
                service, cvss = _PORT_INFO.get(port, ("unknown service", 3.1))
                cls = ("exposed-sensitive-service" if port in _SENSITIVE_PORTS
                       else "exposed-service")
                exposures.append(ExposureRecord(asset.value, cls,
                    f"{service} reachable on {port}/tcp", cvss_base=cvss,
                    extra={"port": port, "service": service}))
        elif asset.type == "subdomain":
            exposures.extend(check_tls(asset.value))
            exposures.extend(check_exposed_files(asset.value))
            exposures.extend(check_takeover(asset.value))
            exposures.extend(check_third_party_hosting(asset.value))
            exposures.extend(check_dev_environment(asset.value))
            if scan_secrets:
                exposures.extend(scan_web_secrets(asset.value))
        # (bucket branch below)
        elif asset.type == "bucket" and asset.meta.get("public"):
            attribution = asset.meta.get("attribution", "weak")
            evidence = asset.meta.get("evidence") or asset.value
            # Only a permuted name that carries a brand token is confidently the
            # target's asset; otherwise flag low and label attribution unverified
            # so a stranger's public bucket is never reported as a Critical finding.
            cvss = 7.5 if attribution == "brand" else 4.0
            note = "" if attribution == "brand" else \
                (" - ATTRIBUTION UNVERIFIED: permuted name, may not belong to the "
                 "target; confirm ownership before reporting")
            exposures.append(ExposureRecord(asset.value, "public-bucket",
                "Cloud storage bucket is publicly readable" + note,
                evidence_ref=evidence, cvss_base=cvss,
                extra={"attribution": attribution}))
    # de-duplicate identical findings (same class + asset + description)
    deduped: dict[tuple, ExposureRecord] = {}
    for e in exposures:
        deduped.setdefault((e.cls, e.asset_value, e.description), e)
    return list(deduped.values())
