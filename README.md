# AutoASM-NG

**Automated External Attack Surface Management with threat intelligence and
breach-pattern correlation, tuned for the Nigerian financial sector.**

AutoASM-NG discovers an organisation's internet-facing assets, runs passive
non-intrusive checks against them, correlates the findings with public threat
intelligence (NVD, CISA KEV, HIBP) and an anonymised regional breach-pattern
corpus, and ranks every exposure by how it is *actually* exploited in the local
threat landscape, not just by raw CVSS. Results land in a web dashboard and an
exportable PDF report.

> Passive and non-intrusive by design. No exploitation, no credential testing,
> no load-inducing activity. Scan assets you own or are authorised to assess.

## What it does

1. **Discovery** — subdomains (crt.sh + DNS brute-force + optional subfinder/amass),
   IP/ASN mapping, cloud buckets (S3/Azure/GCP keyword permutation), API endpoints
   (OpenAPI/Swagger).
2. **Assessment** — open ports, weak/expired TLS, exposed config files,
   subdomain-takeover fingerprints, public cloud storage.
3. **Correlation** — NVD CVEs, CISA KEV (in-the-wild), HIBP domain breaches, and an
   anonymised regional breach-pattern corpus.
4. **Risk scoring** — `RiskScore = criticality (1–5) × CVSS (0–1) × breach_relevance (1.0–2.0)`.
5. **Reporting** — dashboard with charts + PDF export of the prioritised findings.

## Architecture

A single deployable web app. The Flask app serves the dashboard and runs the scan
engine in background threads, so long scans never block the UI.

```
  Flask app  ──►  scan engine (autoasm/)  ──►  database
  (UI + API)      discovery / assessment        SQLite (dev)
                  correlation / scoring          Postgres (prod)
```

## Quick start (local)

```bash
python -m pip install -r requirements.txt
python -m autoasm.cli serve            # http://127.0.0.1:5000
```
Or run a scan headless:
```bash
python -m autoasm.cli scan --org "Example Bank" --domains example.com
python -m autoasm.cli report --scan 1 --pdf
python -m autoasm.cli tools            # show which optional tools are present
```

Optional external tools (auto-detected; pure-Python fallback if absent):
`nmap`, `subfinder`, `assetfinder`, `amass`, `nuclei`.

## Deploy (one app, one click)

**Render:** push to GitHub → New → Blueprint → pick the repo. It reads
`render.yaml` (Docker image includes nmap, provisions Postgres). Open the URL.

**Railway:** push to GitHub → New Project → Deploy from repo. It reads
`railway.json`. Add a Postgres plugin and set `AUTOASM_DB_URL`.

The scan engine needs raw sockets and nmap and runs for minutes to hours, so it
deploys to a container host (Render/Railway), not Vercel serverless. A separate
Vercel frontend can be added later against the same engine if desired.

## Evaluation

`eval/` holds a private harness that measures recall, exposure coverage, and
risk-ranking correlation against an expert ground truth built from real
engagements. `eval/private/` is git-ignored; client domains and findings never
get committed, and the dissertation refers only to anonymised "Bank A/B/C".

```bash
python -m eval.harness run eval/private/bankA.json
python -m eval.harness all eval/private/
```

## Project context

Built as a MIVA Open University MIT Professional Master's Project, and usable as a
real attack-surface tool. The breach-pattern corpus is fully de-identified; no
client or engagement is named anywhere in this repository.

## License

MIT (see LICENSE). Use responsibly and only within authorisation.
