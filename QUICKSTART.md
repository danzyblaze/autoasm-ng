# AutoASM-NG - Quick Start (run on your own machine)

The fastest way to see AutoASM-NG running on `http://localhost:5000`.

## Windows (easiest)

**Double-click `Run-AutoASM-NG.bat`.**

It installs any missing Python packages, starts the app, and opens your browser
automatically. That is all.

## Any OS (one command)

```bash
python run_local.py
```

(macOS / Linux / WSL: `./run_local.sh`)

This checks dependencies, sets up a local SQLite database, opens
`http://127.0.0.1:5000`, and starts the dashboard.

## First scan

1. The dashboard opens. Click **+ New scan**.
2. Enter an organisation name and one or more root domains you own or are
   authorised to assess (for example `example.com`).
3. Click **Launch scan**. A live progress page shows discovery, assessment,
   correlation, and scoring as they run.
4. When it finishes you get the ranked findings, charts, and a **PDF report**
   button.

## Command line (no browser)

```bash
python -m autoasm.cli scan --org "Example Bank" --domains example.com
python -m autoasm.cli report --scan 1            # JSON summary
python -m autoasm.cli report --scan 1 --pdf      # PDF report
python -m autoasm.cli tools                       # which optional tools are present
```

## Optional power-up tools

AutoASM-NG works out of the box in pure Python. If these are on your PATH it uses
them for deeper results (and falls back gracefully if not):

- **nmap** - faster, deeper port and service scanning
- **subfinder** / **assetfinder** / **amass** - richer subdomain discovery
- **nuclei** - template-based misconfiguration and CVE checks

Run `python -m autoasm.cli tools` to see what is detected.

## Notes

- Scans are passive and non-intrusive. Only scan assets you own or are authorised
  to assess.
- A full scan of a large estate can take a while (minutes to hours). A single
  small domain is quick. The live progress page keeps you updated.
- Data is stored in a local `data/autoasm.db` SQLite file. Delete it to reset.
