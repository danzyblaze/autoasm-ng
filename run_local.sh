#!/usr/bin/env bash
# One-command local launcher for AutoASM-NG (macOS / Linux / WSL).
#   ./run_local.sh
set -e
cd "$(dirname "$0")"
PY=python3
command -v $PY >/dev/null 2>&1 || PY=python
exec "$PY" run_local.py
