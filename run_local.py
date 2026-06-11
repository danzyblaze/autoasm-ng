"""One-command local launcher for AutoASM-NG.

    python run_local.py

Checks dependencies, initialises the database, opens your browser, and starts the
web app at http://127.0.0.1:5000 . No configuration required; it uses a local
SQLite database by default.
"""
from __future__ import annotations

import importlib
import subprocess
import sys
import threading
import webbrowser

REQUIRED = ["flask", "sqlalchemy", "requests", "dns", "cryptography", "reportlab"]
PIP_NAMES = {"dns": "dnspython", "sqlalchemy": "SQLAlchemy", "flask": "Flask"}
PORT = 5000


def ensure_deps() -> None:
    missing = []
    for mod in REQUIRED:
        try:
            importlib.import_module(mod)
        except ImportError:
            missing.append(PIP_NAMES.get(mod, mod))
    if missing:
        print(f"[setup] installing missing packages: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet",
                               *missing])
        print("[setup] done")


def main() -> int:
    print("=" * 56)
    print("  AutoASM-NG  -  local launcher")
    print("=" * 56)
    ensure_deps()

    from autoasm.models import init_db
    from autoasm.core import available_tools
    init_db()

    tools = available_tools()
    have = [t for t, ok in tools.items() if ok]
    miss = [t for t, ok in tools.items() if not ok]
    print(f"[tools] available : {', '.join(have) or 'none'}")
    if miss:
        print(f"[tools] optional (pure-Python fallback used): {', '.join(miss)}")

    url = f"http://127.0.0.1:{PORT}"
    print(f"\n[ready] open {url}\n")
    threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    from autoasm.dashboard import create_app
    app = create_app()
    # threaded=True so dashboard polling works while a scan runs in a thread.
    app.run(host="127.0.0.1", port=PORT, threaded=True, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
