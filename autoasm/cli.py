"""Command-line interface for AutoASM-NG.

Usage:
  python -m autoasm.cli scan --org "Example Bank" --domains example.com,foo.com
  python -m autoasm.cli report --scan 1 [--pdf]
  python -m autoasm.cli serve [--port 5000]
  python -m autoasm.cli tools
"""
from __future__ import annotations

import argparse
import json
import sys


def _cmd_scan(args) -> int:
    from .orchestrator import Orchestrator
    domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    if not domains:
        print("error: --domains is required", file=sys.stderr)
        return 2
    orch = Orchestrator(args.org, domains, default_criticality=args.criticality,
                        allowed_ips=(args.ips.split(",") if args.ips else None))
    scan_id = orch.run()
    print(f"scan_id={scan_id}")
    return 0


def _cmd_report(args) -> int:
    from .reporting import scan_summary, export_pdf
    data = scan_summary(args.scan)
    if not data:
        print(f"error: no scan {args.scan}", file=sys.stderr)
        return 1
    if args.pdf:
        path = export_pdf(args.scan)
        print(f"PDF written: {path}")
    else:
        print(json.dumps(data, indent=2, default=str))
    return 0


def _cmd_serve(args) -> int:
    from .dashboard import create_app
    create_app().run(host=args.host, port=args.port, debug=args.debug)
    return 0


def _cmd_tools(_args) -> int:
    from .core import available_tools
    for tool, present in available_tools().items():
        print(f"{tool:12} {'present' if present else 'MISSING (fallback used)'}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="autoasm",
        description="AutoASM-NG — automated external attack surface management")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="run a scan")
    sp.add_argument("--org", required=True)
    sp.add_argument("--domains", required=True, help="comma-separated root domains")
    sp.add_argument("--ips", default="", help="comma-separated authorised IPs")
    sp.add_argument("--criticality", type=int, default=3)
    sp.set_defaults(func=_cmd_scan)

    rp = sub.add_parser("report", help="show / export a scan report")
    rp.add_argument("--scan", type=int, required=True)
    rp.add_argument("--pdf", action="store_true")
    rp.set_defaults(func=_cmd_report)

    vp = sub.add_parser("serve", help="run the web dashboard")
    vp.add_argument("--host", default="127.0.0.1")
    vp.add_argument("--port", type=int, default=5000)
    vp.add_argument("--debug", action="store_true")
    vp.set_defaults(func=_cmd_serve)

    tp = sub.add_parser("tools", help="show external tool availability")
    tp.set_defaults(func=_cmd_tools)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
