"""Flask dashboard (FR10) — view scans, ranked findings, and export PDF.

Run via:  python -m autoasm.cli serve
"""
from __future__ import annotations

import hmac

from flask import (Flask, render_template, abort, send_file, request,
                   redirect, url_for, jsonify, session)

from . import config
from .models import Organisation, Scan, get_session
from .reporting import (scan_summary, export_pdf, export_de_xlsx,
                        scan_assets, export_assets_xlsx, export_assets_csv)
from .jobs import start_scan, job_status


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = config.SECRET_KEY
    # Gate the dashboard only when a password is configured (AUTOASM_PASSWORD).
    # Local runs stay open; a public deployment sets the password to require login.
    auth_required = bool(config.DASHBOARD_PASSWORD)

    @app.context_processor
    def _auth_ctx():
        return {"auth_on": auth_required, "logged_in": session.get("auth", False)}

    @app.before_request
    def _require_login():
        if not auth_required:
            return None
        if request.endpoint in ("login", "logout", "static"):
            return None
        if not session.get("auth"):
            return redirect(url_for("login", next=request.path))
        return None

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not auth_required:
            return redirect(url_for("index"))
        error = None
        if request.method == "POST":
            u = request.form.get("username", "")
            p = request.form.get("password", "")
            ok = (hmac.compare_digest(u, config.DASHBOARD_USER) and
                  hmac.compare_digest(p, config.DASHBOARD_PASSWORD))
            if ok:
                session["auth"] = True
                session.permanent = True
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") else url_for("index"))
            error = "Invalid username or password."
        return render_template("login.html", error=error)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login") if auth_required else url_for("index"))

    @app.route("/")
    def index():
        session = get_session()
        try:
            scans = session.query(Scan).order_by(Scan.started_at.desc()).all()
            orgs = {o.id: o.name for o in session.query(Organisation).all()}
            rows = [{"id": s.id, "org": orgs.get(s.org_id, "?"),
                     "assets": s.asset_count, "exposures": s.exposure_count,
                     "duration": s.duration_seconds, "started": s.started_at}
                    for s in scans]
            return render_template("index.html", scans=rows)
        finally:
            session.close()

    @app.route("/scan/<int:scan_id>")
    def scan_view(scan_id: int):
        st = job_status(scan_id)
        if st.get("state") == "unknown":
            abort(404)
        if st.get("state") != "completed":
            return render_template("running.html", scan_id=scan_id, st=st)
        data = scan_summary(scan_id)
        if not data:
            return render_template("running.html", scan_id=scan_id, st=st)
        return render_template("scan.html", d=data)

    @app.route("/api/scan/<int:scan_id>/status")
    def scan_status_api(scan_id: int):
        return jsonify(job_status(scan_id))

    @app.route("/scan/<int:scan_id>/pdf")
    def scan_pdf(scan_id: int):
        try:
            path = export_pdf(scan_id)
        except ValueError:
            abort(404)
        return send_file(path, as_attachment=True)

    @app.route("/scan/<int:scan_id>/de")
    def scan_de(scan_id: int):
        """Consultant-style findings XLSX report (synopsis / category / impact /
        resolution / status / appendix) via findings2de.py."""
        try:
            path = export_de_xlsx(scan_id)
        except (ValueError, FileNotFoundError):
            abort(404)
        return send_file(path, as_attachment=True)

    @app.route("/scan/<int:scan_id>/assets")
    def scan_assets_view(scan_id: int):
        """Asset inventory — viewable while a scan runs or after it completes,
        regardless of whether any exposures were found."""
        data = scan_assets(scan_id)
        if not data:
            abort(404)
        return render_template("assets.html", d=data)

    @app.route("/scan/<int:scan_id>/assets.xlsx")
    def scan_assets_xlsx(scan_id: int):
        try:
            path = export_assets_xlsx(scan_id)
        except ValueError:
            abort(404)
        return send_file(path, as_attachment=True)

    @app.route("/scan/<int:scan_id>/assets.csv")
    def scan_assets_csv(scan_id: int):
        try:
            path = export_assets_csv(scan_id)
        except ValueError:
            abort(404)
        return send_file(path, as_attachment=True)

    @app.route("/new", methods=["GET", "POST"])
    def new_scan():
        if request.method == "POST":
            org = request.form["org"].strip()
            domains = [d.strip() for d in request.form["domains"].split(",")
                       if d.strip()]
            crit = int(request.form.get("criticality", 3))
            scan_id = start_scan(org, domains, default_criticality=crit)
            return redirect(url_for("scan_view", scan_id=scan_id))
        return render_template("new.html")

    return app
