"""WSGI entrypoint for production servers (gunicorn / Render / Railway).

    gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120

One worker with several threads is the right shape here: scans run in their own
background threads inside the process, and job progress is tracked in-process, so
multiple workers would not share that state. Threads handle the concurrent web
requests (dashboard polling) while a scan runs.
"""
from autoasm.dashboard import create_app
from autoasm.models import init_db

init_db()
app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
