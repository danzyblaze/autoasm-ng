# AutoASM-NG — single deployable web app (Flask UI + scan engine).
# Includes nmap so the assessment stage runs at full capability.
# Deploy on Render / Railway / Fly / any container host.
FROM python:3.12-slim

# nmap for port/service fingerprinting; build deps for psycopg2.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap ca-certificates gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY autoasm/ ./autoasm/
COPY wsgi.py .

ENV PORT=8000
EXPOSE 8000

# One worker, several threads: scans run in background threads inside the worker.
CMD ["sh", "-c", "gunicorn wsgi:app --bind 0.0.0.0:${PORT:-8000} --workers 1 --threads 8 --timeout 120"]
