# keycloak-passwordless-mover-upper — worker image (target: linux/amd64 for Coolify)
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HEARTBEAT_PATH=/tmp/heartbeat

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Run unprivileged; the only thing we write is the heartbeat file in /tmp.
RUN useradd --create-home --uid 10001 mover
USER mover

# No port to probe (this is a worker, not a server), so health is "the loop
# completed a sweep recently". Allow two intervals plus slack before failing.
HEALTHCHECK --interval=60s --timeout=10s --start-period=120s --retries=3 \
  CMD ["python", "-c", "import os,sys,time; \
p=os.environ.get('HEARTBEAT_PATH','/tmp/heartbeat'); \
i=float(os.environ.get('INTERVAL_MINUTES','15'))*60; \
sys.exit(0 if os.path.exists(p) and time.time()-os.path.getmtime(p) < i*2+300 else 1)"]

CMD ["python", "-m", "src.mover"]
