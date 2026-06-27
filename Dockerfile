# capsule-anchor — Cloud Run production image.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    CAPSULE_ANCHOR_HOST=0.0.0.0 \
    CAPSULE_ANCHOR_PORT=8000

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -u 1000 -m -s /bin/false anchor

COPY pyproject.toml ./
COPY packages ./packages

# Non-editable install with the postgres extra so psycopg[binary] is present
# when CAPSULE_ANCHOR_DATABASE_URL is set (Cloud SQL backend).
RUN pip install ".[postgres]"

RUN chown -R anchor:anchor /app
USER anchor

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://localhost:8000/health || exit 1

ENTRYPOINT ["capsule-anchor"]
