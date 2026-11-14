# Pulsar Hub — multi-stage build. Build context is the repo root.
# Dev dependencies (requirements-dev.txt) are never installed in the image.
# .env is never COPYed (see .dockerignore); secrets arrive as runtime environment variables only.

# ── Stage 1: dependency builder ──────────────────────────────────────────────
FROM python:3.12-slim AS builder

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ── Stage 2: final (non-root) ────────────────────────────────────────────────
FROM python:3.12-slim AS final

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

RUN groupadd -r -g 10001 app && useradd -r -g app -u 10001 -M -s /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=app:app manage.py ./
COPY --chown=app:app hub ./hub
# The remote-console relay runs from the same image as a third role (`relay`). It imports no
# Django and is given no database address; the web service imports only its settings rules.
COPY --chown=app:app relay ./relay
COPY --chown=app:app docker/entrypoint.sh ./docker/entrypoint.sh

# collectstatic needs settings to load, but reads no database. The values below exist only for
# this one RUN (they are not ENV, so they are not in the image). DJANGO_DEBUG=True is set so that
# settings do not demand OIDC_RSA_PRIVATE_KEY, which is a runtime secret that must never be baked
# in. Static files do not depend on DEBUG. The runtime default stays DEBUG=false.
RUN mkdir -p /app/staticfiles \
    && chmod +x docker/entrypoint.sh \
    && DJANGO_DEBUG=True \
       DJANGO_SECRET_KEY=build-placeholder \
       DATABASE_URL=postgres://x:x@localhost/x \
       python manage.py collectstatic --noinput \
    && chown -R app:app /app/staticfiles

USER app
EXPOSE 8000 8001 8002 8003

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["web"]
