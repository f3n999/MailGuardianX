# syntax=docker/dockerfile:1.6
# ════════════════════════════════════════════════════════════
#  Stage 1 — builder : compile les wheels (yara-python, asyncpg, bcrypt)
# ════════════════════════════════════════════════════════════
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Dépendances système nécessaires à la compilation des extensions C
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libffi-dev \
        libssl-dev \
        libpq-dev \
        libmagic1 \
        libjansson-dev \
        automake \
        libtool \
        make \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Installation des deps Python dans un venv isolé
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt


# ════════════════════════════════════════════════════════════
#  Stage 2 — base : runtime minimal commun
# ════════════════════════════════════════════════════════════
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

LABEL maintainer="MailGuardianX Team — Oteria B3" \
      description="MailGuardianX Orchestrator API"

# Dépendances runtime (pas de compilateur ici)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        libmagic1 \
        libjansson4 \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Copie le venv depuis builder
COPY --from=builder /opt/venv /opt/venv

WORKDIR /app

# User non-root
RUN useradd --create-home --uid 1000 --shell /bin/bash mailguard


# ════════════════════════════════════════════════════════════
#  Stage 3 — production
# ════════════════════════════════════════════════════════════
FROM base AS production

# Code applicatif (en dernier pour maximiser le cache)
COPY --chown=mailguard:mailguard orchestrator/ ./orchestrator/
COPY --chown=mailguard:mailguard yara-rules/ ./yara-rules/
COPY --chown=mailguard:mailguard alembic/ ./alembic/
COPY --chown=mailguard:mailguard alembic.ini ./

USER mailguard

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "orchestrator.api.main:app", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "4", \
     "--proxy-headers", "--forwarded-allow-ips=*"]


# ════════════════════════════════════════════════════════════
#  Stage 4 — Celery worker (image partagée, CMD différent)
# ════════════════════════════════════════════════════════════
FROM production AS worker

CMD ["celery", "-A", "orchestrator.celery_app", "worker", \
     "--loglevel=info", "--concurrency=4", \
     "-Q", "celery", "--prefetch-multiplier=1"]


# ════════════════════════════════════════════════════════════
#  Stage 5 — development (avec --reload + outils)
# ════════════════════════════════════════════════════════════
FROM base AS development

COPY --chown=mailguard:mailguard orchestrator/ ./orchestrator/
COPY --chown=mailguard:mailguard yara-rules/ ./yara-rules/
COPY --chown=mailguard:mailguard alembic/ ./alembic/
COPY --chown=mailguard:mailguard alembic.ini ./

USER mailguard

CMD ["uvicorn", "orchestrator.api.main:app", \
     "--host", "0.0.0.0", "--port", "8000", "--reload"]
