FROM ghcr.io/astral-sh/uv:0.11.29@sha256:eb2843a1e56fd9e30c7276ce1a52cba86e64c7b385f5e3279a0e08e02dd058fc AS uv

FROM python:3.14.7-slim-bookworm@sha256:23c59390fc717bf09f9336908199a0ae75d9c4264bf296123f94ad772fea3b52 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:${PATH}"

RUN groupadd --gid 10001 aegis \
    && useradd --uid 10001 --gid aegis --no-create-home --home-dir /app \
       --shell /usr/sbin/nologin aegis
WORKDIR /app

COPY --from=uv /uv /uvx /bin/
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./
COPY configs ./configs
COPY scripts/api_entrypoint.sh /usr/local/bin/api-entrypoint
COPY scripts/stage_runtime_secrets.sh /usr/local/bin/stage-runtime-secrets
COPY scripts/runtime_smoke.py /app/scripts/runtime_smoke.py

RUN uv sync --frozen --no-dev --no-editable \
    && chown -R aegis:aegis /app \
    && chmod 0555 /usr/local/bin/api-entrypoint /usr/local/bin/stage-runtime-secrets

USER aegis:aegis
EXPOSE 8000
ENTRYPOINT ["api-entrypoint"]
CMD ["aegisledger", "serve"]
