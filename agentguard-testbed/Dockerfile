FROM ghcr.io/astral-sh/uv:0.12.9@sha256:8b940d3a9d65bed080436972241af2e21c84b5e8c9193f7014ed71479ee795ff AS uv

FROM python:3.13.14-slim-bookworm@sha256:9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64 AS runtime

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
