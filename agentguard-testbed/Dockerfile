FROM ghcr.io/astral-sh/uv:0.12.22@sha256:f513a91fc62fe7c17567eee97230dd198e43edb8a9fbecca843714a4358fe1bc AS uv

FROM python:3.14.8-slim-bookworm@sha256:c8137f4c460908c8763f281c8f22c431eb5c538514ba9553fc3a89c06b7cfb88 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:${PATH}"

RUN groupadd --gid 10001 aegis \
    && useradd --uid 10001 --gid aegis --no-create-home --home-dir /app \
       --shell /usr/sbin/nologin aegis
WORKDIR /app

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /uvx /bin/
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./
COPY configs ./configs
COPY scripts/api_entrypoint.sh /usr/local/bin/api-entrypoint
COPY scripts/stage_runtime_secrets.sh /usr/local/bin/stage-runtime-secrets
COPY scripts/runtime_smoke.py /app/scripts/runtime_smoke.py

RUN python -m pip install --no-cache-dir --upgrade \
      "pip>=26.1.2" \
      "setuptools>=78.1.1" \
      "msgpack>=1.2.1" \
      "urllib3>=2.8" \
      "cryptography>=50.0.2" \
      "PyJWT>=2.14" \
    && uv lock --upgrade-package cryptography --upgrade-package PyJWT --upgrade-package urllib3 --upgrade-package msgpack --upgrade-package pip \
    && uv sync --frozen --no-dev --no-editable \
    && uv pip install --python /app/.venv/bin/python --upgrade \
      "msgpack>=1.2.1" \
      "urllib3>=2.8" \
      "cryptography>=50.0.2" \
      "PyJWT>=2.14" \
    && chown -R aegis:aegis /app \
    && chmod 0555 /usr/local/bin/api-entrypoint /usr/local/bin/stage-runtime-secrets

USER aegis:aegis
EXPOSE 8000
ENTRYPOINT ["api-entrypoint"]
CMD ["aegisledger", "serve"]
