# Runtime image: ONLY production dependencies (no pytest/ruff/mypy).
FROM python:3.12-slim AS runtime

# Official python:3.12-slim lags Debian security updates; the container-scan
# gate (trivy, HIGH/CRITICAL, ignore-unfixed) fails on base-image CVEs until
# the layer below is applied. Keep narrow: only packages with fixable
# findings, upgraded from trixie-security.
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade zlib1g \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root
RUN useradd --create-home --uid 10001 eitop

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml .
COPY alembic.ini .
COPY alembic ./alembic
COPY app ./app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER eitop

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]

# Dev/test image: runtime + lint/test toolchain. Used by the `tester`
# compose service; never deployed to production.
FROM runtime AS dev

USER root
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt
USER eitop
