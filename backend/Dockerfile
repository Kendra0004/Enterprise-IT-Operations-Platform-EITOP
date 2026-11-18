# Runtime image: ONLY production dependencies (no pytest/ruff/mypy).
FROM python:3.12-slim AS runtime

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
