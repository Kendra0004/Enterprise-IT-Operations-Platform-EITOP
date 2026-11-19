"""Session helper for Celery tasks.

Workers do not run inside a FastAPI request, so they open their own
session per task and commit/rollback explicitly. Kept separate from
``app.core.database`` to make the request-vs-worker boundary obvious.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy.orm import Session

from app.core.database import SessionLocal


@contextmanager
def session_scope() -> Iterator[Session]:
    """Provide a transactional scope around a worker task."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
