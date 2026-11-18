"""Agent-facing endpoints: enrollment, heartbeat, inventory, self-rotation.

Authentication model (separate from user identity):
- ``/agent/enroll`` is unauthenticated but rate-limited and size-limited.
- All other routes require an ``eitop_ep_`` agent credential bound to one
  endpoint; a user JWT is rejected and vice versa.
- Payloads forbid extra fields — a smuggled ``endpoint_id`` (impersonation
  attempt) is a 422, never an authorization input.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import select

from app.api.deps import CurrentEndpoint, DbSession
from app.core.rate_limit import enroll_rate_limit
from app.models import EndpointCredential
from app.schemas.endpoints import (
    AgentCredentialRotateOut,
    AgentEnrollOut,
    AgentEnrollRequest,
    AgentHeartbeatOut,
    AgentHeartbeatRequest,
    AgentInventoryOut,
    AgentInventoryRequest,
)
from app.services.endpoint_service import (
    apply_inventory,
    enroll,
    record_heartbeat,
    rotate_credential,
)

router = APIRouter(prefix="/agent", tags=["agent"])

EnrollGuard = Annotated[None, Depends(enroll_rate_limit)]


@router.post(
    "/enroll",
    response_model=AgentEnrollOut,
    status_code=status.HTTP_201_CREATED,
)
def enroll_endpoint(
    payload: AgentEnrollRequest,
    request: Request,
    db: DbSession,
    _: EnrollGuard,
) -> AgentEnrollOut:
    endpoint, raw_credential = enroll(db, payload, request=request)
    return AgentEnrollOut(
        endpoint_id=endpoint.id,
        credential=raw_credential,
        issued_at=datetime.now(UTC),
    )


@router.post("/heartbeat", response_model=AgentHeartbeatOut)
def heartbeat(
    payload: AgentHeartbeatRequest,
    request: Request,
    db: DbSession,
    endpoint: CurrentEndpoint,
) -> AgentHeartbeatOut:
    record_heartbeat(db, endpoint, payload.agent_version)
    return AgentHeartbeatOut(
        endpoint_id=endpoint.id,
        status=endpoint.status,
        server_time=datetime.now(UTC),
    )


@router.post("/inventory", response_model=AgentInventoryOut)
def submit_inventory(
    payload: AgentInventoryRequest,
    request: Request,
    db: DbSession,
    endpoint: CurrentEndpoint,
) -> AgentInventoryOut:
    counts = apply_inventory(db, endpoint, payload)
    return AgentInventoryOut(
        endpoint_id=endpoint.id,
        accepted=True,
        server_time=datetime.now(UTC),
        counts=counts,
    )


@router.post("/rotate-credential", response_model=AgentCredentialRotateOut)
def rotate_own_credential(
    request: Request,
    db: DbSession,
    endpoint: CurrentEndpoint,
) -> AgentCredentialRotateOut:
    """Agent-initiated rotation: the collector replaces its own credential
    (e.g. on a schedule) without administrator involvement."""
    active = db.scalar(
        select(EndpointCredential)
        .where(
            EndpointCredential.endpoint_id == endpoint.id,
            EndpointCredential.revoked_at.is_(None),
        )
        .order_by(EndpointCredential.created_at.desc())
    )
    assert active is not None  # we just authenticated with it
    raw = rotate_credential(
        db, endpoint, active, request=request, actor_email="agent"
    )
    return AgentCredentialRotateOut(
        endpoint_id=endpoint.id,
        credential=raw,
        issued_at=datetime.now(UTC),
    )


__all__ = ["router"]
