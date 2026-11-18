"""ORM models package — importing this module registers all tables."""

from app.models.endpoints import (
    ENDPOINT_ACTIVE,
    ENDPOINT_REVOKED,
    Endpoint,
    EndpointCredential,
    EndpointFact,
    EndpointGroup,
    EndpointMetadata,
    EndpointSoftware,
    EnrollmentToken,
    endpoint_group_members,
)
from app.models.rbac import Permission, Role, User, role_permissions, user_roles
from app.models.tokens import AuditLog, RefreshToken

__all__ = [
    "ENDPOINT_ACTIVE",
    "ENDPOINT_REVOKED",
    "AuditLog",
    "Endpoint",
    "EndpointCredential",
    "EndpointFact",
    "EndpointGroup",
    "EndpointMetadata",
    "EndpointSoftware",
    "EnrollmentToken",
    "Permission",
    "RefreshToken",
    "Role",
    "User",
    "endpoint_group_members",
    "role_permissions",
    "user_roles",
]
