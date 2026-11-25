# RBAC Model

## Structure

```
User ──< user_roles >── Role ──< role_permissions >── Permission
```

Permissions are strings (`resource:action`). Authorization checks **all**
permissions of **all** roles of the user — a user with any role granting a
permission passes.

## Initial roles

| Role | Permissions |
|---|---|
| `admin` | `admin:read`, `admin:write`, `audit:read`, `endpoints:read`, `endpoints:write`, `directory:read`, `directory:write`, `directory:sync` |
| `security_auditor` | `audit:read`, `endpoints:read`, `directory:read`, `security:read`, `vulns:read`, `network:read`, `assets:read`, `reports:read` |
| `operator` | `endpoints:read/write`, `directory:read`, `network:read`, `automation:read/execute`, `assets:read/write`, `reports:read` |
| `readonly` | `endpoints:read`, `directory:read`, `security:read`, `vulns:read`, `network:read`, `assets:read`, `reports:read` (no `:write` anywhere) |
| `agent` | `endpoints:write` (collector identity, report-only) |

Full catalog lives in `backend/app/db/seed.py` (`PERMISSIONS`), seeded
idempotently. Roles are **data, not code** — new roles can be granted only
existing permissions.

## Enforcing in code

```python
from app.api.deps import require_permissions

AdminWrite = Annotated[User, Depends(require_permissions("admin:write"))]

@router.post("/things")
def create_thing(admin: AdminWrite) -> ...:
    ...  # only reaches here if the caller holds admin:write
```

- Missing permission → **403** problem+json naming the missing permissions.
- Missing/invalid token → **401**.
- Every admin/audit route is guarded; tests assert the role × endpoint
  matrix (see `backend/tests/test_rbac.py`).

## Rules

1. Least privilege: grant `:read` by default; `:write` and especially
   `automation:execute` require explicit need.
2. No permission → no route. There is no "superuser bypass" flag; `admin`
   simply holds all `admin:*` grants.
3. New modules add their permission strings to `PERMISSIONS` and assign
   them to roles in the same PR — never hardcode role names in routes.
4. `agent` role accompanies the collector identity: it can report
   inventory (`endpoints:write`) but read nothing. Collectors themselves
   authenticate with endpoint credentials (`eitop_ep_…`), not user
   logins — do not assign `agent` to humans.

The full role × permission matrix lives in
[api/README.md](api/README.md#permission-matrix).
