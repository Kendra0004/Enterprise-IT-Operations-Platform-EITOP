"""Seed initial roles and permissions (idempotent).

Run: python -m app.db.seed
"""

from __future__ import annotations

import logging

from sqlalchemy import func, select

from app.core.database import SessionLocal
from app.models import Permission, Role, User

logger = logging.getLogger(__name__)

# Permission catalog — keep stable; new modules add new permission names.
PERMISSIONS: dict[str, str] = {
    "admin:read": "Read administrative data (users, roles)",
    "admin:write": "Manage users and roles",
    "audit:read": "Read audit logs",
    "endpoints:read": "View endpoint inventory",
    "endpoints:write": "Manage endpoints",
    "security:read": "View security/compliance posture",
    "vulns:read": "View vulnerabilities",
    "vulns:write": "Manage remediation tracking",
    "network:read": "View network devices and metrics",
    "network:write": "Manage network configuration",
    "automation:read": "View automation jobs",
    "automation:execute": "Run automation jobs (privileged)",
    "assets:read": "View assets",
    "assets:write": "Manage assets",
    "reports:read": "Read and export reports",
}

# Initial roles from the platform spec.
ROLES: dict[str, tuple[str, list[str]]] = {
    "admin": ("Full platform administrator", ["admin:read", "admin:write", "audit:read"]),
    "security_auditor": (
        "Read-only security and audit access",
        [
            "audit:read",
            "endpoints:read",
            "security:read",
            "vulns:read",
            "network:read",
            "assets:read",
            "reports:read",
        ],
    ),
    "operator": (
        "Day-to-day IT operations",
        [
            "endpoints:read",
            "endpoints:write",
            "network:read",
            "automation:read",
            "automation:execute",
            "assets:read",
            "assets:write",
            "reports:read",
        ],
    ),
    "readonly": (
        "Read-only access across modules",
        [
            "endpoints:read",
            "security:read",
            "vulns:read",
            "network:read",
            "assets:read",
            "reports:read",
        ],
    ),
    "agent": (
        "Endpoint collector identity (report-only)",
        ["endpoints:write"],
    ),
}


def seed_rbac() -> None:
    """Insert missing permissions and roles. Safe to run repeatedly."""
    with SessionLocal() as db:
        existing_perms = {
            p.name for p in db.scalars(select(Permission)).all()
        }
        for name, desc in PERMISSIONS.items():
            if name not in existing_perms:
                db.add(Permission(name=name, description=desc))

        db.flush()

        perm_by_name = {
            p.name: p for p in db.scalars(select(Permission)).all()
        }

        existing_roles = {r.name for r in db.scalars(select(Role)).all()}
        for name, (desc, perm_names) in ROLES.items():
            if name in existing_roles:
                continue
            role = Role(name=name, description=desc)
            role.permissions = [
                perm_by_name[pn] for pn in perm_names if pn in perm_by_name
            ]
            db.add(role)

        db.commit()
        logger.info("rbac_seeded", extra={"roles": sorted(ROLES)})


def bootstrap_admin(email: str, password: str, full_name: str = "Administrator") -> bool:
    """Create the initial admin user if no users exist yet.

    Returns True when a user was created. Refuses to run when users already
    exist (prevents accidental extra admins via env vars).
    """
    from app.core.security import hash_password

    with SessionLocal() as db:
        user_count = db.scalar(select(func.count()).select_from(User)) or 0
        if user_count > 0:
            logger.info("bootstrap_skipped_users_exist")
            return False
        db.add(
            User(
                email=email.lower(),
                full_name=full_name,
                hashed_password=hash_password(password),
                is_active=True,
                roles=[r for r in db.scalars(select(Role).where(Role.name == "admin"))],
            )
        )
        db.commit()
        logger.info("bootstrap_admin_created", extra={"email": email.lower()})
        return True


if __name__ == "__main__":
    import argparse
    import getpass
    import os
    import sys

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Seed RBAC and optionally bootstrap admin")
    parser.add_argument("--admin-email", default=os.environ.get("BOOTSTRAP_ADMIN_EMAIL"))
    parser.add_argument(
        "--admin-password-stdin",
        action="store_true",
        help=(
            "Read the admin password from stdin (one line) instead of the "
            "environment. Passwords are NEVER accepted as command-line "
            "arguments: argv is visible in `ps` and shell history."
        ),
    )
    args = parser.parse_args()

    seed_rbac()
    if args.admin_email:
        password = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD")
        if args.admin_password_stdin:
            password = sys.stdin.readline().rstrip("\n")
        elif not password and sys.stdin.isatty():
            password = getpass.getpass("Admin password (min 12 chars, hidden): ")
        if not password:
            raise SystemExit(
                "No admin password provided. Set BOOTSTRAP_ADMIN_PASSWORD, "
                "pipe it via --admin-password-stdin, or run interactively."
            )
        if len(password) < 12:
            raise SystemExit("Admin password must be at least 12 characters")
        created = bootstrap_admin(args.admin_email, password)
        print(f"Admin bootstrap: {'created' if created else 'skipped (users exist)'}.")
    else:
        print("RBAC seed complete. (Set BOOTSTRAP_ADMIN_EMAIL/_PASSWORD to create first admin.)")
