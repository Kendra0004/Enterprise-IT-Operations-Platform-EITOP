"""make audit_logs append-only at the database level

Revision ID: 0002_audit_append_only
Revises: 0001_initial
Create Date: 2026-11-18

A row-level trigger rejects any UPDATE or DELETE on ``audit_logs`` so the
audit trail cannot be rewritten even by a compromised application process or
a direct psql session using the application role.

Operational notes:
- The application role cannot drop the trigger (it is not a table owner
  action unless performed by the owner; the owner here is the role that
  created the table — typically ``eitop``). For a deliberate retention purge,
  an administrator must explicitly drop ``audit_logs_append_only`` first.
- ``TRUNCATE`` is not blocked by row triggers; it remains available for
  test fixtures, and a future retention design should replace it with
  partitioned archival instead.
- Deleting a ``users`` row would normally fire the FK ``ON DELETE SET NULL``
  on ``audit_logs.actor_user_id`` (an UPDATE) and now fail by design —
  user deletion must disable the trigger deliberately.
"""
from alembic import op

revision = "0002_audit_append_only"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION audit_logs_block_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION
                'audit_logs is append-only: % is not permitted', TG_OP
                USING ERRCODE = 'restrict_violation';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_logs_append_only
        BEFORE UPDATE OR DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION audit_logs_block_mutation()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS audit_logs_block_mutation()")
