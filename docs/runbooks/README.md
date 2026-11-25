# Operational runbooks

Step-by-step procedures for operating EITOP. Every command is real —
service names come from `docker-compose.yml`, scripts from
`infrastructure/scripts/`. In production, prefix compose commands with
`-f docker-compose.yml -f docker-compose.prod.yml` (or export
`COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml` once).

| # | Runbook | Covers |
|---|---|---|
| 1 | [First-time deployment](first-time-deployment.md) | fresh install → healthy stack |
| 2 | [Administrator bootstrap](administrator-bootstrap.md) | first admin user, safely |
| 3 | [User and role administration](user-role-administration.md) | create users, assign roles |
| 4 | [Endpoint enrollment and credential rotation](endpoint-enrollment.md) | tokens, agent creds, rotation/revocation |
| 5 | [Endpoint troubleshooting](endpoint-troubleshooting.md) | offline agents, bad inventory |
| 6 | [Active Directory connection setup](ad-connection-setup.md) | first LDAPS connection + test + sync |
| 7 | [AD synchronization troubleshooting](ad-sync-troubleshooting.md) | sync failures by sanitized label |
| 8 | [Findings lifecycle](findings-lifecycle.md) | acknowledge, suppress, reopen |
| 9 | [Backup scheduling and verification](backup-scheduling.md) | cron, retention, verifying dumps |
| 10 | [Database restoration](database-restoration.md) | restore, disaster recovery |
| 11 | [Application upgrades and migrations](upgrades-and-migrations.md) | version upgrades, alembic |
| 12 | [Secret rotation](secret-rotation.md) | SECRET_KEY, DB/Redis passwords, backup keys |
| 13 | [Redis and Celery troubleshooting](redis-celery-troubleshooting.md) | workers, beat, broker |
| 14 | [Service restart and recovery](service-restart-recovery.md) | planned restarts, crash recovery |
| 15 | [Incident response and security investigation](incident-response.md) | triage, containment, audit forensics |
| 16 | [Log inspection and audit review](log-inspection-audit-review.md) | JSON logs, audit queries |

Each runbook states purpose, prerequisites, exact commands with
expected output, failure symptoms, recovery steps, and security
warnings. Reference documentation lives in
[../api/README.md](../api/README.md),
[../configuration/README.md](../configuration/README.md),
[../architecture/README.md](../architecture/README.md).
