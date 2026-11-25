# monitoring

No external monitoring stack (Prometheus/Grafana/ELK) ships with EITOP —
deliberately: no paid services, no extra infrastructure to operate.
Built-in observability you can build on:

| Signal | Where |
|---|---|
| Liveness / readiness | `GET /health`, `GET /health/ready` (db + redis) — probe these from your existing monitor |
| Structured logs | JSON lines on stdout per container (docker json-file; prod overlay rotates 5 × 10 MB) — ship with any log agent |
| Worker health | compose healthcheck runs `celery inspect ping` (prod overlay) |
| Audit trail | append-only `audit_logs` table via `GET /api/v1/audit-logs` |
| Backup health | exit codes + log of `infrastructure/scripts/backup.sh` (alert on non-zero / stale files) |
| Directory sync freshness | `GET /api/v1/directory/health`, `sync-runs` |

Suggested integration (operator-provided, not shipped): scrape
`/health/ready` (expect 200) as the service UP signal, alert on
`status: not_ready`, on worker healthcheck failures, and on backup
job non-zero exits.

Runbook-level triage: [../../docs/troubleshooting/README.md](../../docs/troubleshooting/README.md).
