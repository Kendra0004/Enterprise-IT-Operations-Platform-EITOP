# docker

Docker build assets for EITOP. There is no separate image registry or
build service — images are built locally by Compose.

| File | Purpose |
|---|---|
| [`../../docker-compose.yml`](../../docker-compose.yml) | development stack (services: `backend`, `worker`, `beat`, `frontend`, `postgres`, `redis`, `tester`) |
| [`../../docker-compose.prod.yml`](../../docker-compose.prod.yml) | production overlay (TLS edge proxy, port removal, resource limits, log rotation, worker healthcheck) |
| [`../../backend/Dockerfile`](../../backend/Dockerfile) | API/worker/beat image (non-root, entrypoint runs migrations + seed) |
| [`../../frontend/Dockerfile`](../../frontend/Dockerfile) | Node build stage → `nginx-unprivileged` (uid 101, port 8080) |

Usage: see [../../docs/installation/README.md](../../docs/installation/README.md)
(dev) and [../../docs/installation/production.md](../../docs/installation/production.md)
(production).
