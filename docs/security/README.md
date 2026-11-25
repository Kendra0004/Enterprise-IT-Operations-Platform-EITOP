# Security documentation

| Document | Contents |
|---|---|
| [../architecture/security.md](../architecture/security.md) | **Current security model**: trust boundaries, authentication/CSRF/RBAC, encryption at rest and in transit, audit logging, fail-fast config validation, explicit limitations, verified-vs-unverified status |
| [../endpoints/security.md](../endpoints/security.md) | Endpoint-agent threat model: identity separation, enrollment abuse, revocation, input hardening |
| [../authentication.md](../authentication.md) | Login/refresh/logout flow, cookie attributes, token rotation and reuse detection |
| [../rbac.md](../rbac.md) | Permission model and seeded roles |
| [PHASE1_SECURITY_REVIEW.md](PHASE1_SECURITY_REVIEW.md) | Dated Phase-1 audit (2026-11-18): findings, fixes, residual risks — historical record, superseded where later phases changed behavior |
| [../../SECURITY.md](../../SECURITY.md) | Vulnerability reporting policy |

Operations: incident response and secret rotation runbooks in
[../runbooks/](../runbooks/README.md).
