# Contributing to EITOP

Thanks for your interest in contributing.

## Ground rules

1. All code must be free and open source (MIT-compatible dependencies only).
2. **Never** commit secrets, credentials, tokens, or private keys.
3. Every feature change ships with tests. No task is done until CI is green.
4. No placeholder implementations of core functionality — mark work as
   "Under development" instead of faking behavior.
5. Shared architecture or database contract changes must be proposed first
   (open an issue / ADR) before implementation.

## Development workflow

1. Fork and branch from `main` (`feature/<short-name>`).
2. Set up the environment per [docs/local-development.md](docs/local-development.md).
3. Run checks before pushing:

   ```bash
   cd backend && ruff check . && mypy app && pytest
   cd frontend && npm run build && npm test
   ```

4. Open a pull request. Describe *why* the change exists.

## Code standards

- Backend: Python 3.12, type-annotated, `ruff` + `mypy` clean.
- Frontend: TypeScript strict mode, no `any` without justification.
- Migrations: additive-only in normal PRs; destructive migrations need an ADR.
- Commit messages: imperative mood, scoped (`auth: add refresh rotation`).

## Review criteria

- Tests cover the new behavior (including failure paths).
- Security impact considered (authz, input validation, injection).
- Docs updated when behavior or env vars change.
