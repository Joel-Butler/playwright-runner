# Journal

## 2026-08-31 — orchestration brief

Added `ORCHESTRATION_PROMPT.md`, a self-contained Luna overseer and worker prompt for the Playwright Runner prototype. It records the accepted trust, identity, networking, gVisor-release-blocker, and Ceph S3 artifact-retention decisions without making cluster changes.

## 2026-08-31 — prototype foundation

Implemented the control-plane security primitives, API contract, cleanup lifecycle, unit tests, Restricted-PSS runner Job template, namespace quotas, minimal RBAC, Cilium public-egress policy, Gateway API sub-path route, runner image scaffold, and minimal UI. All changes are local and un-deployed. The image digest is intentionally a release-gate placeholder; gVisor and staging network isolation remain unresolved production blockers. Worker worktrees were provisioned by the app, but no monitorable worker task IDs or worker commits became available, so the overseer reconciled the implementation directly in the main worktree.

## 2026-08-31 — uv test loop

Added setuptools packaging metadata so `runner_service` is installed by `uv sync --extra dev`. The full suite now runs through `uv run pytest`; 7 tests pass. The initial Worker B rework dispatch was accepted by the task service, but its task ID was not exposed for monitoring or integration.

## 2026-08-31 — release audit

Added a fail-closed image release audit. It correctly blocks the current runner and Playwright base image placeholders until immutable digests are populated and `docker buildx imagetools inspect` verifies both linux/amd64 and linux/arm64.
