# playwright-runner
An interactive service allowing delegated users to run playwright over the cluster.

## Prototype status

This repository now contains a local-only control-plane contract, security primitives and tests, hardened Kubernetes manifests, a minimal browser UI, and a runner image scaffold. It has not been deployed and must not be treated as production-safe: gVisor installation/RuntimeClass verification, multi-architecture image publication, and staging isolation tests remain release blockers.

The backend authorizes only verified Cloudflare Access JWT subjects, maps them to opaque owner IDs, redacts streamed secrets, and scopes Ceph artifact keys and upload authority by owner/job. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [runner_service/api_contract.md](runner_service/api_contract.md), and [docs/VALIDATION.md](docs/VALIDATION.md).

Install development dependencies with `uv sync --extra dev`, then run local checks with `uv run pytest` and `uv run python scripts/static_policy_test.py`. Kubernetes commands in the validation document are dry-run or inspection commands only; no cluster writes are part of this prototype.

## Agent orchestration

The complete Luna overseer and worker brief is in [ORCHESTRATION_PROMPT.md](./ORCHESTRATION_PROMPT.md). It defines the security boundary, delegated workstreams, integration rules, and release-validation gates for the prototype.
