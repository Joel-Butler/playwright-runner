# Playwright Runner Architecture

## Status and trust model

This is a local-only prototype and is not production-safe. Runner input is arbitrary Node.js/Playwright code plus package installation, so every runner is fully untrusted. The prototype provides Python control-plane primitives and manifests; it is not yet a running Node.js or Go API service.

Production release is blocked on gVisor installation, a verified `gvisor` RuntimeClass selected by runner Jobs, staging isolation tests, and immutable multi-architecture image verification.

## Identity and routing

Cloudflare Access is the identity provider. The backend must validate the Access JWT signature and claims, then use verified `sub` as the only authorization identity. Email and forwarded identity headers are display metadata only. The backend maps the verified subject to an opaque owner ID.

The intended route is `on.jhbutler.info/playwright-runner` through the existing Cilium Gateway API. The example HTTPRoute uses `URLRewrite`; the prototype does not expose CDP, remote browser WebSockets, or any other remote debugging endpoint. TLS termination, authentication enforcement at the edge, and rate limiting remain deployment requirements/future controls.

## Control plane and execution

The versioned submission contract validates code size, dependency specs, environment-variable names and values, timeout, concurrency, and bounded retention. It validates payload constraints; it does not claim to validate JavaScript syntax.

The backend ServiceAccount is scoped in `playwright-tenant` to the resources it uses: create/get/delete `Secrets` and `ConfigMaps`, and create/get/watch/delete `Jobs`. Runner Jobs use a separate ServiceAccount with `automountServiceAccountToken: false`, Restricted PSS settings, non-root execution, no privilege escalation, dropped capabilities, a read-only root filesystem, and narrowly scoped writable `emptyDir` scratch paths.

Jobs use `activeDeadlineSeconds`, resource limits, and `ttlSecondsAfterFinished`. User code is delivered through a temporary ConfigMap and secrets through environment variables in a temporary Secret. Cleanup of Job, Secret, and ConfigMap is attempted on completion, failure, cancellation, and deadline; failures are observable and retried by control-plane policy.

## Network and artifacts

Cilium policy intends to allow only external DNS and public TCP 80/443 while denying Kubernetes API, node, private/internal, metadata, pod, service, and other cluster destinations. This boundary requires staging verification and is not claimed as proven by this repository.

Logs, screenshots, traces, and videos are bounded retained data in the local Ceph S3-compatible bucket. Keys are scoped by opaque owner ID and job ID. The backend enforces owner-only listing/download and issues runners short-lived, job-prefix-scoped upload authority; runners never receive bucket-wide credentials. Retention is user-selected within documented bounds and requires cleanup execution.

Target-domain allowlisting is a future opt-in mode and is disabled by default.

