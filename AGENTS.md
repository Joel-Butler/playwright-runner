# AGENTS.md

## Core Context

- **Environment:** Bare-metal K8s on Ubuntu 24.04 (ARM64/AMD64).
- **Platform:** Multi-tenant Playwright execution service for untrusted user scripts.
- **Deployment:** Manual via `kubectl` and `helm`. No CI/CD.
- **Namespace:** `playwright-tenant` - isolated execution namespace for ephemeral test jobs.
- **Ingress:** Cilium Gateway API with HTTPRoutes and WebSocket support.
- **Storage:** Rook-Ceph for persistent data (secrets, logs).

## Critical Guardrails

- **No Cluster Writes:** You cannot modify the cluster. Draft manifests/commands and instruct the user to run them.
- **Ephemeral Execution:** All test workloads must run as K8s `Job` resources with `activeDeadlineSeconds` to ensure automatic cleanup.
- **RBAC Boundary:** Backend API uses minimal ServiceAccount permissions (`create`, `get`, `watch`, `delete` for `Jobs` and `Secrets` only in `playwright-tenant`).
- **Playwright Pods:** Must run with `automountServiceAccountToken: false` and zero API access.
- **Network Isolation:** Playwright pods must have **no access** to internal K8s API server, node IPs, or internal subnets. Only public internet (80/443) and external DNS permitted.
- **Pod Security:** Enforce `Restricted` PSS profile. `drop: ["ALL"]` capabilities, non-root user, read-only filesystem.
- **Runtime Hardening:** Consider **gVisor** or **Kata Containers** via `RuntimeClass` for untrusted code execution.
- **Resource Limits:** Namespace `ResourceQuota` (max 20 concurrent pods, 40GB RAM). Pod `LimitRange` enforces 2GB max memory.
- **Secrets:** Managed via Doppler/External Secrets. Never hardcode. Secrets are temporary K8s `Secret` resources, deleted immediately after execution.
- **Gateway over Ingress:** ALWAYS use the Gateway API for routing. NEVER use the Ingress API.
- **Multi-Arch:** ALWAYS verify `arm64`/`amd64` support for all images. ALWAYS pin image tags and Helm chart versions.

## Agent Execution Guardrails

### File Integrity

- **Git-Centric Approach:** Use atomic commits and worktrees. Agents operate on isolated worktrees; changes are committed locally and only merged upon explicit approval.
- **Workspace Isolation:** Use isolated temporary directories (e.g., `/tmp/agent-session-XXX`) for non-code tasks.
- **Auditability:** All file system write attempts should be logged.

### Command Execution

- **Restricted Shell:** Use a restricted shell environment with limited executables. All command inputs must be sanitized.
- **Principle of Least Privilege (PoLP):** Use dedicated service accounts with minimum permissions.
- **No Direct Cluster Writes:** Operate on drafted manifests only. All destructive or write actions require explicit, human-verified prompts.
- **Context Enforcement:** Always mandate `--namespace` and verify `kubectl config current-context`.

## Workflow Conventions

- **Documentation:** Mandatory: any configuration change MUST include a concurrent update to the local `README.md`.
- **Hybrid Routing:** For new services, prefer onboarding to the consolidated domain using sub-paths (e.g., `/playwright-runner`). Use `URLRewrite` filters to map sub-paths to backend root `/`.
- **Helm:** Preferred path for new apps is a custom chart in the shared Helm repository.

## Directory Structure

```
.
├── Apps/                           # Application-specific K8s manifests and Helm charts
│   └── playwright-runner/          # Playwright-as-a-Service deployment
│       ├── frontend/               # Frontend UI (React + Monaco Editor)
│       ├── backend/                # Backend API (Node.js/Go)
│       └── playwright-tenant/      # Ephemeral job execution templates
├── Cilium/                         # Cilium networking and CNI policies
│   └── network-policies/           # Egress policies for tenant isolation
├── Gateway/                        # Gateway API configurations
├── Helm/                           # Global Helm values and templates
├── Monitoring/                     # Observability stack (Prometheus, Grafana, Loki)
├── Security/                       # RBAC, ServiceAccounts, PSS, RuntimeClass
├── Storage/                        # Storage backend configurations
└── Scripts/                        # Automation and maintenance scripts
```

## Playwright Tenant Guardrails

### Ephemeral Job Creation

- **Job Template:** Must use `activeDeadlineSeconds` (e.g., 900s = 15 minutes) for auto-cleanup.
- **Secret Injection:** User secrets mounted as environment variables only, never as files.
- **ConfigMap Injection:** User code mounted via `ConfigMap` or `emptyDir`.
- **Teardown:** Backend API must proactively delete both `Job` and `Secret` upon completion or timeout.

### Network Isolation (Cilium NetworkPolicies)

- **Drop All Internal Traffic:** Block access to K8s API server, node IPs, and internal subnets.
- **Permit External Access:** Allow DNS resolution and public internet (80/443) for browser data protocol.
- **Enforce PSS:** `Restricted` profile with `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`.

### Log Scrubbing

- **Backend API Must Intercept:** Pod log streams must be filtered to mask known secret values before transmission to Frontend UI.

## Pi-Harness Interaction Patterns

- **Navigation:** Use `ls -R` or `find` to orient, then `read` to examine specific files.
- **Large Files:** Use `limit` and `offset` for large files to prevent truncation.
- **Log Files:** Prefer `tail` with `grep` for relevant entries.
- **Command Output:** For large outputs, avoid returning full content. Use `tail`, `grep`, or filtering tools.
- **Precise Edits:** Use `edit` for modifying existing files. Ensure `oldText` matches exactly.
- **New Files:** Use `write` for creating new files or complete rewrites.
- **Execution:** Use `bash` to run commands. Verify against **Critical Guardrails** before `kubectl`/`helm`.

## Observability & Debugging

- **Metrics:** Use Prometheus to check resource usage and pod health.
- **Logs:** Use Loki to inspect application and system logs.
- **Correlation:** Correlate Prometheus metric spikes with Loki log anomalies.
- **Dashboards:** Refer to existing Grafana configurations in `Monitoring/`.

## Knowledge Preservation & Journaling

### 📝 Local Work Journaling Guidelines

- **Purpose:** Journals are for in-progress work.
- **Location:** Must be created within the specific working sub-folder (e.g., `apps/playwright-runner/JOURNAL.md`).
- **Progress Reporting:** At task completion, document accomplishments in the local journal.

### 📚 Centralized Knowledge Base (KB) Requirements

- **Context Tagging:** Tag contributions by repository and service (e.g., `repo:playwright-runner`, `service:backend-api`).
- **Retrieval:** KB queries must include context tags to scope search results.

## Essential Commands

- **Verify Namespace:** `kubectl config current-context` then `kubectl get ns playwright-tenant -o yaml`
- **Deploy App:** `kubectl apply -f Apps/playwright-runner/ -n playwright-tenant`
- **Inspect Jobs:** `kubectl get jobs -n playwright-tenant -o wide`
- **View Logs:** `kubectl logs -n playwright-tenant <pod-name> --tail=100`
- **Cilium Policy:** `kubectl get networkpolicies -n playwright-tenant -o yaml`
- **Resource Quota:** `kubectl describe resourcequota -n playwright-tenant`
- **Pod Security:** `kubectl get pods -n playwright-tenant -o jsonpath='{.items[*].spec.securityContext}'`

## Risk Assessment Summary

| Risk Category | Threat | Mitigation |
|--------------|--------|------------|
| Host/Cluster | Script escapes sandbox | Cilium egress policies, PSS `Restricted`, gVisor/Kata |
| User Secrets | Credential leakage | No persistent storage, log scrubbing, TLS enforcement |
| Resource Exhaustion | Memory leaks/DDoS | ResourceQuota, LimitRange, activeDeadlineSeconds |
| Network Access | Internal scanning | NetworkPolicies drop all internal traffic |
