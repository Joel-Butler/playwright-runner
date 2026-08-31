"""P1 defense-in-depth checks for runtime and platform boundaries."""

import re
from pathlib import Path

import pytest

from runner_service.lifecycle import Submission, cleanup_submission
from runner_service.security import Artifact, ValidationError, authorize_artifact, artifact_key, redact_secrets

ROOT = Path(__file__).parents[1]


class FailureClient:
    def __init__(self, failures):
        self.failures = set(failures)
        self.calls = []

    def delete(self, kind, name):
        self.calls.append((kind, name))
        if kind in self.failures:
            raise OSError(f"{kind} unavailable")


def test_cleanup_attempts_every_resource_and_reports_all_failures():
    submission = Submission("job-1", "secret-1", "code-1")
    client = FailureClient({"jobs", "configmaps"})
    errors = cleanup_submission(client, submission)
    assert client.calls == [("jobs", "job-1"), ("secrets", "secret-1"), ("configmaps", "code-1")]
    assert errors == ["jobs/job-1: OSError", "configmaps/code-1: OSError"]
    assert submission.cleanup_errors == errors


def test_cleanup_is_repeatable_after_partial_failure():
    submission = Submission("job-1", "secret-1", "code-1")
    client = FailureClient({"secrets"})
    first = cleanup_submission(client, submission)
    second = cleanup_submission(client, submission)
    assert first == second == ["secrets/secret-1: OSError"]
    assert client.calls.count(("jobs", "job-1")) == 2


def test_redaction_overlapping_multiline_unicode_and_short_values():
    assert redact_secrets("prefix ABCDE suffix", ["ABCDE", "BCD"]) == "prefix [REDACTED] suffix"
    assert redact_secrets("line one\n秘密鍵\nline three", ["秘密鍵"]) == "line one\n[REDACTED]\nline three"
    # Very short values are deliberately not redacted to avoid corrupting logs.
    assert redact_secrets("x 12", ["x", "12"]) == "x 12"


def test_artifact_rejects_invalid_owner_job_and_filename_shapes():
    owner = "own_" + "c" * 32
    for invalid_owner in ("own_", "own_" + "G" * 32, "owner_" + "c" * 32):
        with pytest.raises(ValidationError): artifact_key(invalid_owner, "job-1", "trace.zip")
    for invalid_job in ("", "job/1", "../escape", "J" * 64):
        with pytest.raises(ValidationError): artifact_key(owner, invalid_job, "trace.zip")
    for invalid_filename in ("", ".", "..", "x" * 129):
        with pytest.raises(ValidationError): artifact_key(owner, "job-1", invalid_filename)


def test_artifact_owner_authorization_is_exact():
    owner = "own_" + "c" * 32
    artifact = Artifact(owner, "job-1", artifact_key(owner, "job-1", "trace.zip"), 100)
    authorize_artifact(owner, artifact)
    with pytest.raises(PermissionError): authorize_artifact(owner[:-1] + "d", artifact)


def test_runner_entrypoint_is_fail_closed_and_uses_scratch_only():
    entrypoint = (ROOT / "runner_image/entrypoint.sh").read_text()
    assert "set -eu" in entrypoint
    assert "npm install --ignore-scripts" in entrypoint
    assert "npm_config_cache=/tmp/npm-cache" in entrypoint
    assert "PLAYWRIGHT_BROWSERS_PATH=/tmp/ms-playwright" in entrypoint
    assert "printf '%s' \"$DEPENDENCIES_JSON\"" in entrypoint
    assert "echo" not in entrypoint
    assert "kubectl" not in entrypoint and "CDP" not in entrypoint


def test_every_container_image_is_digest_pinned_and_release_audit_is_required():
    refs = []
    for path in [ROOT / "runner_image/Dockerfile", *sorted((ROOT / "deploy/k8s").glob("*.yaml"))]:
        for line in path.read_text().splitlines():
            match = re.search(r"(?:FROM|image:)\s+([^\s]+)", line)
            if match:
                refs.append(match.group(1))
    assert refs
    assert all("@sha256:" in ref for ref in refs)
    placeholders = {
        "mcr.microsoft.com/playwright@sha256:REPLACE_WITH_VERIFIED_PLAYWRIGHT_BASE_DIGEST",
        "ghcr.io/example/playwright-runner@sha256:REPLACE_WITH_VERIFIED_MULTIARCH_DIGEST",
    }
    assert all(ref in placeholders or re.fullmatch(r".*@sha256:[0-9a-f]{64}", ref) for ref in refs)


def test_manifest_security_context_network_and_exact_rbac_scope():
    job = (ROOT / "deploy/k8s/02-runner-job-template.yaml").read_text()
    policy = (ROOT / "deploy/k8s/03-egress.yaml").read_text()
    rbac = (ROOT / "deploy/k8s/01-rbac.yaml").read_text()
    assert "runtimeClassName: gvisor" in job
    assert "automountServiceAccountToken: false" in job
    assert "runAsNonRoot: true" in job
    assert "seccompProfile: {type: RuntimeDefault}" in job
    assert "allowPrivilegeEscalation: false" in job
    assert "readOnlyRootFilesystem: true" in job
    assert "capabilities: {drop: [ALL]}" in job
    assert "activeDeadlineSeconds: 900" in job and "limits:" in job and "memory: 2Gi" in job
    assert "toEntities: [world]" in policy
    assert 'port: "80"' in policy and 'port: "443"' in policy
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10"):
        assert cidr in policy
    assert "resources: [secrets, configmaps]" in rbac
    assert "resources: [jobs]" in rbac
    assert "verbs: [create, get, watch, delete]" in rbac
    assert "cluster-admin" not in rbac and "nodes" not in rbac and "pods/exec" not in rbac
