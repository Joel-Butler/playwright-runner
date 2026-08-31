"""P0 fail-closed validation coverage for the untrusted runner boundary."""

import base64
import hashlib
import hmac
import json
import subprocess
import sys
from pathlib import Path

import pytest

from runner_service.artifacts import authorize_download, issue_upload, retention_deadline
from runner_service.lifecycle import Submission, cleanup_submission
from runner_service.security import (
    AccessClaims,
    Artifact,
    ValidationError,
    artifact_key,
    validate_cloudflare_access_jwt,
    validate_submission,
)

ROOT = Path(__file__).parents[1]


def _b64(value: object) -> str:
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=").decode()


def _rs256_token(claims: dict, *, kid: str = "known", signature: bytes | None = None, algorithm: str = "RS256") -> tuple[str, dict]:
    head = _b64({"alg": algorithm, "kid": kid, "typ": "JWT"})
    body = _b64(claims)
    # Deterministic RSA-shaped fixture: e=1 and a 1024-bit modulus let this
    # dependency-free test exercise the verifier's PKCS#1 v1.5 checks.
    n = (1 << 1024) - 1
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    digest = hashlib.sha256(f"{head}.{body}".encode()).digest()
    encoded = b"\x00\x01" + b"\xff" * (128 - len(prefix) - len(digest) - 3) + b"\x00" + prefix + digest
    sig = signature or encoded
    token = f"{head}.{body}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
    jwks = {"keys": [{"kid": kid, "kty": "RSA", "n": base64.urlsafe_b64encode(n.to_bytes(128, "big")).rstrip(b"=").decode(), "e": "AQ"}]}
    return token, jwks


@pytest.mark.parametrize(
    ("claims", "kid", "jwks", "message"),
    [
        ({"sub": "u", "aud": "aud", "exp": 101}, "known", None, "invalid JWT signature"),
        ({"sub": "u", "aud": "aud", "exp": 101}, "unknown", None, "malformed access token or JWKS"),
        ({"sub": "u", "aud": "wrong", "exp": 101}, "known", None, "invalid JWT claims"),
        ({"sub": "u", "aud": "aud", "exp": 100}, "known", None, "invalid JWT claims"),
        ({"aud": "aud", "exp": 101}, "known", None, "invalid JWT claims"),
        ({"sub": 123, "aud": "aud", "exp": 101}, "known", None, "invalid JWT claims"),
    ],
)
def test_cloudflare_access_rs256_rejections(claims, kid, jwks, message):
    token, valid_jwks = _rs256_token(claims, kid=kid)
    if message == "invalid JWT signature":
        token, _ = _rs256_token(claims, signature=b"x" * 128)
    if message == "malformed access token or JWKS":
        _, valid_jwks = _rs256_token(claims, kid="known")
    with pytest.raises(ValidationError, match=message):
        validate_cloudflare_access_jwt(token, valid_jwks, "aud", now=100)


def test_cloudflare_access_rs256_valid_and_malformed():
    token, jwks = _rs256_token({"sub": "opaque-source", "email": "display@example.test", "aud": "aud", "exp": 101})
    claims = validate_cloudflare_access_jwt(token, jwks, "aud", now=100)
    assert claims == AccessClaims("opaque-source", "display@example.test", 101)
    with pytest.raises(ValidationError):
        validate_cloudflare_access_jwt("not-a-jwt", jwks, "aud", now=100)
    with pytest.raises(ValidationError, match="malformed access token or JWKS"):
        validate_cloudflare_access_jwt(token, {}, "aud", now=100)
    bad_header, _ = _rs256_token({"sub": "u", "aud": "aud", "exp": 101}, algorithm="HS256")
    with pytest.raises(ValidationError, match="unsupported JWT algorithm"):
        validate_cloudflare_access_jwt(bad_header, jwks, "aud", now=100)


def test_submission_exact_byte_boundaries():
    assert len(validate_submission({"code": "x" * (256 * 1024)})["code"].encode()) == 256 * 1024
    with pytest.raises(ValidationError):
        validate_submission({"code": "x" * (256 * 1024 + 1)})
    assert len(validate_submission({"code": "x", "env": {"TOKEN": "é" * 2048}})["env"]["TOKEN"].encode()) == 4096
    with pytest.raises(ValidationError):
        validate_submission({"code": "x", "env": {"TOKEN": "é" * 2049}})


def test_submission_dependency_environment_and_policy_bounds():
    assert len(validate_submission({"code": "x", "dependencies": {f"pkg{i}": "1.0.0" for i in range(32)}})["dependencies"]) == 32
    with pytest.raises(ValidationError):
        validate_submission({"code": "x", "dependencies": {f"pkg{i}": "1.0.0" for i in range(33)}})
    for dependency in {"../escape": "1.0.0"}:
        with pytest.raises(ValidationError):
            validate_submission({"code": "x", "dependencies": {dependency: "1.0.0"}})
    with pytest.raises(ValidationError):
        validate_submission({"code": "x", "dependencies": {"pkg": "https://evil.test/pkg.tgz"}})
    assert validate_submission({"code": "x", "timeoutSeconds": 1, "retentionSeconds": 0})["timeoutSeconds"] == 1
    assert validate_submission({"code": "x", "timeoutSeconds": 900, "retentionSeconds": 30 * 86400})["retentionSeconds"] == 30 * 86400
    for payload in ({"timeoutSeconds": 0}, {"timeoutSeconds": 901}, {"retentionSeconds": -1}, {"retentionSeconds": 30 * 86400 + 1}):
        with pytest.raises(ValidationError):
            validate_submission({"code": "x", **payload})
    with pytest.raises(ValidationError):
        validate_submission({"code": "x", "env": {"bad-name": "x"}})
    with pytest.raises(ValidationError):
        validate_submission({"code": "x", "env": {f"KEY{i}": "x" for i in range(33)}})


class DeletionClient:
    def __init__(self, failures=()):
        self.deleted = []
        self.failures = set(failures)

    def delete(self, kind, name):
        self.deleted.append((kind, name))
        if kind in self.failures:
            raise RuntimeError("simulated deletion failure")


def test_cleanup_partial_failure_is_observable_and_repeatable():
    client = DeletionClient({"secrets"})
    submission = Submission("job-1", "secret-1", "code-1")
    errors = cleanup_submission(client, submission)
    assert errors == ["secrets/secret-1: RuntimeError"]
    assert submission.cleanup_errors == errors
    cleanup_submission(client, submission)
    assert len(client.deleted) == 6


def test_artifact_scope_traversal_ownership_expiry_and_upload_limits():
    owner = "own_" + "a" * 32
    other = "own_" + "b" * 32
    assert artifact_key(owner, "job-1", "../../trace.zip") == owner + "/job-1/.._.._trace.zip"
    for bad in ("bad", owner + "/extra"):
        with pytest.raises(ValidationError): artifact_key(bad, "job-1", "trace.zip")
    with pytest.raises(ValidationError): artifact_key(owner, "job/1", "trace.zip")
    upload = issue_upload(owner, "job-1", "trace.zip", now=100, ttl=900)
    assert upload.expires_at == 1000 and upload.max_bytes == 100 * 1024 * 1024
    artifact = Artifact(owner, "job-1", upload.key, 200)
    authorize_download(owner, artifact, now=199)
    with pytest.raises(PermissionError): authorize_download(other, artifact, now=199)
    with pytest.raises(PermissionError): authorize_download(owner, artifact, now=200)
    with pytest.raises(ValidationError): issue_upload(owner, "job-1", "trace.zip", ttl=901)
    assert retention_deadline(100, 0) == 100


def test_manifest_and_image_release_policy_is_fail_closed():
    result = subprocess.run([sys.executable, "scripts/image_release_check.py"], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode != 0
    assert "not an immutable verified digest" in result.stdout
    job = (ROOT / "deploy/k8s/02-runner-job-template.yaml").read_text()
    policy = (ROOT / "deploy/k8s/03-egress.yaml").read_text()
    assert "runtimeClassName: gvisor" in job
    assert "automountServiceAccountToken: false" in job
    assert "allowPrivilegeEscalation: false" in job
    assert "readOnlyRootFilesystem: true" in job
    assert "drop: [ALL]" in job
    assert "activeDeadlineSeconds:" in job and "limits:" in job
    assert "toEntities: [world]" in policy and 'port: "80"' in policy and 'port: "443"' in policy
    assert "egressDeny:" in policy and "169.254.0.0/16" in policy
