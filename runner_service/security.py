from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Mapping

OWNER_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,31}$")
ENV_VALUE_MAX = 4096


class ValidationError(ValueError):
    pass


def validate_submission(payload: Mapping[str, Any]) -> dict[str, Any]:
    code = payload.get("code")
    if not isinstance(code, str) or not code.strip() or len(code.encode()) > 256 * 1024:
        raise ValidationError("code must be non-empty and at most 256 KiB")
    deps = payload.get("dependencies", {})
    if not isinstance(deps, dict) or len(deps) > 32:
        raise ValidationError("dependencies must be an object with at most 32 entries")
    for name, version in deps.items():
        if not isinstance(name, str) or not re.fullmatch(r"@[a-z0-9._-]+/[a-z0-9._-]+|[a-z0-9._-]+", name):
            raise ValidationError("invalid dependency name")
        if not isinstance(version, str) or len(version) > 128 or version.startswith(("git+", "http:", "https:")):
            raise ValidationError("dependencies must use bounded registry version specs")
    env = payload.get("env", {})
    if not isinstance(env, dict) or len(env) > 32:
        raise ValidationError("env must be an object with at most 32 entries")
    for key, value in env.items():
        if not isinstance(key, str) or not OWNER_RE.fullmatch(key) or key.startswith("KUBERNETES_"):
            raise ValidationError("invalid environment variable name")
        if not isinstance(value, str) or len(value.encode()) > ENV_VALUE_MAX:
            raise ValidationError("environment value is too large")
    timeout = payload.get("timeoutSeconds", 900)
    if not isinstance(timeout, int) or not 1 <= timeout <= 900:
        raise ValidationError("timeoutSeconds must be between 1 and 900")
    retention = payload.get("retentionSeconds", 86400)
    if not isinstance(retention, int) or not 0 <= retention <= 30 * 86400:
        raise ValidationError("retentionSeconds must be between 0 and 30 days")
    return {"code": code, "dependencies": deps, "env": env, "timeoutSeconds": timeout, "retentionSeconds": retention}


def opaque_owner_id(subject: str, salt: bytes) -> str:
    if not subject or len(subject) > 512:
        raise ValidationError("invalid identity subject")
    return "own_" + hmac.new(salt, subject.encode(), hashlib.sha256).hexdigest()[:32]


def redact_secrets(text: str, secrets: list[str]) -> str:
    result = text
    for secret in sorted({s for s in secrets if len(s) >= 3}, key=len, reverse=True):
        result = result.replace(secret, "[REDACTED]")
    return result


def _b64(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


@dataclass(frozen=True)
class AccessClaims:
    subject: str
    email: str | None
    expires_at: int


def validate_access_jwt(token: str, secret: bytes, audience: str, now: int | None = None) -> AccessClaims:
    """Prototype HS256 validator; production uses the Cloudflare JWKS key set."""
    try:
        head, body, signature = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValidationError("malformed access token") from exc
    if header.get("alg") != "HS256":
        raise ValidationError("unsupported JWT algorithm")
    expected = _b64(hmac.new(secret, f"{head}.{body}".encode(), hashlib.sha256).digest()).decode()
    if not hmac.compare_digest(expected, signature):
        raise ValidationError("invalid JWT signature")
    current = int(time.time()) if now is None else now
    if claims.get("aud") != audience or not isinstance(claims.get("sub"), str) or int(claims.get("exp", 0)) <= current:
        raise ValidationError("invalid JWT claims")
    return AccessClaims(claims["sub"], claims.get("email"), int(claims["exp"]))


def validate_cloudflare_access_jwt(token: str, jwks: Mapping[str, Any], audience: str, now: int | None = None) -> AccessClaims:
    """Validate a Cloudflare Access RS256 token against a caller-fetched JWKS."""
    try:
        head, body, signature = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        key = next(k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid") and k.get("kty") == "RSA")
        n = int.from_bytes(base64.urlsafe_b64decode(key["n"] + "=" * (-len(key["n"]) % 4)), "big")
        e = int.from_bytes(base64.urlsafe_b64decode(key["e"] + "=" * (-len(key["e"]) % 4)), "big")
        sig = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    except (ValueError, KeyError, StopIteration, TypeError, json.JSONDecodeError) as exc:
        raise ValidationError("malformed access token or JWKS") from exc
    if header.get("alg") != "RS256":
        raise ValidationError("unsupported JWT algorithm")
    size = (n.bit_length() + 7) // 8
    encoded = pow(int.from_bytes(sig, "big"), e, n).to_bytes(size, "big")
    digest = hashlib.sha256(f"{head}.{body}".encode()).digest()
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    expected = b"\x00\x01" + b"\xff" * (size - len(prefix) - len(digest) - 3) + b"\x00" + prefix + digest
    if not hmac.compare_digest(encoded, expected):
        raise ValidationError("invalid JWT signature")
    current = int(time.time()) if now is None else now
    if claims.get("aud") != audience or not isinstance(claims.get("sub"), str) or int(claims.get("exp", 0)) <= current:
        raise ValidationError("invalid JWT claims")
    return AccessClaims(claims["sub"], claims.get("email"), int(claims["exp"]))


@dataclass(frozen=True)
class Artifact:
    owner_id: str
    job_id: str
    key: str
    expires_at: int


def artifact_key(owner_id: str, job_id: str, filename: str) -> str:
    if not re.fullmatch(r"own_[a-f0-9]{32}", owner_id) or not re.fullmatch(r"[a-z0-9-]{1,63}", job_id):
        raise ValidationError("invalid artifact scope")
    safe = filename.replace("/", "_")
    if not safe or len(safe) > 128 or safe in {".", ".."}:
        raise ValidationError("invalid artifact filename")
    return f"{owner_id}/{job_id}/{safe}"


def authorize_artifact(requesting_owner: str, artifact: Artifact) -> None:
    if requesting_owner != artifact.owner_id:
        raise PermissionError("artifact does not belong to owner")
