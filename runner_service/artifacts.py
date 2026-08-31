from __future__ import annotations

import time
from dataclasses import dataclass

from .security import artifact_key, authorize_artifact, Artifact, ValidationError


@dataclass(frozen=True)
class PresignedUpload:
    key: str
    expires_at: int
    max_bytes: int = 100 * 1024 * 1024


def issue_upload(owner_id: str, job_id: str, filename: str, now: int | None = None, ttl: int = 300) -> PresignedUpload:
    if not 1 <= ttl <= 900:
        raise ValidationError("upload TTL must be at most 15 minutes")
    current = int(time.time()) if now is None else now
    return PresignedUpload(artifact_key(owner_id, job_id, filename), current + ttl)


def authorize_download(owner_id: str, artifact: Artifact, now: int | None = None) -> None:
    authorize_artifact(owner_id, artifact)
    if artifact.expires_at <= (int(time.time()) if now is None else now):
        raise PermissionError("artifact URL expired")


def retention_deadline(created_at: int, retention_seconds: int) -> int:
    if not 0 <= retention_seconds <= 30 * 86400:
        raise ValidationError("retention exceeds documented maximum")
    return created_at + retention_seconds

