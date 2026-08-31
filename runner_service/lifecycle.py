from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


class ClusterClient(Protocol):
    def create_secret(self, name: str, data: dict[str, str]) -> None: ...
    def create_job(self, name: str, secret_name: str, code_name: str, timeout: int) -> None: ...
    def delete(self, kind: str, name: str) -> None: ...


@dataclass
class Submission:
    job_id: str
    secret_name: str
    code_name: str
    cleanup_errors: list[str] = field(default_factory=list)


def cleanup_submission(client: ClusterClient, submission: Submission) -> list[str]:
    errors = []
    for kind, name in (("jobs", submission.job_id), ("secrets", submission.secret_name), ("configmaps", submission.code_name)):
        try:
            client.delete(kind, name)
        except Exception as exc:  # cleanup is best effort but observable
            errors.append(f"{kind}/{name}: {type(exc).__name__}")
    submission.cleanup_errors.extend(errors)
    return errors

