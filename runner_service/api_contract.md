# Submission API v1

`POST /api/v1/jobs` accepts `{code, dependencies, env, timeoutSeconds, retentionSeconds}` after Cloudflare Access JWT authentication. The response is `{jobId, status:"queued"}`. `GET /api/v1/jobs/{jobId}`, `GET /api/v1/jobs/{jobId}/logs` (SSE), and `GET /api/v1/jobs/{jobId}/artifacts` are owner-scoped. `DELETE /api/v1/jobs/{jobId}` requests cancellation and cleanup.

The backend maps the verified JWT `sub` to `own_<HMAC>`; email and forwarded headers are display metadata only. Runner upload URLs are short-lived and restricted to `own_<owner>/<job>/<filename>` prefixes. Backend downloads and listings require the same opaque owner ID. Future target-domain allowlisting is an explicit opt-in policy, disabled in v1.

