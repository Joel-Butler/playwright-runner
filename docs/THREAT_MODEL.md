# Threat model and release blockers

Runner input is arbitrary code plus package installation, so the runner is fully untrusted. The backend never evaluates it. The boundary is layered: Restricted PSS, non-root/read-only filesystem, no service-account token, resource/time limits, Cilium public-egress-only policy, and a gVisor RuntimeClass.

ADRs: (1) Cloudflare Access JWT `sub` is the only authorization identity; headers/email are untrusted. (2) owner/job-prefixed Ceph objects and short-lived scoped presigned URLs are mandatory. (3) target-domain allowlisting is designed but disabled by default. (4) `gvisor` is a production-release prerequisite, not an assertion of current availability. (5) image digest and both-architecture manifest verification are release gates.

