FROM mcr.microsoft.com/playwright@sha256:REPLACE_WITH_VERIFIED_PLAYWRIGHT_BASE_DIGEST
USER 10001:10001
COPY --chmod=0555 entrypoint.sh /usr/local/bin/runner-entrypoint
ENTRYPOINT ["/usr/local/bin/runner-entrypoint"]
# Release gate: publish a digest only after docker buildx imagetools inspect proves linux/amd64 and linux/arm64.
