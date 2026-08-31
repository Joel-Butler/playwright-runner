"""Fail-closed image release audit; manifest inspection must be run by an operator."""
from pathlib import Path
import re
import sys

refs = []
for path in [Path("runner_image/Dockerfile"), *Path("deploy/k8s").glob("*.yaml")]:
    for line in path.read_text().splitlines():
        match = re.search(r"(?:FROM|image:)\s+([^\s]+)", line)
        if match:
            refs.append((path, match.group(1)))

failed = False
for path, ref in refs:
    if "REPLACE_WITH" in ref or not re.search(r"@sha256:[0-9a-f]{64}$", ref):
        print(f"BLOCKED {path}: {ref} is not an immutable verified digest")
        failed = True
    else:
        print(f"OK {path}: {ref}")
        print("  operator must verify linux/amd64 and linux/arm64 with docker buildx imagetools inspect")

if failed:
    sys.exit(1)
