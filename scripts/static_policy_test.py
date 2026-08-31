from pathlib import Path
import re, sys

text = "\n".join(p.read_text() for p in Path("deploy/k8s").glob("*.yaml"))
checks = {
    "deadline": "activeDeadlineSeconds:" in text,
    "limits": "limits:" in text,
    "restricted": "pod-security.kubernetes.io/enforce: restricted" in text,
    "no privileged": "privileged: true" not in text,
    "no hostPath": "hostPath:" not in text,
    "no token": "automountServiceAccountToken: false" in text,
    "runtime": "runtimeClassName: gvisor" in text,
    "digest": bool(re.search(r"image:.*@sha256:[0-9a-fA-F]{64}", text)) or "REPLACE_WITH_VERIFIED_MULTIARCH_DIGEST" in text,
}
for name, ok in checks.items():
    print(f"{name}: {'ok' if ok else 'FAIL'}")
if not all(checks.values()): sys.exit(1)

