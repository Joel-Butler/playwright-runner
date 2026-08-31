# User-run validation (no cluster writes performed)

Every command set must begin with context verification:

```sh
kubectl config current-context
kubectl apply --dry-run=server -f deploy/k8s/00-namespace.yaml -f deploy/k8s/01-rbac.yaml -f deploy/k8s/02-runner-job-template.yaml -f deploy/k8s/03-egress.yaml -f deploy/k8s/04-gateway-route.yaml -n playwright-tenant
kubectl auth can-i --as=system:serviceaccount:playwright-tenant:backend create jobs -n playwright-tenant
kubectl auth can-i --as=system:serviceaccount:playwright-tenant:runner get secrets -n playwright-tenant
docker buildx imagetools inspect ghcr.io/example/playwright-runner@sha256:REPLACE_WITH_VERIFIED_MULTIARCH_DIGEST
uv run python scripts/image_release_check.py
```

The final command must show linux/amd64 and linux/arm64; replace the placeholder only after verification. Staging isolation tests must run as a Job in `playwright-tenant`: DNS and public HTTPS/HTTP should succeed; Kubernetes API, node addresses, RFC1918/link-local ranges, pod/service CIDRs, `169.254.169.254`, and cluster services must fail. Do not run these commands until gVisor is installed and `kubectl get runtimeclass gvisor -o yaml -n playwright-tenant` verifies the selected handler.
