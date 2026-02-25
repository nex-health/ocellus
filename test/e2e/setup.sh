#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${KIND_CLUSTER_NAME:-ocellus-e2e}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

usage() {
  echo "Usage: $0 {up|down}" >&2
  exit 1
}

cluster_up() {
  echo "==> Creating kind cluster '${CLUSTER_NAME}'..."
  kind create cluster --name "${CLUSTER_NAME}" --config "${SCRIPT_DIR}/kind-config.yaml" --wait 60s

  echo "==> Installing Cilium via Helm..."
  helm repo add cilium https://helm.cilium.io/ --force-update
  helm install cilium cilium/cilium \
    --namespace kube-system \
    --set image.pullPolicy=IfNotPresent \
    --set ipam.mode=kubernetes \
    --wait --timeout 120s

  echo "==> Waiting for Cilium to be ready..."
  kubectl wait --for=condition=Ready pods -l app.kubernetes.io/name=cilium-agent -n kube-system --timeout=120s

  echo "==> Deploying test workload..."
  kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: e2e-nginx
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: e2e-nginx
  template:
    metadata:
      labels:
        app: e2e-nginx
    spec:
      containers:
        - name: nginx
          image: nginx:stable-alpine
          ports:
            - containerPort: 80
EOF
  kubectl wait --for=condition=Ready pods -l app=e2e-nginx -n default --timeout=120s
  echo "==> Cluster ready."
}

cluster_down() {
  echo "==> Deleting kind cluster '${CLUSTER_NAME}'..."
  kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
  echo "==> Done."
}

case "${1:-}" in
  up)   cluster_up ;;
  down) cluster_down ;;
  *)    usage ;;
esac
