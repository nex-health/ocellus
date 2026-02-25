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

  echo "==> Detecting API server endpoint..."
  local api_server_ip
  api_server_ip=$(docker inspect "${CLUSTER_NAME}-control-plane" -f '{{.NetworkSettings.Networks.kind.IPAddress}}')
  local api_server_port=6443
  echo "    API server: ${api_server_ip}:${api_server_port}"

  echo "==> Installing Cilium via Helm..."
  helm repo add cilium https://helm.cilium.io/ --force-update
  helm install cilium cilium/cilium \
    --namespace kube-system \
    --set image.pullPolicy=IfNotPresent \
    --set ipam.mode=kubernetes \
    --set k8sServiceHost="${api_server_ip}" \
    --set k8sServicePort="${api_server_port}" \
    --set kubeProxyReplacement=true \
    --wait --timeout 300s

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

  echo "==> Creating e2e-nginx Service..."
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: e2e-nginx
  namespace: default
spec:
  selector:
    app: e2e-nginx
  ports:
    - port: 80
      targetPort: 80
EOF

  echo "==> Starting traffic generator..."
  kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: e2e-traffic-gen
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: e2e-traffic-gen
  template:
    metadata:
      labels:
        app: e2e-traffic-gen
    spec:
      containers:
        - name: wget
          image: busybox:stable
          command: ["sh", "-c"]
          args:
            - |
              while true; do
                wget -q -O /dev/null http://e2e-nginx.default.svc
                sleep 2
              done
EOF
  kubectl wait --for=condition=Ready pods -l app=e2e-traffic-gen -n default --timeout=60s
  echo "==> Waiting for conntrack entries to populate..."
  sleep 5

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
