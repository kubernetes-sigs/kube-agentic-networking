#!/usr/bin/env bash

# Copyright The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

# Configuration
CLUSTER_NAME="kan-e2e"
E2E_NAMESPACE="e2e-test-ns"
SYSTEM_NAMESPACE="agentic-net-system"

# Find the repository root
REPO_ROOT=$(git rev-parse --show-toplevel)
cd "${REPO_ROOT}"

# Main execution logic
main() {
  header "Creating kind cluster"
  # Ensure we start with a clean state (helpful for local debugging)
  kind delete cluster --name "${CLUSTER_NAME}" || true
  kind create cluster --name "${CLUSTER_NAME}" --config dev/ci/kind-config.yaml --wait 5m

  header "Building controller image"
  IMAGE_TAG="us-central1-docker.pkg.dev/k8s-staging-images/agentic-net/agentic-networking-controller:main"
  docker build . --tag "${IMAGE_TAG}" --label "runnumber=${BUILD_ID:-0}"

  header "Loading controller image into cluster"
  kind load docker-image "${IMAGE_TAG}" --name "${CLUSTER_NAME}"

  header "Installing Gateway API CRDs"
  kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.0/standard-install.yaml

  header "Installing Project CRDs"
  kubectl apply -f k8s/crds/

  # Create namespace and CA secret before deploying the controller so the pod
  # can start immediately (it requires the CA pool secret as a volume).
  header "Creating agentic-net-system namespace"
  kubectl create namespace "${SYSTEM_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

  header "Creating agentic identity CA"
  go run ./cmd/agentic-net-tool -- make-ca-pool-secret --ca-id=v1 --namespace="${SYSTEM_NAMESPACE}" --name=agentic-identity-ca-pool

  header "Deploying Controller"
  kubectl apply -f k8s/deploy/deployment.yaml

  header "Waiting for controller to be ready"
  kubectl wait --for=condition=available --timeout=300s deployment/agentic-net-controller -n "${SYSTEM_NAMESPACE}"

  header "Running E2E tests"
  # Requirements: K8s v1.35+, PodCertificateRequest/ClusterTrustBundle enabled, and KAN Controller running with --enable-agentic-identity-signer=true.
  cd tests && go clean -testcache && go test -v ./e2e/...
}

# Function to print a prominent header
header() {
  local title=$1
  echo ""
  echo "================================================================================"
  echo "  ${title}"
  echo "================================================================================"
  echo ""
}

# Function to dump logs on failure
cleanup() {
  local status=$?
  if [ "${status}" -ne 0 ]; then
    header "Tests failed, dumping logs..."

    header "Cluster-wide Resources"
    kubectl get all -A || true

    header "Cluster Events"
    kubectl get events -A || true

    header "Controller Description"
    kubectl describe deployment agentic-net-controller -n "${SYSTEM_NAMESPACE}" || true

    header "Controller logs (last 200 lines)"
    kubectl logs deployment/agentic-net-controller -n "${SYSTEM_NAMESPACE}" --all-containers --tail=200 || true

    header "E2E Test Namespace Resources"
    kubectl get all -n "${E2E_NAMESPACE}" || true

    header "Gateway Resources"
    kubectl get gateway -n "${E2E_NAMESPACE}" -o yaml || true

    header "Access Policies"
    kubectl get xaccesspolicies -n "${E2E_NAMESPACE}" || true

    header "Backend Resources"
    kubectl get xbackends -n "${E2E_NAMESPACE}" || true

    header "Pods in E2E namespace"
    kubectl get pods -n "${E2E_NAMESPACE}" -o wide || true

    header "Pod Certificate Requests"
    kubectl get podcertificaterequests -n "${E2E_NAMESPACE}" -o yaml || true

    header "Cluster Trust Bundles"
    kubectl get clustertrustbundles || true

    header "Tester Pod YAML"
    kubectl get pod e2e-tester -n "${E2E_NAMESPACE}" -o yaml || true

    header "MCP Server Logs"
    kubectl logs -n "${E2E_NAMESPACE}" -l app=mcp-everything --tail=100 || true

    header "Envoy Proxy Logs"
    kubectl logs -n "${E2E_NAMESPACE}" -l "kube-agentic-networking.sigs.k8s.io/gateway-name=e2e-gateway" --all-containers --tail=100 || true
  fi
  exit "${status}"
}

# Register the cleanup trap and run main
trap cleanup EXIT
main "$@"
