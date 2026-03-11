#!/bin/bash

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

# Quickstart setup script for kube-agentic-networking.
# This script automates all the steps from the quickstart guide into a single
# idempotent command. It creates a kind cluster, installs CRDs, deploys the
# controller and MCP server, applies policies, and deploys the AI agent.

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/../../..
source "${SCRIPT_ROOT}/hack/kube-env.sh"

# --- Configuration ---
CLUSTER_NAME="kan-quickstart"
NAMESPACE="quickstart-ns"
CONTROLLER_NAMESPACE="agentic-net-system"
GATEWAY_API_VERSION="v1.4.0"
AGENT_UI_PORT="8081"
AGENT_UI_URL="http://localhost:${AGENT_UI_PORT}/dev-ui/?app=mcp_agent"

# --- Helper Functions ---

info() {
  echo -e "${color_green}[INFO]${color_norm} $*"
}

warn() {
  echo -e "${color_yellow}[WARN]${color_norm} $*"
}

error() {
  echo -e "${color_red}[ERROR]${color_norm} $*" >&2
}

check_command() {
  if ! command -v "$1" &> /dev/null; then
    error "'$1' is required but not found in PATH."
    exit 1
  fi
}

wait_for_deployment() {
  local namespace="$1"
  local selector="$2"
  info "Waiting for deployment (${selector}) in namespace ${namespace}..."
  kubectl wait --timeout=5m -n "${namespace}" deployment ${selector} --for=condition=Available
}

# --- Prerequisite Checks ---

info "Checking prerequisites..."
check_command kind
check_command kubectl
check_command go
check_command envsubst

if [[ -z "${HF_TOKEN:-}" ]]; then
  error "HF_TOKEN environment variable is not set."
  echo "  Please export your HuggingFace token before running this script:"
  echo "    export HF_TOKEN=<your-huggingface-token>"
  echo ""
  echo "  You need a token with 'Make calls to Inference Providers' permission."
  echo "  See: https://huggingface.co/docs/hub/en/security-tokens"
  exit 1
fi

info "All prerequisites satisfied."

# --- Step 1: Create Kind Cluster ---

create_kind_cluster() {
  info "Step 1/9: Creating kind cluster '${CLUSTER_NAME}'..."
  if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    warn "Kind cluster '${CLUSTER_NAME}' already exists, skipping creation."
  else
    kind create cluster --name "${CLUSTER_NAME}" --config="${SCRIPT_ROOT}/dev/ci/kind-config.yaml"
    info "Kind cluster '${CLUSTER_NAME}' created."
  fi
  # Ensure kubectl context is set to the kind cluster.
  kubectl config use-context "kind-${CLUSTER_NAME}"
}

# --- Step 2: Install Gateway API CRDs ---

install_gateway_api_crds() {
  info "Step 2/9: Installing Gateway API CRDs (${GATEWAY_API_VERSION})..."
  kubectl apply --server-side -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"
}

# --- Step 3: Install Agentic Networking CRDs ---

install_agentic_networking_crds() {
  info "Step 3/9: Installing Agentic Networking CRDs..."
  kubectl apply -f "${SCRIPT_ROOT}/k8s/crds/agentic.prototype.x-k8s.io_xbackends.yaml"
  kubectl apply -f "${SCRIPT_ROOT}/k8s/crds/agentic.prototype.x-k8s.io_xaccesspolicies.yaml"
}

# --- Step 4: Create Namespaces ---

create_namespaces() {
  info "Step 4/9: Creating namespaces..."
  kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
  kubectl create namespace "${CONTROLLER_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
}

# --- Step 5: Deploy MCP Server ---

deploy_mcp_server() {
  info "Step 5/9: Deploying in-cluster MCP server..."
  kubectl apply -f "${SCRIPT_ROOT}/site-src/guides/quickstart/mcpserver/deployment.yaml"
  wait_for_deployment "${NAMESPACE}" "mcp-everything"
}

# --- Step 6: Deploy Controller ---

deploy_controller() {
  info "Step 6/9: Deploying Agentic Networking controller..."

  # Create CA pool secret before deploying the controller so the pod can start
  # immediately (it requires the CA pool secret as a volume).
  info "Creating CA pool secret for agentic identity..."
  if kubectl get secret agentic-identity-ca-pool -n "${CONTROLLER_NAMESPACE}" &>/dev/null; then
    warn "CA pool secret already exists, skipping creation."
  else
    (cd "${SCRIPT_ROOT}" && go run ./cmd/agentic-net-tool make-ca-pool-secret \
      --ca-id=v1 \
      --namespace="${CONTROLLER_NAMESPACE}" \
      --name=agentic-identity-ca-pool)
  fi

  kubectl apply -f "${SCRIPT_ROOT}/k8s/deploy/deployment.yaml"
  wait_for_deployment "${CONTROLLER_NAMESPACE}" "agentic-net-controller"
}

# --- Step 7: Apply Policies ---

apply_policies() {
  info "Step 7/9: Applying network policies (Gateway, HTTPRoutes, XBackends, XAccessPolicies)..."
  kubectl apply -f "${SCRIPT_ROOT}/site-src/guides/quickstart/policy/e2e.yaml"

  info "Waiting for Envoy proxy deployment to be created..."
  local retries=0
  local max_retries=30
  while ! kubectl get deployment -n "${NAMESPACE}" \
    -l "kube-agentic-networking.sigs.k8s.io/gateway-name=agentic-net-gateway" \
    -o name 2>/dev/null | grep -q .; do
    retries=$((retries + 1))
    if [[ ${retries} -ge ${max_retries} ]]; then
      error "Timed out waiting for Envoy proxy deployment to be created."
      exit 1
    fi
    sleep 5
  done

  info "Waiting for Envoy proxy to be ready..."
  kubectl wait --timeout=5m -n "${NAMESPACE}" deployment \
    -l "kube-agentic-networking.sigs.k8s.io/gateway-name=agentic-net-gateway" \
    --for=condition=Available
}

# --- Step 8: Deploy Agent ---

deploy_agent() {
  info "Step 8/9: Deploying AI agent..."

  # Wait for the Gateway to have an address assigned.
  info "Waiting for Gateway address to be assigned..."
  local gateway_address=""
  local retries=0
  local max_retries=30
  while [[ -z "${gateway_address}" ]]; do
    gateway_address=$(kubectl get gateway agentic-net-gateway -n "${NAMESPACE}" -o jsonpath='{.status.addresses[0].value}' 2>/dev/null || true)
    if [[ -n "${gateway_address}" ]]; then
      break
    fi
    retries=$((retries + 1))
    if [[ ${retries} -ge ${max_retries} ]]; then
      error "Timed out waiting for Gateway address to be assigned."
      exit 1
    fi
    sleep 5
  done

  # Discover service account for the gateway.
  local gateway_sa
  gateway_sa=$(kubectl get sa -n "${NAMESPACE}" -l "kube-agentic-networking.sigs.k8s.io/gateway-name=agentic-net-gateway" -o jsonpath='{.items[0].metadata.name}')
  if [[ -z "${gateway_sa}" ]]; then
    error "Could not find service account for the gateway."
    exit 1
  fi
  local gateway_spiffe_id="spiffe://cluster.local/ns/${NAMESPACE}/sa/${gateway_sa}"

  info "  Gateway Address:   ${gateway_address}"
  info "  Gateway SPIFFE ID: ${gateway_spiffe_id}"

  # Render and apply sidecar config with envsubst.
  GATEWAY_ADDRESS="${gateway_address}" GATEWAY_SPIFFE_ID="${gateway_spiffe_id}" \
    envsubst < "${SCRIPT_ROOT}/site-src/guides/quickstart/adk-agent/sidecar/sidecar-configs.yaml" | kubectl apply -f -

  # Create HuggingFace secret (idempotent via dry-run).
  kubectl create secret generic hf-secret -n "${NAMESPACE}" \
    --from-literal=hf-token-key="${HF_TOKEN}" \
    --dry-run=client -o yaml | kubectl apply -f -

  # Deploy agent.
  kubectl apply -f "${SCRIPT_ROOT}/site-src/guides/quickstart/adk-agent/deployment.yaml"
  wait_for_deployment "${NAMESPACE}" "adk-agent"
}

# --- Step 9: Set Up Port Forward ---

setup_port_forward() {
  info "Step 9/9: Setting up port-forward to agent UI on port ${AGENT_UI_PORT}..."

  # Kill any existing port-forward on the agent UI port.
  local existing_pid
  existing_pid=$(lsof -ti :"${AGENT_UI_PORT}" 2>/dev/null || true)
  if [[ -n "${existing_pid}" ]]; then
    warn "Killing existing process on port ${AGENT_UI_PORT} (PID: ${existing_pid})."
    kill "${existing_pid}" 2>/dev/null || true
    sleep 1
  fi

  kubectl port-forward -n "${NAMESPACE}" service/adk-agent-svc "${AGENT_UI_PORT}:80" &
  sleep 2
}

# --- Main ---

create_kind_cluster
install_gateway_api_crds
install_agentic_networking_crds
create_namespaces
deploy_mcp_server
deploy_controller
apply_policies
deploy_agent
setup_port_forward

echo ""
info "=========================================="
info " Quickstart setup complete!"
info "=========================================="
info ""
info " Open the agent UI in your browser:"
info "   ${AGENT_UI_URL}"
info ""
info " To clean up, run:"
info "   kind delete cluster --name ${CLUSTER_NAME}"
info ""
