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
GATEWAY_API_VERSION="v1.5.0"
AGENT_UI_PORT="8081"
AGENT_UI_URL="http://localhost:${AGENT_UI_PORT}/dev-ui/?app=mcp_agent"

# Default to HuggingFace, can be overridden with --ollama or --gemini flags
USE_OLLAMA=false
OLLAMA_BASE_URL="http://host.docker.internal:11434"
OLLAMA_MODEL="qwen2.5:7b"
USE_GEMINI=false
GEMINI_MODEL="gemini-2.5-flash"

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

# --- Parse Command Line Arguments ---

while [[ $# -gt 0 ]]; do
  case $1 in
    --ollama)
      USE_OLLAMA=true
      shift
      ;;
    --ollama-url)
      OLLAMA_BASE_URL="$2"
      shift 2
      ;;
    --ollama-model)
      OLLAMA_MODEL="$2"
      shift 2
      ;;
    --gemini)
      USE_GEMINI=true
      shift
      ;;
    --gemini-model)
      GEMINI_MODEL="$2"
      shift 2
      ;;
    --help|-h)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --ollama              Use Ollama instead of HuggingFace (default: false)"
      echo "  --ollama-url URL      Ollama base URL (default: http://host.docker.internal:11434)"
      echo "  --ollama-model MODEL  Ollama model name (default: qwen2.5:7b)"
      echo "  --gemini              Use Gemini instead of HuggingFace (default: false)"
      echo "  --gemini-model MODEL  Gemini model name (default: gemini/gemini-2.5-flash)"
      echo "  --help, -h            Show this help message"
      echo ""
      echo "Examples:"
      echo "  # Use HuggingFace (requires HF_TOKEN):"
      echo "  export HF_TOKEN=<your-token>"
      echo "  $0"
      echo ""
      echo "  # Use Gemini (requires GOOGLE_API_KEY):"
      echo "  export GOOGLE_API_KEY=<your-api-key>"
      echo "  $0 --gemini"
      echo ""
      echo "  # Use Ollama with defaults:"
      echo "  $0 --ollama"
      echo ""
      echo "  # Use Ollama with custom settings:"
      echo "  $0 --ollama --ollama-url http://192.168.1.100:11434 --ollama-model llama3.2"
      exit 0
      ;;
    *)
      error "Unknown option: $1"
      echo "Run '$0 --help' for usage information."
      exit 1
      ;;
  esac
done

# --- Prerequisite Checks ---

info "Checking prerequisites..."
check_command kind
check_command kubectl
check_command go
check_command envsubst

if [[ "${USE_GEMINI}" == "true" ]]; then
  if [[ -z "${GOOGLE_API_KEY:-}" ]]; then
    error "GOOGLE_API_KEY environment variable is not set."
    echo "  Please export your Gemini API key before running this script:"
    echo "    export GOOGLE_API_KEY=<your-api-key>"
    exit 1
  fi
  info "Using Gemini model: ${GEMINI_MODEL} (GOOGLE_API_KEY is set)."
elif [[ "${USE_OLLAMA}" == "true" ]]; then
  info "Using Ollama model: ${OLLAMA_MODEL} at ${OLLAMA_BASE_URL}"
  warn "Make sure Ollama is running and accessible at ${OLLAMA_BASE_URL}"
else
  if [[ -z "${HF_TOKEN:-}" ]]; then
    error "HF_TOKEN environment variable is not set."
    echo "  Please export your HuggingFace token before running this script:"
    echo "    export HF_TOKEN=<your-huggingface-token>"
    echo ""
    echo "  You need a token with 'Make calls to Inference Providers' permission."
    echo "  See: https://huggingface.co/docs/hub/en/security-tokens"
    echo ""
    echo "  Alternatively, use --ollama flag or --gemini flag."
    exit 1
  fi
  info "Using HuggingFace model (HF_TOKEN is set)."
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

# --- Step 1.5: Install MetalLB ---

install_metallb_step() {
  info "Step 1.5/9: Installing MetalLB..."
  source dev/ci/lib.sh
  install_metallb
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
    -l "gateway.networking.k8s.io/gateway-name=agentic-net-gateway" \
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
    -l "gateway.networking.k8s.io/gateway-name=agentic-net-gateway" \
    --for=condition=Available
}

# --- Step 8: Deploy Agent ---

deploy_agent() {
  info "Step 8/9: Deploying AI agent..."

  # Wait for the Gateway to have an address assigned.
  info "Waiting for Gateway address to be assigned..."
  local gateway_address=""
  local retries=0
  local max_retries=60
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
  gateway_sa=$(kubectl get sa -n "${NAMESPACE}" -l "gateway.networking.k8s.io/gateway-name=agentic-net-gateway" -o jsonpath='{.items[0].metadata.name}')
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

  # Configure agent deployment based on model choice
  if [[ "${USE_GEMINI}" == "true" ]]; then
    info "Configuring agent for Gemini..."
    # Create Google API key secret (idempotent via dry-run).
    kubectl create secret generic google-secret -n "${NAMESPACE}" \
      --from-literal=GOOGLE_API_KEY="${GOOGLE_API_KEY}" \
      --dry-run=client -o yaml | kubectl apply -f -

    # Patch deployment to use Gemini
    kubectl apply -f "${SCRIPT_ROOT}/site-src/guides/quickstart/adk-agent/deployment.yaml"
    kubectl set env deployment/adk-agent -n "${NAMESPACE}" \
      HF_MODEL- \
      HF_TOKEN- \
      OLLAMA_BASE_URL- \
      OLLAMA_MODEL- \
      GEMINI_MODEL="${GEMINI_MODEL}"
    kubectl set env deployment/adk-agent -n "${NAMESPACE}" \
      --from=secret/google-secret --keys=GOOGLE_API_KEY
  elif [[ "${USE_OLLAMA}" == "true" ]]; then
    info "Configuring agent for Ollama..."
    # Patch deployment to use Ollama
    kubectl apply -f "${SCRIPT_ROOT}/site-src/guides/quickstart/adk-agent/deployment.yaml"
    kubectl set env deployment/adk-agent -n "${NAMESPACE}" \
      HF_MODEL- \
      HF_TOKEN- \
      GEMINI_MODEL- \
      GOOGLE_API_KEY- \
      OLLAMA_BASE_URL="${OLLAMA_BASE_URL}" \
      OLLAMA_MODEL="${OLLAMA_MODEL}"
  else
    info "Configuring agent for HuggingFace..."
    # Create HuggingFace secret (idempotent via dry-run).
    kubectl create secret generic hf-secret -n "${NAMESPACE}" \
      --from-literal=hf-token-key="${HF_TOKEN}" \
      --dry-run=client -o yaml | kubectl apply -f -

    # Deploy agent with HF configuration
    kubectl apply -f "${SCRIPT_ROOT}/site-src/guides/quickstart/adk-agent/deployment.yaml"
    kubectl set env deployment/adk-agent -n "${NAMESPACE}" \
      GEMINI_MODEL- \
      GOOGLE_API_KEY- \
      OLLAMA_BASE_URL- \
      OLLAMA_MODEL-
  fi

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
install_metallb_step
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
