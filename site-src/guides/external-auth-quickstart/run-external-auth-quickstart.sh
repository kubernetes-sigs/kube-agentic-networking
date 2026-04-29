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

# External Auth Quickstart setup script for kube-agentic-networking.
# This script runs the base quickstart and adds external authorization
# using Authorino.

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/../../..
source "${SCRIPT_ROOT}/hack/kube-env.sh"

# --- Configuration ---
NAMESPACE="quickstart-ns"
AUTHORIZER_NAMESPACE="authorino-operator"
AGENT_UI_URL="http://localhost:8081/dev-ui/?app=mcp_agent"

# Store arguments to pass to base quickstart
QUICKSTART_ARGS=()

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

# --- Parse Command Line Arguments ---

while [[ $# -gt 0 ]]; do
  case $1 in
    --ollama)
      QUICKSTART_ARGS+=("--ollama")
      shift
      ;;
    --ollama-url)
      QUICKSTART_ARGS+=("--ollama-url" "$2")
      shift 2
      ;;
    --ollama-model)
      QUICKSTART_ARGS+=("--ollama-model" "$2")
      shift 2
      ;;
    --gemini)
      QUICKSTART_ARGS+=("--gemini")
      shift
      ;;
    --gemini-model)
      QUICKSTART_ARGS+=("--gemini-model" "$2")
      shift 2
      ;;
    --help|-h)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "This script runs the base quickstart and adds external authorization."
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
check_command helm
check_command kubectl
info "All prerequisites satisfied."

# --- Phase 1: Run Base Quickstart ---

run_base_quickstart() {
  info "Part 1: Running base quickstart setup..."
  bash "${SCRIPT_ROOT}/site-src/guides/quickstart/run-quickstart.sh" "${QUICKSTART_ARGS[@]+"${QUICKSTART_ARGS[@]}"}"
}

# --- Phase 2: Deploy External Authorization Service ---

deploy_authorizer() {
  info "Part 2: Deploying external authorization service (Authorino)..."

  # Add Kuadrant Helm repo
  info "Adding Kuadrant Helm repository..."
  helm repo add kuadrant https://kuadrant.io/helm-charts/ --force-update

  # Install Authorino operator if not already installed
  if helm list -n "${AUTHORIZER_NAMESPACE}" 2>/dev/null | grep -q "authorino-operator"; then
    warn "Authorino operator already installed, skipping installation."
  else
    info "Installing Authorino operator..."
    helm install authorino-operator kuadrant/authorino-operator \
      --namespace "${AUTHORIZER_NAMESPACE}" \
      --create-namespace \
      --wait
  fi

  # Deploy Authorino instance
  info "Deploying Authorino instance..."
  kubectl apply -f - <<EOF
apiVersion: operator.authorino.kuadrant.io/v1beta1
kind: Authorino
metadata:
  name: authorino
  namespace: ${AUTHORIZER_NAMESPACE}
spec:
  listener:
    tls:
      enabled: false
  oidcServer:
    tls:
      enabled: false
EOF

  # Deploy AuthConfig with repository-based policy
  info "Deploying repository-based AuthConfig (allow only specific repos)..."
  kubectl apply -f - <<EOF
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: external-auth-config
  namespace: ${AUTHORIZER_NAMESPACE}
spec:
  hosts:
  - '*'
  authorization:
    "allowed-repos-only":
      opa:
        rego: |
          allowed_repos := [
            "kubernetes-sigs/kube-agentic-networking",
            "kubernetes-sigs/gateway-api"
          ]
          repo := input.metadata.filter_metadata.mcp_proxy.params.arguments.repoName
          allow { repo == allowed_repos[_] }
EOF

  # Wait for AuthConfig to be ready
  info "Waiting for AuthConfig to be ready..."
  kubectl wait --for=condition=ready authconfig/external-auth-config \
    -n "${AUTHORIZER_NAMESPACE}" \
    --timeout=120s
}

# --- Phase 3: Apply External Auth Policies ---

apply_external_auth_policies() {
  info "Part 3: Applying external auth policies..."
  kubectl apply -n "${NAMESPACE}" -f "${SCRIPT_ROOT}/site-src/guides/external-auth-quickstart/policy/external-auth.yaml"

  # Give the controller a moment to process the updated policies
  info "Waiting for policies to be processed by the controller..."
  sleep 5
}

# --- Main ---

run_base_quickstart
deploy_authorizer
apply_external_auth_policies

echo ""
info "=========================================="
info " External Auth Quickstart complete!"
info "=========================================="
info ""
info " Open the agent UI in your browser:"
info "   ${AGENT_UI_URL}"
info ""
info " Try the example prompts from the guide:"
info "   - Allowed repos: kubernetes-sigs/kube-agentic-networking, kubernetes-sigs/gateway-api"
info "   - Other repos will be denied"
info ""
