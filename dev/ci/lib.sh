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

# Common Configuration
SYSTEM_NAMESPACE="agentic-net-system"
REGISTRY="us-central1-docker.pkg.dev/k8s-staging-images/agentic-net"
IMAGE_NAME="agentic-networking-controller"
TAG="main"

# Find the repository root and cd to it
REPO_ROOT=$(git rev-parse --show-toplevel)
cd "${REPO_ROOT}"

# Function to setup kind cluster and install MetalLB
setup_kind_cluster() {
  local cluster_name=$1
  
  header "Creating kind cluster"
  kind delete cluster --name "${cluster_name}" || true
  kind create cluster --name "${cluster_name}" --config dev/ci/kind-config.yaml --wait 5m

  # Increase inotify limits for Envoy
  for node in $(kind get nodes --name "${cluster_name}"); do
    docker exec "$node" sysctl -w fs.inotify.max_user_instances=8192
    docker exec "$node" sysctl -w fs.inotify.max_user_watches=524288
  done

  header "Installing MetalLB"
  install_metallb
}

# Install MetalLB on a kind cluster
install_metallb() {
  local metallb_version="v0.13.10"
  kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/"${metallb_version}"/config/manifests/metallb-native.yaml

  needCreate="$(kubectl get secret -n metallb-system memberlist --no-headers --ignore-not-found -o custom-columns=NAME:.metadata.name)"
  if [ -z "$needCreate" ]; then
      kubectl create secret generic -n metallb-system memberlist --from-literal=secretkey="$(openssl rand -base64 128)"
  fi

  # Wait for MetalLB to become available
  kubectl rollout status -n metallb-system deployment/controller --timeout 5m
  kubectl rollout status -n metallb-system daemonset/speaker --timeout 5m

  # Configure MetalLB with an IP address pool derived from the Docker network used by Kind.
  # We inspect the 'kind' network to find the subnet, and take the range .200 to .250.
  # This range is safe to use because it is at the high end of the subnet, well outside
  # the range a container engine typically uses when dynamically assigning IPs
  # to containers (Kind nodes).
  # For example, if the subnet is 192.168.8.0/24, address_first_three_octets will
  # be 192.168.8 and the range will be 192.168.8.200-192.168.8.250.
  local engine="${CONTAINER_ENGINE:-docker}"
  if [[ "${engine}" == "podman" ]]; then
    subnet=$(podman network inspect kind | jq -r '.[].subnets.[].subnet | select(contains(":") | not)')
  else
    subnet=$(docker network inspect kind | jq -r '.[].IPAM.Config[].Subnet | select(contains(":") | not)')
  fi
  if [[ -z "${subnet}" ]]; then
      echo "Error: Could not find subnet for network kind"
      return 1
  fi

  address_first_three_octets=$(echo "${subnet}" | awk -F. '{printf "%s.%s.%s",$1,$2,$3}')
  address_range="${address_first_three_octets}.200-${address_first_three_octets}.250"

  kubectl apply -f - <<EOF
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  namespace: metallb-system
  name: kube-services
spec:
  addresses:
  - ${address_range}
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: kube-services
  namespace: metallb-system
spec:
  ipAddressPools:
  - kube-services
EOF
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

# Function to dump diagnostics on failure
dump_diagnostics() {
  local status=$?
  local cluster_name=$1
  local system_namespace=$2
  local test_namespace=${3:-}
  local tester_pod_name=${4:-}
  local envoy_selector=${5:-}
  
  if [ "${status}" -ne 0 ]; then
    header "Tests failed, dumping logs..."

    header "Cluster-wide Resources"
    kubectl get all -A || true

    header "Cluster Events"
    kubectl get events -A || true

    header "Controller Description"
    kubectl describe deployment agentic-net-controller -n "${system_namespace}" || true

    header "Controller logs (last 200 lines)"
    kubectl logs deployment/agentic-net-controller -n "${system_namespace}" --all-containers --tail=200 || true
    
    if [ -n "${test_namespace}" ]; then
      header "Test Namespace Resources (${test_namespace})"
      kubectl get all -n "${test_namespace}" || true

      header "Gateway Resources"
      kubectl get gateway -n "${test_namespace}" -o yaml || true

      header "Access Policies"
      kubectl get xaccesspolicies -n "${test_namespace}" || true

      header "Backend Resources"
      kubectl get xbackends -n "${test_namespace}" || true

      header "Pods in test namespace"
      kubectl get pods -n "${test_namespace}" -o wide || true

      header "Pod Certificate Requests"
      kubectl get podcertificaterequests -n "${test_namespace}" -o yaml || true

      header "Cluster Trust Bundles"
      kubectl get clustertrustbundles || true

      if [ -n "${tester_pod_name}" ]; then
        header "Tester Pod YAML"
        kubectl get pod "${tester_pod_name}" -n "${test_namespace}" -o yaml || true
      fi

      header "MCP Server Logs"
      kubectl logs -n "${test_namespace}" -l app=mcp-everything --tail=100 || true

      if [ -n "${envoy_selector}" ]; then
        header "Envoy Proxy Logs"
        kubectl logs -n "${test_namespace}" -l "${envoy_selector}" --all-containers --tail=100 || true
      fi
    fi
  fi
  exit "${status}"
}

# Function to build and load controller image
build_and_load_controller_image() {
  local cluster_name=$1
  local registry=$2
  local image_name=$3
  local tag=$4
  
  header "Building controller image"
  make build REGISTRY="${registry}" IMAGE_NAME="${image_name}" TAG="${tag}" EXTRA_BUILD_OPT="--label runnumber=${BUILD_ID:-0}"

  header "Loading controller image into cluster"
  kind load docker-image "${registry}/${image_name}:${tag}" --name "${cluster_name}"
}

# Function to install CRDs
install_crds() {
  header "Installing Gateway API CRDs"
  kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.1/standard-install.yaml

  header "Installing Project CRDs"
  kubectl apply -f k8s/crds/
}

# Function to setup agentic identity
setup_agentic_identity() {
  local system_namespace=$1
  
  header "Creating agentic-net-system namespace"
  kubectl create namespace "${system_namespace}" --dry-run=client -o yaml | kubectl apply -f -

  header "Creating agentic identity CA"
  kubectl delete secret agentic-identity-ca-pool -n "${system_namespace}" --ignore-not-found
  go run ./cmd/agentic-net-tool -- make-ca-pool-secret --ca-id=v1 --namespace="${system_namespace}" --name=agentic-identity-ca-pool
}

# Function to deploy controller
deploy_controller() {
  local tag=$1
  local system_namespace=$2
  
  header "Deploying Controller"
  sed "s|\(image: .*/agentic-networking-controller:\).*|\1${tag}|" k8s/deploy/deployment.yaml | kubectl apply -f -

  header "Waiting for controller to be ready"
  kubectl wait --for=condition=available --timeout=300s deployment/agentic-net-controller -n "${system_namespace}"
}

# Function to setup cluster and deploy controller
setup_cluster_with_controller() {
  local cluster_name=$1

  # setup_kind_cluster "${cluster_name}"
  # build_and_load_controller_image "${cluster_name}" "${REGISTRY}" "${IMAGE_NAME}" "${TAG}"
  
  install_crds
  setup_agentic_identity "${SYSTEM_NAMESPACE}"
  deploy_controller "${TAG}" "${SYSTEM_NAMESPACE}"
}