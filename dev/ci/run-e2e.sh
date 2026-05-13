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


# Source common library relative to this script
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# Main execution logic
main() {
  setup_cluster_with_controller "${CLUSTER_NAME}"

  header "Running E2E tests"
  # Requirements: K8s v1.35+, PodCertificateRequest/ClusterTrustBundle enabled, and KAN Controller running with --enable-agentic-identity-signer=true.
  cd tests && go clean -testcache && go test -v ./e2e/...
}

# Register the diagnostics trap and run main
trap 'dump_diagnostics "${CLUSTER_NAME}" "${SYSTEM_NAMESPACE}" "${E2E_NAMESPACE}" "e2e-tester" "gateway.networking.k8s.io/gateway-name=e2e-gateway"' EXIT
main "$@"
