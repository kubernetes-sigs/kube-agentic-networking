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
CLUSTER_NAME="kan-conformance"
CONFORMANCE_NAMESPACE="gateway-conformance-infra"

# Source common library relative to this script
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# Main execution logic
main() {
  setup_cluster_with_controller "${CLUSTER_NAME}"

  header "Running Conformance tests"

  cd tests && go clean -testcache

  local test_args=(-mod=mod -tags conformance -timeout=10m -v ./conformance/... -gateway-class=kube-agentic-networking -cleanup-base-resources=false)
  if [ -n "${RUN_TEST:-}" ]; then
    test_args+=(-run-test="$RUN_TEST")
  fi

  GOWORK=off CGO_ENABLED=0 go test "${test_args[@]}"
}

# Register the diagnostics trap and run main
trap 'dump_diagnostics "${CLUSTER_NAME}" "${SYSTEM_NAMESPACE}" "${CONFORMANCE_NAMESPACE}" "conformance-tester" "gateway.networking.k8s.io/gateway-name"' EXIT
main "$@"
