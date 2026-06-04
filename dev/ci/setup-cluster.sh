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

CLUSTER_NAME="${CLUSTER_NAME:-kan-dev}"

# Source common library relative to this script
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

setup_cluster_with_controller "${CLUSTER_NAME}"

echo ""
echo "Cluster '${CLUSTER_NAME}' is ready."
echo "Context: kind-${CLUSTER_NAME}"
echo ""
echo "To run conformance tests:"
echo "  GATEWAY_CLASS=kube-agentic-networking make conformance"
echo ""
echo "To tear down:"
echo "  make teardown-cluster"
