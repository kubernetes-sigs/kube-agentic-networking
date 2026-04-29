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
