#!/usr/bin/env bash

# Copyright 2025 The Kubernetes Authors.
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

set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "Usage: $0 <binary_path> <package_url> <version> <gobin_path>" >&2
  exit 1
fi

BINARY_PATH="$1"
PACKAGE_URL="$2"
VERSION="$3"
GOBIN="$4"

VERSIONED_BINARY="${BINARY_PATH}-${VERSION}"
PACKAGE_WITH_VERSION="${PACKAGE_URL}@${VERSION}"

if [ -f "${VERSIONED_BINARY}" ] && [ "$(readlink -- "${BINARY_PATH}" 2>/dev/null)" = "${VERSIONED_BINARY}" ]; then
  exit 0
fi

echo "Downloading ${PACKAGE_WITH_VERSION}"
rm -f "${BINARY_PATH}"
GOBIN="${GOBIN}" go install "${PACKAGE_WITH_VERSION}"
mv "${BINARY_PATH}" "${VERSIONED_BINARY}"
ln -sf "$(realpath "${VERSIONED_BINARY}")" "${BINARY_PATH}"

