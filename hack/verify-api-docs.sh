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

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")/..

make -C "$SCRIPT_ROOT" api-ref-docs

if ! grep -q "Resource Types" "${SCRIPT_ROOT}/site-src/reference/spec.md"; then
	echo "Error: Generated API reference appears to be empty or broken (missing 'Resource Types')."
	exit 1
fi

if git status -s "${SCRIPT_ROOT}/site-src/reference" 2>&1 | grep -E -q '^\s?[MADRCU\?]'
then
	echo "Uncommitted changes or new files in generated API reference documentation (site-src/reference):"
	git status -s "${SCRIPT_ROOT}/site-src/reference"
	git diff "${SCRIPT_ROOT}/site-src/reference"
	echo ""
	echo "Please run 'make api-ref-docs' and commit the changes."
	exit 1
fi