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

GOPATH=${GOPATH:-$(go env GOPATH)}

# "go env" doesn't print anything if GOBIN is the default, so we
# have to manually default it.
GOBIN=${GOBIN:-$(go env GOBIN)}
GOBIN=${GOBIN:-${GOPATH}/bin}
REMOTE=${REMOTE:-origin}

echo $GOBIN

go install github.com/elastic/crd-ref-docs@latest

declare -a arr=(
    "main"
)

mkdir -p ${PWD}/tmp

for i in "${arr[@]}"; do
    tmpdir=$(mktemp -d --tmpdir=${PWD}/tmp)

    # Use the current api directory instead of fetching from remote,
    # which is required for CI (Prow) to verify PR changes correctly.
    cp -r api ${tmpdir}/api

    # Start removing any "release-" prefix from docpath
    docpath=${i#"release-"}
    # If the release is "main" simply remove it
    docpath=${docpath#"main"}
	mkdir -p "${PWD}/site-src/reference/${docpath}"

    ${GOBIN}/crd-ref-docs \
        --source-path=${tmpdir}/api \
        --config=crd-ref-docs.yaml \
        --templates-dir=${PWD}/hack/crd-ref-templates/ \
        --renderer=markdown \
        --output-path=${PWD}/site-src/reference/${docpath}/spec.md
done
