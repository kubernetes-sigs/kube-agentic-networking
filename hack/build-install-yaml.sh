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

readonly CRD_DIR="k8s/crds"
readonly RELEASE_DIR="release"
readonly VERSION_FILE="version/version.go"
readonly KUSTOMIZATION_FILE="$CRD_DIR/kustomization.yaml"

if [ ! -f "$VERSION_FILE" ]; then
    echo "Error: $VERSION_FILE not found. Make sure you run this script from the repository root." >&2
    exit 1
fi

if [ ! -f "$KUSTOMIZATION_FILE" ]; then
    echo "Error: $KUSTOMIZATION_FILE not found. Please create it to define which CRDs to include." >&2
    exit 1
fi

# Extract version from version/version.go
TAG=$(awk -F'"' '/BundleVersion\s*=/ {print $2}' "$VERSION_FILE")

if [ -z "$TAG" ]; then
    echo "Error: Could not extract BundleVersion from $VERSION_FILE." >&2
    exit 1
fi

# Read list of CRD files to include from kustomization.yaml
# It matches lines starting with optional spaces, a hyphen, and spaces, then extracts the filename.
EXPERIMENTAL_CRDS=($(awk '/^[[:space:]]*-[[:space:]]+/ {gsub(/^[[:space:]]*-[[:space:]]+/,""); print}' "$KUSTOMIZATION_FILE"))

if [ ${#EXPERIMENTAL_CRDS[@]} -eq 0 ]; then
    echo "Error: No resources found in $KUSTOMIZATION_FILE." >&2
    exit 1
fi

echo "Building install YAML for version: $TAG"
echo "Reading resources from: $KUSTOMIZATION_FILE"

mkdir -p "$RELEASE_DIR"

# Output file is version-specific
OUTPUT_FILE="$RELEASE_DIR/experimental-install-${TAG}.yaml"

# Make clean file with boilerplate
if [ -f hack/boilerplate/boilerplate.sh.txt ]; then
    readonly YEAR=$(date +"%Y")
    cat hack/boilerplate/boilerplate.sh.txt > "$OUTPUT_FILE"

    # Replace YEAR in boilerplate
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sed -i "s/YEAR/${YEAR}/g" "$OUTPUT_FILE"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/YEAR/${YEAR}/g" "$OUTPUT_FILE"
    else
        echo "Warning: Unsupported OS for sed, boilerplate year not updated."
    fi
else
    echo "# Experimental Installation Manifests - Version $TAG" > "$OUTPUT_FILE"
fi

cat << EOF >> "$OUTPUT_FILE"
#
# Kube Agentic Networking Experimental Resources Install
# Version: ${TAG}
# (Includes resources defined in ${KUSTOMIZATION_FILE})
#
EOF

for file in "${EXPERIMENTAL_CRDS[@]}"; do
    full_path="$CRD_DIR/$file"
    if [ -f "$full_path" ]; then
        echo "Appending $file..."
        echo "---" >> "$OUTPUT_FILE"
        echo "#" >> "$OUTPUT_FILE"
        echo "# $file" >> "$OUTPUT_FILE"
        echo "#" >> "$OUTPUT_FILE"
        cat "$full_path" >> "$OUTPUT_FILE"
    else
        echo "Warning: $full_path not found, skipping."
    fi
done

echo "Generated: $OUTPUT_FILE"

