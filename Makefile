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

# We need all the Make variables exported as env vars.
# Note that the ?= operator works regardless.

# Enable Go modules.
export GO111MODULE=on
# Warn if undefined variables are referenced.
MAKEFLAGS += --warn-undefined-variablesm

# First target in the Makefile is a default target when run with no
# arguments.
default: all
.PHONY: default

# This must be included after the default target (it defines targets
# so we cannot have it be first in the Makefile).
IMAGE_NAME ?= agentic-networking-controller
include $(CURDIR)/hack/build/Makefile.common.in

.PHONY: help ## Print this help menu.
help:
	@grep -hE '^[ a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-17s\033[0m %s\n", $$1, $$2}'

.PHONY: all
# Note: the build target is defined in hack/build/Makefile.common.in.
# It builds for the local architecture and loads the image into the local docker daemon.
all: validate-python vet fmt verify test build  ## Test, verify and build this project locally.

PYTHON_FILES := $(shell find ./hack -type f -name "*.py")
PYTHON_FILES += $(shell find ./site-src -type f -name "*.py")

.PHONY: validate-python
validate-python:
	@echo "Validating Python files"
	@if [ -n "$(PYTHON_FILES)" ]; then python -m py_compile $(PYTHON_FILES); else echo "No Python files found."; fi

.PHONY: fmt
fmt:  ## Run go fmt against code.
	$(info ...Begin to run go fmt against code.)
	go fmt ./...
	cd tests && go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	$(info ...Begin to run go vet against code.)
	go vet ./...
	cd tests && go vet ./...

.PHONY: test
test: test-unit test-cel test-crd ## Run all tests.

.PHONY: test-unit
test-unit: ## Run unit tests.
	$(info ...Running unit tests.)
	# Only run tests for packages that actually contain test files to avoid warnings and wasted cycles.
	go list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' ./... | xargs go test -race -cover

.PHONY: test-cel
test-cel: ## Run CEL tests.
	$(info ...Running CEL tests.)
	cd tests && go test -v ./cel/...

.PHONY: test-crd
test-crd: ## Run CRD tests.
	$(info ...Running CRD tests.)
	cd tests && go test -v ./crd/...

.PHONY: test-e2e
test-e2e: ## Run full E2E tests including cluster setup and controller deployment.
	$(info ...Running full E2E pipeline (setup + test).)
	./dev/ci/run-e2e.sh

.PHONY: verify
verify: ## Run go vet
	hack/verify-all.sh -v

REPO_ROOT:=${CURDIR}

## @ Code Generation Variables

# Find the code-generator package in the Go module cache.
# The 'go mod download' command in the targets ensures this will succeed.
CODEGEN_PKG = $(shell go env GOPATH)/pkg/mod/k8s.io/code-generator@$(shell go list -m -f '{{.Version}}' k8s.io/code-generator)
CODEGEN_SCRIPT := $(CODEGEN_PKG)/kube_codegen.sh

# The root directory where your API type definitions are located.
SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/
# The root directory where client code will be placed.
CLIENT_OUTPUT_DIR := $(REPO_ROOT)/k8s/client
# The root Go package for your generated client code.
CLIENT_OUTPUT_PKG := $(shell go list -m | head -n 1)/k8s/client
BOILERPLATE_FILE := hack/boilerplate/boilerplate.generatego.txt


## @ Code Generation

.PHONY: generate
generate: manifests deepcopy register clientsets ## Generate manifests, deepcopy code, and clientsets.

.PHONY: manifests
manifests: controller-gen ## Generate CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd paths="./api/..." output:crd:artifacts:config=k8s/crds

.PHONY: deepcopy
deepcopy: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="$(BOILERPLATE_FILE)" paths="./api/..."

.PHONY: clientsets
clientsets: ## Generate clientsets, listers, and informers.
	@echo "--- Ensuring code-generator is in module cache..."
	@go mod download k8s.io/code-generator
	@echo "+++ Generating client code..."
	@bash -c 'source $(CODEGEN_SCRIPT); \
		kube::codegen::gen_client \
		    --with-watch \
		    --output-dir $(CLIENT_OUTPUT_DIR) \
		    --output-pkg $(CLIENT_OUTPUT_PKG) \
		    --boilerplate $(BOILERPLATE_FILE) \
		    ./'

.PHONY: register
register: ## Generate register code for CRDs under ./api/v0alpha0 and ./api/v1alpha1
	@echo "--- Ensuring code-generator is in module cache..."
	@go mod download k8s.io/code-generator
	@echo "+++ Generating register code for api/v0alpha0..."
	@bash -c 'source $(CODEGEN_SCRIPT); \
		kube::codegen::gen_register \
		    --boilerplate $(BOILERPLATE_FILE) \
		    ./api/v0alpha0'
	@echo "+++ Generating register code for api/v1alpha1..."
	@bash -c 'source $(CODEGEN_SCRIPT); \
		kube::codegen::gen_register \
		    --boilerplate $(BOILERPLATE_FILE) \
		    ./api/v1alpha1'


## @ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen

## Tool Versions
CONTROLLER_TOOLS_VERSION ?= v0.19.0

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN) ## Installs controller-gen if not already installed.
	chmod +x ./hack/install-tool.sh
	./hack/install-tool.sh \
		"$(CONTROLLER_GEN)" \
		"sigs.k8s.io/controller-tools/cmd/controller-gen" \
		"$(CONTROLLER_TOOLS_VERSION)" \
		"$(LOCALBIN)"
# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

##@Quickstart

.PHONY: quickstart
quickstart: ## Run the quickstart setup with HuggingFace (requires HF_TOKEN env var, kind, kubectl, go).
	site-src/guides/quickstart/run-quickstart.sh

.PHONY: quickstart-ollama
quickstart-ollama: ## Run the quickstart setup with Ollama
	site-src/guides/quickstart/run-quickstart.sh --ollama

.PHONY: quickstart-gemini
quickstart-gemini: ## Run the quickstart setup with Gemini (requires GOOGLE_API_KEY env var)
	site-src/guides/quickstart/run-quickstart.sh --gemini

# Variables for easy updates
AGENT_IMG    := locally-built-adk-agent-image
AGENT_TAG    := dev
NAMESPACE    := quickstart-ns
CONTEXT      := $(shell kubectl config current-context)

.PHONY: dev-reload-agent
dev-reload-agent: ## Build, load and restart ADK agent in Kind with safety checks
	@if [[ "$(CONTEXT)" != kind-* ]]; then \
		echo "Error: Current context is '$(CONTEXT)', not a Kind cluster."; \
		exit 1; \
	fi

	@echo "Building ADK agent image..."
	DOCKER_BUILDKIT=1 docker build -t $(AGENT_IMG):$(AGENT_TAG) site-src/guides/quickstart/adk-agent/

	@CLUSTER_NAME=$(shell echo $(CONTEXT) | sed 's/kind-//'); \
	echo "Loading image into Kind cluster: $$CLUSTER_NAME..."; \
	kind load docker-image $(AGENT_IMG):$(AGENT_TAG) --name $$CLUSTER_NAME

	@echo "Updating Deployment in namespace: $(NAMESPACE)..."
	kubectl patch deployment adk-agent -n $(NAMESPACE) --type=json \
		-p='[{"op": "replace", "path": "/spec/template/spec/containers/0/imagePullPolicy", "value": "IfNotPresent"}]'
	
	kubectl set image deployment/adk-agent adk-agent=$(AGENT_IMG):$(AGENT_TAG) -n $(NAMESPACE)
	
	@echo "Restarting adk-agent pods..."
	kubectl rollout restart deployment/adk-agent -n $(NAMESPACE)

.PHONY: dev-reload-controller
dev-reload-controller: build ## Build and reload controller image into Kind cluster
	@if [[ "$(CONTEXT)" != kind-* ]]; then \
		echo "Error: Current context is '$(CONTEXT)', not a Kind cluster."; \
		exit 1; \
	fi
	@CLUSTER_NAME=$$(echo $(CONTEXT) | sed 's/kind-//'); \
	echo "Loading image into Kind cluster: $$CLUSTER_NAME..."; \
	kind load docker-image $(REGISTRY)/$(IMAGE_NAME):$(TAG) --name $$CLUSTER_NAME

	@echo "Updating Deployment in namespace: agentic-net-system..."
	kubectl patch deployment agentic-net-controller -n agentic-net-system --type=json \
		-p='[{"op": "replace", "path": "/spec/template/spec/containers/0/imagePullPolicy", "value": "IfNotPresent"}]'
	
	kubectl set image deployment/agentic-net-controller manager=$(REGISTRY)/$(IMAGE_NAME):$(TAG) -n agentic-net-system
	
	@echo "Restarting agentic-net-controller pods..."
	kubectl rollout restart deployment/agentic-net-controller -n agentic-net-system

##@Docs

.PHONY: build-docs
build-docs: api-ref-docs
	docker build --pull -t kube-agentic-networking/mkdocs hack/mkdocs/image
	docker run --rm -v ${PWD}:/docs kube-agentic-networking/mkdocs build

.PHONY: build-docs-netlify
build-docs-netlify: api-ref-docs
	pip install -r hack/mkdocs/image/requirements.txt
	python -m mkdocs build

.PHONY: live-docs
live-docs: api-ref-docs
	docker build -t kube-agentic-networking/mkdocs hack/mkdocs/image
	docker run --rm -it -p 3000:3000 -v ${PWD}:/docs kube-agentic-networking/mkdocs

.PHONY: api-ref-docs
api-ref-docs:
	hack/mkdocs/generate.sh
