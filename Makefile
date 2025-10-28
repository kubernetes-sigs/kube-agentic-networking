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

# Print the help menu.
.PHONY: help
help:
	@grep -hE '^[ a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-17s\033[0m %s\n", $$1, $$2}'

.PHONY: all
all: vet fmt verify test build;$(info $(M)...Begin to test, verify and build this project.) @ ## Test, verify and build this project.

# Run go fmt against code
.PHONY: fmt
fmt: ;$(info $(M)...Begin to run go fmt against code.)  @ ## Run go fmt against code.
	gofmt -w ./pkg

# Run go vet against code
.PHONY: vet
vet: ;$(info $(M)...Begin to run go vet against code.)  @ ## Run go vet against code.
	go vet ./pkg/...

# Run go test against code
.PHONY: test
test: vet;$(info $(M)...Begin to run tests.)  @ ## Run tests.
	go test -race -cover ./pkg/...


# Run static analysis.
.PHONY: verify
verify:
	hack/verify-all.sh -v

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

##@Docs

.PHONY: build-docs
build-docs:
		docker build --pull -t kube-agentic-net/mkdocs hack/mkdocs/image
			docker run --rm -v ${PWD}:/docs kube-agentic-net/mkdocs build

.PHONY: build-docs-netlify
build-docs-netlify:
		pip install -r hack/mkdocs/image/requirements.txt
			mkdocs build

.PHONY: live-docs
live-docs:
		docker build -t kube-agentic-net/mkdocs hack/mkdocs/image
			docker run --rm -it -p 3000:3000 -v ${PWD}:/docs kube-agentic-net/mkdocs
