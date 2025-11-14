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
