# Development Guide

This document provides essential information for building, testing, and contributing to the `kube-agentic-networking` project.

## 1. Artifacts and Build Process

All container images in this project are built using `make`, which provides a consistent interface over `docker buildx`. The build logic is shared across all artifacts via `hack/build/Makefile.common.in`.

### Controller Image (`agentic-networking-controller`)

- **Role**: The core artifact of this project. It contains the Kubernetes controller that reconciles standard Gateway API and project-specific custom networking resources to serve xDS configurations to Envoy proxies.
- **Location**: [cmd/](../cmd/) and [pkg/](../pkg/)
- **How to Build**: `make build` from the repository root.

### Quickstart & Demonstration Artifacts

These images are provided solely for the [Quickstart Guide](../site-src/guides/quickstart/) to demonstrate the capabilities of the networking stack. They are not intended for production use.

- **MCP Server** (`quickstart-everything-mcp`)
  - **Location**: [site-src/guides/quickstart/mcpserver/](../site-src/guides/quickstart/mcpserver/)
  - **How to Build**: `cd site-src/guides/quickstart/mcpserver/ && make build`
- **ADK Agent** (`quickstart-adk-agent`)
  - **Location**: [site-src/guides/quickstart/adk-agent/](../site-src/guides/quickstart/adk-agent/)
  - **How to Build**: `cd site-src/guides/quickstart/adk-agent/ && make build`
  - **How to Reload in Kind (Local Development only)**: `make dev-reload-agent` from the repository root. This builds the ADK agent image, loads it into the local Kind cluster, and restarts the deployment.
- **Other Agent Examples**: Located under [site-src/guides/quickstart/additional-agent-examples/](../site-src/guides/quickstart/additional-agent-examples/). Each has its own `Makefile` following the same `make build` pattern.

## 2. Code Generation

The project uses several generators to maintain consistency between API definitions and implementation. **You must run these whenever you modify files in the `api/` directory.**

- `make generate`: The "catch-all" target that runs:
  - `manifests`: Generates CRD YAML files in `k8s/crds/`.
  - `deepcopy`: Generates `DeepCopy` methods for Go types.
  - `clientsets`: Generates typed clients, informers, and listers in `k8s/client/`.
  - `register`: Generates API registration code.

## 3. Local Verification

The project provides high-level rules for local verification:

- **`make test`**: Runs all unit, CEL, and CRD tests.
- **`make verify`**: Runs all verification scripts (linting, boilerplate checks, etc.) via [hack/verify-all.sh](../hack/verify-all.sh).
- **`make test-e2e`**: Runs the full End-to-End suite against a real `kind` cluster.
  - **Workflow**: It automatically creates a cluster, builds the controller, deploys it with necessary infrastructure (like the Agentic Identity CA), and runs tests from [tests/e2e/](../tests/e2e/).
  - **Debugging**: If the E2E tests fail, the underlying script ([dev/ci/run-e2e.sh](./ci/run-e2e.sh)) will automatically dump cluster-wide resource states and logs to the console for troubleshooting.

## 4. Continuous Integration (CI)

The project uses **Prow** and **Google Cloud Build (GCB)** for automated verification and deployment. You can check the current status of all jobs at [prow.k8s.io](https://prow.k8s.io/?repo=kubernetes-sigs%2Fkube-agentic-networking) and our [Test Grid](https://testgrid.k8s.io/sig-network-kube-agentic-networking).

### PR Verification
Every Pull Request triggers a suite of [Prow jobs](https://github.com/kubernetes/test-infra/blob/master/config/jobs/kubernetes-sigs/kube-agentic-networking/kube-agentic-networking-config.yaml) to ensure code quality:
- **Linting & Boilerplate**: Automated checks via `make verify`.
- **Testing**: Execution of `make test`.
- **E2E**: Full system validation via `make test-e2e`.

### Image Pushing (Remote Build)
When a PR is merged or a push occurs on `main`, a [staging Prow job](https://github.com/kubernetes/test-infra/blob/master/config/jobs/image-pushing/k8s-staging-agentic-net.yaml) is triggered:
1. Prow executes the `cloudbuild.yaml` configuration.
2. GCB runs `make push`, which performs a multi-platform build (`linux/amd64`, `linux/arm64`) and pushes the resulting images to [the staging registry](https://console.cloud.google.com/artifacts/docker/k8s-staging-images/us-central1/agentic-net).

### Image Promotion
Official images are promoted from staging to `registry.k8s.io/agentic-net/` by following the [Kubernetes Image Promoter process](https://github.com/kubernetes/k8s.io/tree/main/registry.k8s.io#creating-image-promoter-manifests).

At a high level, this involves:
1. Ensuring your image is successfully built and pushed to the [staging registry](https://console.cloud.google.com/artifacts/docker/k8s-staging-images/us-central1/agentic-net) by the CI process.
2. Creating a Pull Request to the [kubernetes/k8s.io](https://github.com/kubernetes/k8s.io) repository to update [images.yaml](https://github.com/kubernetes/k8s.io/blob/main/registry.k8s.io/images/k8s-staging-agentic-net/images.yaml) with the new image tags and their corresponding digests.
3. Once the PR is merged, the images are automatically promoted to the production registry by the image promoter tool.
