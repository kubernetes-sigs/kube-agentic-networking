# Build the agentic-net-controller binary
# The image will be pushed to https://console.cloud.google.com/artifacts/docker/k8s-staging-images/us-central1/agentic-net.

# This will be overridden at build time by makefile to .go-version
ARG GO_VERSION=1.25.5
FROM golang:${GO_VERSION} AS builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the entire project directory
COPY . .

# Build
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o agentic-net-controller cmd/agentic-net-controller/main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/agentic-net-controller .
USER 65532:65532

ENTRYPOINT ["/agentic-net-controller"]
