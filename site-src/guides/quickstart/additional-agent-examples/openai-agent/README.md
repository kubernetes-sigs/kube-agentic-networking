# OpenAI Agent with MCP Integration

This directory contains an agent that uses the OpenAI SDK to interact with a language model and dynamically loaded tools from MCP servers. The agent provides a chat interface using Gradio.

## Features

- **Gradio Web Interface**: A user-friendly chat interface for interacting with the agent.
- **OpenAI SDK**: Uses the OpenAI SDK to communicate with a language model.
- **Hugging Face Model**: Connects to a Hugging Face model through an OpenAI-compatible endpoint.
- **Multi-Server MCP Client**: Connects to multiple MCP servers to load and use tools.

## Cloud Build

The `cloudbuild.yaml` file is configured to build and push the Docker image using Google Cloud Build.

## Deployment

The `deployment.yaml` file contains the Kubernetes manifests for deploying the agent into a kubernetes cluster.

### Components

-   **ServiceAccount**: `adk-agent-sa` - A service account for the agent.
-   **Deployment**: `openai-agent` - The deployment for the agent, which includes:
    -   An `initContainer` that configures `iptables` to redirect traffic to the Envoy sidecar.
    -   The OpenAI agent container.
    -   An Envoy sidecar container that proxies requests to the MCP servers.
-   **Service**: `openai-agent-svc` - A `LoadBalancer` service that exposes the agent and Envoy proxy.

