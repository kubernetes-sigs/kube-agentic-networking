# LangChain Agent with MCP Integration

This directory contains a LangChain agent that demonstrates how to integrate with the Multi-Server MCP Client to access tools and interact with a language model. The agent is built using `langchain`, `litellm`, and `streamlit`.

## Features

- **Streamlit Web Interface**: A user-friendly chat interface for interacting with the agent.
- **Multi-Server MCP Client**: Connects to multiple MCP servers to load and use tools.
- **LiteLLM Integration**: Uses `litellm` to connect to a Hugging Face model, which can be configured to use other language models.

## Cloud Build

The `cloudbuild.yaml` file is configured to build and push the Docker image using Google Cloud Build. It uses the `Makefile` to execute the build and push commands.

## Deployment

The `deployment.yaml` file contains the Kubernetes manifests for deploying the LangChain agent into a kubernetes cluster.

### Components

-   **ServiceAccount**: `adk-agent-sa` - A service account for the agent.
-   **Deployment**: `langchain-agent` - The deployment for the agent, which includes:
    -   An `initContainer` that configures `iptables` to redirect traffic to the Envoy sidecar.
    -   The LangChain agent container.
    -   An Envoy sidecar container that proxies requests to the MCP servers.
-   **Service**: `langchain-agent-svc` - A `LoadBalancer` service that exposes the LangChain agent and Envoy proxy.

