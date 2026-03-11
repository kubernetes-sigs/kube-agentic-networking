# ADK Agent with MCP Integration

This directory contains a custom-built, lightweight agent demonstrating a direct integration with the Multi-Server MCP Client.
Users can use this agent to interact with a language model and execute tools exposed by the MCP servers.

## Features

- **FastAPI Web Interface**: Serves a user-friendly web interface for interacting with the agent using FastAPI and Uvicorn.
- **Multi-Server MCP Client**: Connects to multiple MCP servers to dynamically load and use tools.

## Cloud Build

The `cloudbuild.yaml` file is configured to build and push the Docker image using Google Cloud Build.

## Deployment

The `deployment.yaml` file contains the Kubernetes manifests for deploying the agent into a Kubernetes cluster.

### Components

- **ServiceAccount**: `adk-agent-sa` - A service account for the agent.
- **Deployment**: `adk-agent` - The deployment for the agent, which includes:
    - An `initContainer` (e.g., `proxy-init`) that configures `iptables` to redirect traffic to the Envoy sidecar.
    - The ADK agent container.
    - An Envoy sidecar container that proxies requests to the MCP servers.
- **Service**: `adk-agent-svc` - A service that exposes the agent web interface at port 8080 and Envoy proxy at port 10001.
