# Gemini Agent Guidelines: Kube Agentic Networking

This document provides essential context for working on the Kube Agentic Networking project.

## 1. Project Overview

This project is a Kubernetes controller built with `client-go`. Its primary function is to reconcile Kubernetes networking resources (both standard Gateway API and custom types) into dynamic Envoy proxy configurations, which are then served via an xDS server. The ultimate goal is to provide a declarative, high-level policy engine for controlling network access for in-cluster AI agents.

## 2. Core Design Principles

-   **Gateway-Centric Reconciliation**: The `gateway.networking.k8s.io/Gateway` resource is the root of the reconciliation process. All configuration is anchored to a `Gateway`.
-   **Upstream Reconciliation**: Changes to child resources (like `HTTPRoute`, `XAccessPolicy`) trigger a reconciliation of the parent `Gateway` they are associated with.
-   **Isolated Data Plane**: A dedicated Envoy proxy (`Deployment` and `Service`) is provisioned and managed for each `Gateway` resource, ensuring network isolation.

## 3. Code and Repository Structure

-   `api/`: Defines the Go types for the Custom Resource Definitions (`XBackend`, `XAccessPolicy`).
-   `cmd/`: Main application entrypoint.
-   `pkg/`: Contains all core controller and translator logic.
    -   `pkg/controller`: This is the core control loop. It contains the informers and event handlers that watch for resource changes and enqueue `Gateway` resources for reconciliation.
    -   `pkg/translator`: This package is responsible for the stateless, one-way translation of Kubernetes API objects into Envoy xDS resource configurations (Listeners, Clusters, Routes, etc.).
    -   `pkg/infra`: This handles the data plane lifecycle.
        -   `infra/envoy`: Manages the creation, update, and deletion of the Kubernetes resources that constitute an Envoy proxy (Deployment, Service, ConfigMap).
        -   `infra/xds`: Implements the gRPC server that serves the generated configurations to the Envoy proxies.
-   `k8s/`: Stores Kubernetes manifests for deployment, including CRDs and controller RBAC/Deployment YAML.
-   `docs/`: Project design documents and user-facing guides.

## 4. Development and Testing Workflow

The `Makefile` is the primary tool for development tasks:

-   **Run Tests**: `make test`
-   **Generate Code**: `make generate` (after modifying API types)
