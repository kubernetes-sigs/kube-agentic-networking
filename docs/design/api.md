# API design

This document describes the design of the project’s custom APIs and how they fit with the Gateway API.

## Overview

The project extends the [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) with two main custom resources:

- **XBackend** — describes a backend (e.g. an MCP server) that HTTPRoutes can reference via BackendRef.
- **XAccessPolicy** — describes who can access what: it targets one or more XBackends and defines rules (sources and authorization) that the data plane enforces.

Type definitions and generated code live under [`api/`](../../api/) and [`k8s/`](../../k8s/). For a short “what lives where” guide, see [repo_structure.md](repo_structure.md).

## XBackend

An **XBackend** represents a backend that agents or tools call into—for example, an MCP server. It is namespaced and is referenced by HTTPRoute `BackendRef`s (and by XAccessPolicy targetRefs). The controller and translator use XBackends to configure the data plane (e.g. clusters, RBAC) so that traffic to that backend is correctly routed and authorized.

Key design points:

- One XBackend per logical backend (e.g. one MCP server).
- Backend identity can be specified by Kubernetes Service name (in-cluster) or by hostname (external).
- The data plane uses XBackend to know where to send traffic and how to secure it (e.g. mTLS, path).

## XAccessPolicy

An **XAccessPolicy** is an authorization policy: it defines *who* can access *what* for the backends it targets. It targets XBackends via `targetRefs` and contains rules that describe allowed (or denied) sources and optional authorization (e.g. which tools or methods). The translator turns XAccessPolicy into data-plane configuration (e.g. Envoy RBAC) so that only allowed callers can reach the targeted backends.

Key design points:

- Targets one or more XBackends via `targetRefs`.
- Rules combine a source (e.g. service account, namespace) with optional authorization (e.g. allowed tools/methods).
- If no XAccessPolicy targets an XBackend, the data plane does not enforce RBAC for that backend (allow-all behaviour). If at least one XAccessPolicy targets it, the translated rules are enforced.

## Relationship to Gateway API

The project is built on top of the Gateway API and works with Gateway resources (Gateway, GatewayClass, and route types such as HTTPRoute; GRPCRoute may be supported later). Route resources can reference XBackends via BackendRef. **XBackend** and **XAccessPolicy** are custom resources that work with these Gateway resources and the data plane: BackendRef → XBackend, and XAccessPolicy → RBAC (or equivalent) for those backends.

Proposals that introduce or change these APIs are under [docs/proposals/](../proposals/).
