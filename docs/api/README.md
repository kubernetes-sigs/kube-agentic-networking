# APIs

This document gives a high-level overview of the project’s APIs and where they are defined.

## API types (Go)

**Location:** [`api/v0alpha0/`](../../api/v0alpha0/)

- **XBackend** (`backend_types.go`) — Describes a backend (e.g. MCP server) with `spec.mcp.serviceName` or `spec.mcp.hostname`, port, and path.
- **XAccessPolicy** (`accesspolicy_types.go`) — Authorization policy: who can access what (e.g. targetRefs to XBackends, rules with source and authorization).

After changing types under `api/`, run **`make generate`** to regenerate deepcopy, register, and client code.

## CRDs (Kubernetes manifests)

**Location:** [`k8s/crds/`](../../k8s/crds/)

- `agentic.prototype.x-k8s.io_xbackends.yaml`
- `agentic.prototype.x-k8s.io_xaccesspolicies.yaml`

These are the manifests installed in a cluster. They are generated from the Go types in `api/`.

## Generated clients

**Location:** [`k8s/client/`](../../k8s/client/)

Clientsets, listers, and informers for the API types (used by the controller and translator). Regenerated via the project’s codegen (e.g. `make generate`).

## Relationship to Gateway API

This project extends the [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/). It uses:

- **Gateway**, **GatewayClass**, **HTTPRoute** from the Gateway API.
- **XBackend** and **XAccessPolicy** as custom resources that integrate with HTTPRoute (e.g. BackendRef to XBackend, policies that target XBackends).

Proposals that introduce or change APIs are under [`docs/proposals/`](../proposals/).
