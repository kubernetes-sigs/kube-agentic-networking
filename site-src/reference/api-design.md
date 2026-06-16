# API design

This document describes the design of the project's custom APIs and how they fit with the Gateway API. Note that this API is still in an early alpha state and could still change significantly.

## XBackend

An **XBackend** represents a backend that agents or tools call into—for example, an MCP server. It is namespaced and is referenced by HTTPRoute `BackendRef`s (and by XAccessPolicy targetRefs).

> [!NOTE:] 
> The project is in the process of moving to use the Gateway API's XBackend defined [here](https://github.com/kubernetes-sigs/gateway-api/blob/main/geps/gep-4894/index.md)

## XAccessPolicy

An **XAccessPolicy** is an authorization policy: it defines *who* can access *what* for the backends it targets. It targets Gateways or XBackends via `targetRefs` and contains rules that describe allowed (or denied) sources and optional authorization (e.g. which tools or methods).

## Relationship to Gateway API

The project is built on top of the Gateway API and works with Gateway resources (Gateway, GatewayClass, and route types such as HTTPRoute; GRPCRoute may be supported later). Route resources can reference XBackends via BackendRef. **XBackend** and **XAccessPolicy** are custom resources that extend these Gateway resources.

Proposals that introduce or change these APIs are listed under [Enhancements](../proposals/overview.md) on this site (source files live in `docs/proposals/` in the repository).
