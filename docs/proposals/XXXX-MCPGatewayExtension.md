Date: 9th June 2026<br/>
Authors: david-martin<br/>
Status: Provisional<br/>

# MCPGatewayExtension

## Summary

MCP-aware features like `XAccessPolicy` tool authorization require the Gateway to parse MCP protocol messages. There is no standard mechanism to enable this. This proposal introduces `MCPGatewayExtension`, a CRD that targets a Gateway listener and signals the implementation to enable MCP request body parsing on that listener.

## Non-Goals

- Defining what MCP parsing means at the implementation level (buffering, streaming, external processing).
- Authorization or access control policy (`XAccessPolicy`).
- Backend registration or routing (`XBackend`, `HTTPRoute`).
- Locking down which fields are extracted from the request body. The set of extracted information will evolve alongside the MCP specification.
- Implementation-specific concerns: observability, auth, rate limiting.

## Use Cases & Motivation

A platform operator deploys a Gateway and wants `XAccessPolicy` rules to apply to MCP tool calls. Without a signal to the Gateway that MCP parsing should be active on a listener, MCP traffic is opaque HTTP and tool-level policies have no effect.

## Design

### CRD

`MCPGatewayExtension` uses the Gateway API policy attachment pattern. `sectionName` targets a specific listener. When omitted, parsing is enabled on all listeners.

```yaml
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: MCPGatewayExtension
metadata:
  name: enable-mcp
  namespace: gateway-system
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: prod-gateway
    sectionName: mcp-listener
```

```go
type MCPGatewayExtensionSpec struct {
    // TargetRef identifies the Gateway (and optionally a specific listener)
    // on which to enable MCP parsing.
    // +required
    TargetRef gwapiv1.LocalPolicyTargetReferenceWithSectionName `json:"targetRef"`
}
```

What happens when a listener is targeted is implementation-specific. In the Istio/Envoy case, this could mean configuring an ext-proc filter for the listener's port. The outcome is that the Gateway can parse MCP JSON-RPC request bodies and surface extracted information (e.g., as headers or dynamic metadata) for routing, access control, or observability.

### Why Listener-Level Targeting?

Gateways typically serve multiple listeners: HTTPS on 443, admin endpoints, other. Parsing request bodies on listeners that don't carry MCP traffic adds overhead for no benefit. `sectionName` provides per-listener granularity using the same mechanism Gateway API policies already use.

#### Alternatives

**Gateway-level only (no per-listener targeting):** Simpler, but forces operators to either dedicate entire Gateways to MCP traffic or accept body parsing overhead on all listeners. Many deployments will share a Gateway across MCP and non-MCP traffic.

**Per-route targeting (HTTPRoute):** Body parsing is typically configured at the infrastructure layer (e.g., Envoy filter chains operate at the listener/port level). Per-route targeting would also couple parsing configuration to routing configuration, complicating lifecycle management.

### What Gets Extracted

The MCP specification [release candidate (2026-07-28)](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/) requires `Mcp-Method` and `Mcp-Name` headers on every Streamable HTTP request, mirroring information from the JSON-RPC body. This allows some method-level and tool-level policy enforcement from headers alone.

While the new spec propagates through MCP client and server implementations, there will be a need to continue parsing the MCP method and tool name from the request body. In addition, there may be other request body information that implementations need to extract: tool call arguments, client metadata in `_meta`, or fields introduced by future spec revisions. What to extract and how to surface it is deliberately left open. `MCPGatewayExtension` signals that the Gateway *may* parse the body; what it does with the contents is implementation-defined.

### Status

The resource carries its own status conditions (`Accepted`, `Programmed`), independent of the Gateway's status.

### Constraints

- One `MCPGatewayExtension` per listener. Conflicts are rejected and reported in status.
- Implementations MUST NOT enforce MCP-aware policies unless parsing has been explicitly enabled.

## Extensibility

The spec is minimal. Implementations may need buffer sizes, timeouts, session storage, TLS configuration. These can be added as optional fields without touching the Gateway resource, which is the main advantage of a separate CRD over modifying the Gateway spec directly.

## Support Requirements

An implementation that supports MCP-aware features MUST support `MCPGatewayExtension` or an equivalent mechanism that provides a clear, observable signal that MCP parsing is active on a given Gateway or listener.
