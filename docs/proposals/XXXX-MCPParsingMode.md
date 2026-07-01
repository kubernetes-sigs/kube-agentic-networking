Date: 9th June 2026<br/>
Authors: david-martin<br/>
Status: Provisional<br/>

# Enabling MCP Parsing on a Gateway

A Gateway implementation must parse MCP protocol messages before it can enforce MCP-aware policies such as `XAccessPolicy` tool authorization rules. Today, there is no standard mechanism to signal that a Gateway should treat traffic on a listener as MCP and begin parsing JSON-RPC messages.

This proposal introduces an API for enabling MCP parsing on a Gateway. It is a prerequisite for any MCP-aware feature — without MCP parsing enabled, the Gateway treats MCP traffic as opaque HTTP and cannot inspect or enforce tool-level policies.

Two approaches are presented for consideration.

## Non-Goals

- Defining what MCP parsing means at the implementation level (message buffering, streaming, SSE handling). These are implementation concerns.
- Defining authorization or access control policy. That is the domain of `XAccessPolicy`.
- Backend registration or routing. That is the domain of `XBackend` and `HTTPRoute`.

## Use Cases & Motivation

### Personas

- **Gateway implementer**: Needs a clear signal to activate MCP parsing logic in the data plane.
- **Platform operator**: Needs a way to designate which Gateways (or listeners) handle MCP traffic.

### User Journey

A platform operator deploys a Gateway and wants to enforce `XAccessPolicy` rules on MCP tool calls. Today, there is no way to tell the Gateway to parse MCP messages. The operator needs to:

1. Deploy a Gateway with one or more listeners.
2. Signal that MCP parsing should be enabled on that Gateway (or a specific listener).
3. Attach `XAccessPolicy` resources that reference MCP methods like `tools/call`.

Without step 2, the Gateway cannot inspect MCP payloads and `XAccessPolicy` rules that reference MCP methods have no effect.

## Approach A: MCPGatewayExtension (Policy Attachment)

A new CRD, `MCPGatewayExtension`, that targets a Gateway using the standard Gateway API policy attachment pattern.

### Example

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

### API

```go
type MCPGatewayExtensionSpec struct {
    // TargetRef identifies the Gateway (and optionally a specific listener)
    // on which to enable MCP parsing.
    // +required
    TargetRef gwapiv1.LocalPolicyTargetReferenceWithSectionName `json:"targetRef"`
}
```

When `sectionName` is specified, MCP parsing is enabled only on that listener. When omitted, MCP parsing is enabled on all listeners of the targeted Gateway.

### Pros

- Follows the established Gateway API policy attachment pattern. Gateway implementers already understand `targetRef`.
- Decoupled from the Gateway resource itself — no changes to upstream Gateway API types.
- Can be extended with implementation-specific fields (e.g., buffer sizes, timeouts, session storage) without modifying the Gateway spec.
- Supports cross-namespace targeting via `ReferenceGrant`, matching existing Gateway API conventions.
- Per-listener granularity via `sectionName`.
- Can carry status conditions to report whether MCP parsing is active, making troubleshooting straightforward.

### Cons

- Introduces a new CRD that must be installed and understood by operators.
- Indirection: the operator must look at both the Gateway and the MCPGatewayExtension to understand the full configuration.
- Lifecycle coupling: the MCPGatewayExtension must be reconciled alongside the Gateway. Ordering and dependency between the two resources adds implementation complexity.

## Approach B: Gateway `mcpMode` Field

A new top-level field on the Gateway `spec`, `mcpMode`, as an enum that defaults to `Disabled`.

### Example

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: prod-gateway
  namespace: gateway-system
spec:
  mcpMode: Enabled
  gatewayClassName: example-gc
  listeners:
    - name: mcp-listener
      protocol: HTTP
      port: 8080
```

### API

```go
// MCPMode indicates whether the Gateway should parse MCP protocol messages.
// +kubebuilder:validation:Enum=Enabled;Disabled
// +kubebuilder:default=Disabled
type MCPMode string

const (
    MCPModeEnabled  MCPMode = "Enabled"
    MCPModeDisabled MCPMode = "Disabled"
)
```

This would be added to the Gateway spec, either upstream in the Gateway API or via an extension mechanism (e.g., `parametersRef`, annotations, or a future Gateway API extension point).

When set to `Enabled`, the Gateway activates MCP parsing on all its listeners.

### Pros

- Single resource: the operator looks at one object to understand the full Gateway configuration.
- Simple mental model: "this Gateway does MCP" is expressed in one field.
- No new CRD to install or manage.
- No lifecycle ordering concerns — the mode is part of the Gateway itself.

### Cons

- Requires modifying the Gateway spec. If done upstream, this depends on Gateway API maintainers accepting MCP as a first-class concern. If done via `parametersRef` or annotations, it becomes implementation-specific and loses portability.
- No per-listener granularity without additional complexity (e.g., a per-listener field or a list of listener names).
- Cannot carry its own status conditions. MCP parsing readiness would need to be reported in the Gateway's existing status, which may not have a natural place for it.
- Harder to extend. Adding MCP-specific configuration (buffer sizes, timeouts) to the Gateway spec pollutes a general-purpose resource.
- Binary toggle does not accommodate future modes (e.g., `Inspect` vs `Enforce`, or protocol variants).

## Comparison

| Concern | Approach A (MCPGatewayExtension) | Approach B (mcpMode field) |
|---|---|---|
| New CRD required | Yes | No |
| Per-listener granularity | Yes, via `sectionName` | No (applies to all listeners) |
| Extensibility | High — own spec for MCP-specific config | Low — limited to a single enum |
| Gateway API compatibility | No upstream changes needed | Requires upstream change or implementation-specific mechanism |
| Operator complexity | Two resources to manage | One resource |
| Status reporting | Own status conditions | Must share Gateway status |
| Policy attachment pattern | Standard | N/A |

## Support Requirements

An implementation that supports MCP-aware features (e.g., `XAccessPolicy` with MCP method rules) MUST provide a mechanism to enable MCP parsing on a Gateway.

An implementation MUST support at least one of the approaches described in this proposal, or an equivalent mechanism that satisfies the same requirement: a clear, observable signal that MCP parsing is active on a given Gateway or listener.

An implementation MUST NOT enforce MCP-aware policies on traffic unless MCP parsing has been explicitly enabled.
