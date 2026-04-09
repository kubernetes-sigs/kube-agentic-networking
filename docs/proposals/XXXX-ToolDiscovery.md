# Tool Discovery for KAN

Date: 16th March 2026<br/>
Authors: @rubambiza, @evaline-ju, @david-martin, @guicassolato<br/>
Status: Provisional<br/>

> [!CAUTION]
> This API is in a provisional state. It is subject to change and should not be
> implemented without first consulting the maintainers of the project.

## Summary

KAN has no mechanism to discover what tools an MCP backend exposes. Operators
must manually enumerate tool names in `XAccessPolicy` rules, and there is no
feedback loop when tools are added, removed, or misconfigured on backends.

This proposal adds optional, opt-in tool discovery to KAN: a controller that
connects to MCP backends, calls `tools/list`, validates the results, and
surfaces discovered tools in `XBackend.status`. This enables policy validation
against real backend state, operator visibility via `kubectl`, and a foundation
for future capabilities like response filtering. Discovery is advisory (i.e.,
it enhances observability but does not affect policy enforcement). Backends
without discovery enabled continue to work exactly as they do today.

## Non-Goals

- **`tools/list` response filtering.** Filtering the `tools/list` response
  based on caller identity (so agents only see tools they're authorized to call)
  is a natural next step but would require a separate proposal.
- **Tool prefixing / federation.** Disambiguating tools with the same name
  across multiple backends (e.g., via prefix namespacing) is out of scope.
- **Full tool schema storage in CRD status.** Storing `inputSchema` and
  `outputSchema` in `XBackend.status` risks etcd bloat. Discovery validates
  schemas but does not persist them.

## Motivation

### The Gap

KAN's `XBackend` CRD is purely a routing target. It knows an MCP server's
address and port, but nothing about what tools that server exposes:

```go
type MCPBackend struct {
    ServiceName *string `json:"serviceName,omitempty"`
    Hostname    *string `json:"hostname,omitempty"`
    Port        int32   `json:"port"`
    Path        string  `json:"path,omitempty"`
}
// No status.discoveredTools, no status.tools[].
```

This creates three concrete problems:

**1. Stale access policies.** `XAccessPolicy` rules require operators to
manually list tool names. If a backend adds, renames, or removes a tool, the
policy becomes stale with no warning. The ToolAuthAPI proposal (0008) explicitly
acknowledges this as a TODO.

**2. No operator visibility.** There is no way to inspect what tools a backend
exposes without directly calling `tools/list` on the backend. `kubectl get
xbackend` tells you nothing about the backend's capabilities.

**3. Invalid schemas propagate silently.** When a backend MCP server exposes
tools with invalid JSON schemas, the problem is invisible until an agent tries
to use the tools. For example, [Kuadrant/mcp-gateway issue #662](https://github.com/Kuadrant/mcp-gateway/issues/662) documents a case
where a backend with an invalid `inputSchema` caused an agent to fail with a 400
error (`"JSON schema is invalid. It must match JSON Schema draft 2020-12"`).
Without validation at the discovery layer, broken backends silently poison the
system.

### Personas

**Platform Engineer** — Configures `XBackend` and `XAccessPolicy` resources.
Needs to know what tools each backend exposes to write correct policies, and
wants warnings when policies reference tools that don't exist.

**Tool Developer** — Deploys MCP servers behind KAN. Wants confidence that
newly added or renamed tools are visible to the platform without manual CRD
updates.

### User Journeys

**CUJ 1: Operator discovers tools on a new backend.**
The platform engineer creates an `XBackend` pointing at an MCP server. Within
the sync interval, `kubectl get xbackend my-backend -o yaml` shows
`status.discoveredTools` populated with the backend's tools. No manual
enumeration required.

**CUJ 2: Operator writes a valid access policy.**
The platform engineer writes an `XAccessPolicy` referencing tool names. The
controller validates the tool names against `XBackend.status.discoveredTools`
and sets a Warning condition on the policy if any tool name doesn't match.

**CUJ 3: Backend adds a new tool.**
A tool developer deploys a new version of their MCP server with an additional
tool. The discovery controller detects the change (via `tools/list_changed`
notification or the next poll) and updates `XBackend.status`. Existing
`XAccessPolicy` resources that don't include the new tool are unaffected; the
operator can add it when ready.

**CUJ 4: Backend exposes an invalid tool.**
A tool developer deploys an MCP server with a tool whose `inputSchema` is
invalid JSON Schema. The discovery controller validates the schema, rejects the
tool, and emits a Warning event on the `XBackend`. The invalid tool does not
appear in `status.discoveredTools`, preventing it from being referenced in
policies or reaching agents.

## Context

Three recent developments inform this proposal's design:

**XBackend is in flux.** KAN is actively reconsidering XBackend's shape to
align with the AI Gateway WG's Backend resource ([gateway-api PR #4488](https://github.com/kubernetes-sigs/gateway-api/pull/4488)). [Issue
#161](https://github.com/kubernetes-sigs/kube-agentic-networking/issues/161) tracks whether to drop `Service` as a target type; [issue #162](https://github.com/kubernetes-sigs/kube-agentic-networking/issues/162) questions
whether `path` belongs on XBackend or in protocol-specific options. This
proposal's design is resilient to these changes: it extends `XBackend.status`
(observed state), not `XBackend.spec`, so it works regardless of how the spec
evolves.

**MCP 2025-11-25 expanded the tool data model.** The MCP spec now includes
`title` (human-readable display name), `outputSchema`, `icons`, pagination on
`tools/list` via cursor, and mandatory JSON Schema 2020-12 validation for
`inputSchema`. The `tools/list_changed` notification (available since
2025-03-26) was not incorporated in the original proposal.

**Kuadrant/mcp-gateway validates the approach.** Three developments in the MCP
Gateway directly inform this proposal: `tools/list_changed` support ([PR #329](https://github.com/Kuadrant/mcp-gateway/pull/329))
validates the hybrid polling + notification approach; [issue #662](https://github.com/Kuadrant/mcp-gateway/issues/662) (invalid
schemas breaking downstream agents) motivates schema validation at the discovery
layer; and the `MCPServerRegistration` CRD's evolution toward richer backend
metadata ([PR #500](https://github.com/Kuadrant/mcp-gateway/pull/500)) confirms that a count-only status is insufficient for policy
validation.

## API

### XBackend Status Extension

```go
type BackendStatus struct {
    // Conditions describe the current state of the XBackend.
    // +optional
    // +listType=map
    // +listMapKey=type
    Conditions []metav1.Condition `json:"conditions,omitempty"`

    // DiscoveredTools lists the tools discovered on this backend via
    // MCP tools/list. Only tools with valid schemas are included.
    // +optional
    // +listType=map
    // +listMapKey=name
    DiscoveredTools []DiscoveredTool `json:"discoveredTools,omitempty"`

    // LastDiscoveryTime is the timestamp of the last successful
    // tools/list call to this backend.
    // +optional
    LastDiscoveryTime *metav1.Time `json:"lastDiscoveryTime,omitempty"`
}

type DiscoveredTool struct {
    // Name is the unique identifier for the tool, as returned by
    // the MCP server's tools/list response.
    // +required
    Name string `json:"name"`

    // Title is the human-readable display name for the tool.
    // Corresponds to the "title" field in MCP 2025-11-25.
    // +optional
    Title string `json:"title,omitempty"`

    // Description is a human-readable description of the tool's
    // functionality.
    // +optional
    Description string `json:"description,omitempty"`
}
```

### XBackend Status Conditions

The discovery controller sets the following conditions on `XBackend`:

| Type | Status | Reason | Meaning |
|------|--------|--------|---------|
| `ToolsDiscovered` | `True` | `DiscoverySucceeded` | tools/list succeeded, all tools valid |
| `ToolsDiscovered` | `True` | `PartiallyValid` | tools/list succeeded, but some tools had invalid schemas and were excluded |
| `ToolsDiscovered` | `False` | `DiscoveryFailed` | tools/list call itself failed (backend unreachable, protocol error) |

### Complete Example

```yaml
apiVersion: agentic.prototype.x-k8s.io/v0alpha0
kind: XBackend
metadata:
  name: weather-service
  namespace: default
  annotations:
    agentic.prototype.x-k8s.io/enable-discovery: "true"
spec:
  mcp:
    serviceName: weather-mcp
    port: 8080
    path: /mcp
status:
  conditions:
    - type: ToolsDiscovered
      status: "True"
      reason: DiscoverySucceeded
      message: "Discovered 2 tools"
      lastTransitionTime: "2026-03-16T10:30:00Z"
  discoveredTools:
    - name: get_forecast
      title: "Weather Forecast"
      description: "Get weather forecast for a location"
    - name: get_alerts
      title: "Weather Alerts"
      description: "Get active weather alerts for a region"
  lastDiscoveryTime: "2026-03-16T10:30:00Z"
```

An `XAccessPolicy` referencing a non-existent tool receives a Warning:

```yaml
apiVersion: agentic.prototype.x-k8s.io/v0alpha0
kind: XAccessPolicy
metadata:
  name: agent-weather-access
  namespace: default
spec:
  targetRefs:
    - group: agentic.prototype.x-k8s.io
      kind: XBackend
      name: weather-service
  rules:
    - name: allow-forecast
      source:
        type: ServiceAccount
        serviceAccount:
          name: my-agent
          namespace: default
      authorization:
        type: InlineTools
        tools:
          - "get_forecast"
          - "get_humidity"  # Not discovered on backend
status:
  ancestors:
    - ancestorRef:
        group: agentic.prototype.x-k8s.io
        kind: XBackend
        name: weather-service
      controllerName: agentic.prototype.x-k8s.io/controller
      conditions:
        - type: Accepted
          status: "True"
          reason: "Accepted"
          message: "Policy accepted; unverified tools: get_humidity (not found in discovered tools for XBackend 'weather-service')"
          lastTransitionTime: "2026-03-16T10:31:00Z"
```

## Implementation

### Discovery Controller

The discovery logic lives in `pkg/discovery/` within the existing
`agentic-net-controller` binary as a new reconciler. Discovery is opt-in:
the controller only processes XBackend resources that carry the
`agentic.prototype.x-k8s.io/enable-discovery: "true"` annotation. Backends
without this annotation are ignored, incurring zero overhead. The discovery
controller can also be disabled entirely via a controller flag
(`--enable-discovery=false`).

For opted-in backends, it:

1. **Watches** XBackend resources with the discovery annotation.
2. **Connects** to each backend's MCP endpoint using the `mcp-go` client
   library (`github.com/mark3labs/mcp-go`).
3. **Calls** `tools/list`, handling pagination via cursor for backends with
   many tools.
4. **Validates** each tool's `inputSchema` against JSON Schema draft 2020-12.
   Tools with invalid schemas are rejected and logged as Warning events on the
   XBackend resource.
5. **Updates** `XBackend.status.discoveredTools[]` with validated tools only.
6. **Listens** for `tools/list_changed` notifications on backends that declare
   the `listChanged` capability, triggering immediate re-discovery.
7. **Falls back to polling** (configurable interval, default 30s) for backends
   that don't support `list_changed`, and as a periodic consistency check.
8. **Detects drift** by diffing new vs. old tool sets and emits Kubernetes
   Events when tools are added, removed, or fail validation.

### AccessPolicy Validation

The existing AccessPolicy reconciler is extended to cross-reference
`rules[].authorization.tools[]` against `XBackend.status.discoveredTools`:

- If a tool name doesn't match, surface the unverified tool names in the
  `Accepted` condition's `message` field on the relevant ancestor entry
  (not rejection — the tool may not be discovered yet). This follows
  Gateway API convention of using standard condition types rather than
  introducing domain-specific ones.
- Validation runs on both AccessPolicy changes and XBackend status changes,
  so stale policies are detected when a backend removes a tool.

### Phasing

**Phase 1: In-cluster discovery (plain HTTP).** XBackend status extension,
discovery controller, schema validation, `list_changed` support, drift
detection. The controller connects to backends using the service name and port
from `XBackend.spec.mcp` over plain HTTP. This is sufficient for in-cluster
backends where trust is assumed. In mesh environments (e.g., Istio sidecar on
the controller pod), mTLS is handled transparently at the infrastructure layer,
so the plain HTTP implementation covers that case without extra work.

Backends that require authentication for `tools/list` will fail gracefully:
the XBackend receives a `ToolsDiscovered: False` condition with reason
`DiscoveryFailed`, and AccessPolicy enforcement continues unaffected. Discovery
is advisory — it does not gate the data plane. The operator sees an early
signal that the backend is unreachable to the control plane, but runtime tool
calls proceed normally as long as the agent's own credentials are valid.

**Phase 2: External backends (TLS and authentication).** Extends the discovery
controller to connect to backends outside the cluster, requiring TLS and
potentially a credential reference for `tools/list` calls. The exact mechanism
(e.g., a `credentialRef` on XBackend) is deferred pending stabilization of the
Backend spec between KAN and the AI Gateway WG.

**Phase 3: Policy validation.** AccessPolicy cross-referencing against
discovered tools. When an XBackend has `ToolsDiscovered: False` (discovery
failed or not yet attempted), any AccessPolicy targeting that backend includes
a note in the `Accepted` condition message indicating which target backends
had no discovery data available (e.g., "tools not verified against XBackend
'weather-service': discovery unavailable"). This ensures operators have
visibility without blocking policy acceptance.

### Alternative: Separate Discovery Controller

The discovery logic is encapsulated in `pkg/discovery/`, making extraction into
a standalone `agentic-net-discovery` binary straightforward if the community
prefers separation of concerns. This pattern, a dedicated controller whose
sole job is to periodically fetch remote capabilities and cache them in CRD
status, is used by the kagenti-operator's AgentCard controller, which fetches
agent capability cards from `/.well-known/agent.json` endpoints and writes them
to `AgentCard.status`. The benefit is fault isolation: a bug or crash in the
discovery loop doesn't affect the main proxy management controller. The
embedded approach is recommended to start because it avoids an additional
deployment and simplifies RBAC.

## Prior Art

### Kuadrant/mcp-gateway MCPManager

The MCP Gateway's broker connects to upstream MCP servers and calls
`tools/list` on a reconciliation loop, maintaining an in-memory registry. It
supports `tools/list_changed` for reactive re-discovery ([PR #329](https://github.com/Kuadrant/mcp-gateway/pull/329)) and prefixes
tool names for federation. Its `MCPServerRegistration` CRD status stores only a
tool count — sufficient for the gateway's needs but too minimal for KAN's
policy validation use case.

- *Pro:* Production-tested discovery loop with list_changed support.
- *Pro:* Schema validation gap ([issue #662](https://github.com/Kuadrant/mcp-gateway/issues/662)) validates our design choice to
  validate at the discovery layer.
- *Con:* CRD status (count only) is insufficient for policy validation.
- *Con:* In-memory tool registry doesn't surface tools to kubectl or other
  controllers.

### [kagenti-operator](https://github.com/kagenti/kagenti-operator) AgentCard Controller

The kagenti-operator's AgentCard controller periodically fetches agent
capability cards from `/.well-known/agent.json` endpoints and caches them in
`AgentCard.status.card`. It detects drift via SHA-256 hashing and runs as a
dedicated controller separate from other reconcilers.

- *Pro:* Validates the pattern of fetching remote capabilities into CRD status.
- *Pro:* Separate controller provides fault isolation.
- *Con:* Separate deployment adds operational complexity.

## Alternatives Considered

### Discovery in the data plane (Envoy calls tools/list)

Envoy could call `tools/list` at request time instead of a controller caching
the results. This would always be fresh but adds latency to every `tools/list`
request, provides no CRD visibility, and makes offline policy validation
impossible. The controller-side approach also enables schema validation before
tools reach agents.

### Full tool metadata in XBackend.status

Storing `inputSchema`, `outputSchema`, and other fields would provide a
complete picture but risks `etcd` bloat. A backend with 150 tools at ~5 KB each
approaches etcd's ~1.5 MB per-object limit. Name + title + description at
~200-500 bytes per tool is the right middle ground: enough for policy
validation and kubectl inspection, without the storage risk.

### Separate ToolRegistry CRD

A dedicated `XToolRegistry` CRD could decouple tool discovery from XBackend.
This adds CRD surface area without clear benefit at this stage. If etcd size
becomes a concern, the `pkg/discovery/` package boundary makes migrating to a
separate CRD a localized change.

## Community Consensus Points

### Phase 1

1. **Is `XBackend.status` the right location?** Given the ongoing XBackend
   shape discussions ([#161](https://github.com/kubernetes-sigs/kube-agentic-networking/issues/161), [#162](https://github.com/kubernetes-sigs/kube-agentic-networking/issues/162)), should discovery wait? We argue no. Status
   constitutes observed state that is independent of spec changes.
2. **MCP client library.** Should KAN depend on `github.com/mark3labs/mcp-go`?
   It is the most mature Go MCP client.
3. **Default sync interval.** We propose 30s. Configurable via controller flag.

### Phase 3

4. **Warning vs. rejection.** Should an AccessPolicy referencing a
   non-existent tool be admitted with a Warning, or rejected? We recommend
   Warning — the backend may be temporarily unreachable.
5. **Bi-directional validation.** Should validation trigger on both
   AccessPolicy changes and XBackend status changes? We recommend both.

## Contributors

This proposal is led by @rubambiza (IBM) with support from @evaline-ju (IBM),
@david-martin (Red Hat), and @guicassolato (Red Hat). Delivery of Phases 1-2
would establish a natural ownership scope for `pkg/discovery/`. Phase 2 is
deferred pending Backend spec stabilization.

## References

- [0008-ToolAuthAPI proposal](./0008-ToolAuthAPI.md) — tool-level authorization, acknowledges discovery as a TODO
- [KAN issue #161](https://github.com/kubernetes-sigs/kube-agentic-networking/issues/161) — Service targeting on XBackend
- [KAN issue #162](https://github.com/kubernetes-sigs/kube-agentic-networking/issues/162) — Path on XBackend
- [KAN PR #182](https://github.com/kubernetes-sigs/kube-agentic-networking/pull/182) — Empty tool list deny-all semantics
- [gateway-api PR #4488](https://github.com/kubernetes-sigs/gateway-api/pull/4488) — Upstream Backend resource
- [AI Gateway WG Proposal 10](https://github.com/kubernetes-sigs/wg-ai-gateway/blob/main/proposals/10-egress-gateways.md) — Egress gateways with MCP protocol support
- [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25) — Current MCP spec with tool annotations, pagination, schema requirements
- [Kuadrant/mcp-gateway issue #662](https://github.com/Kuadrant/mcp-gateway/issues/662) — Schema validation gap
- [Kuadrant/mcp-gateway PR #329](https://github.com/Kuadrant/mcp-gateway/pull/329) — tools/list_changed support
