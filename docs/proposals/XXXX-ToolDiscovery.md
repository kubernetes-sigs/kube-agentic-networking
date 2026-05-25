# Tool Discovery for KAN

Date: 16th March 2026<br/>
Authors: @rubambiza, @evaline-ju, @david-martin, @guicassolato<br/>
Status: Provisional<br/>

> [!CAUTION]
> This API is in a provisional state. It is subject to change and should not be
> implemented without first consulting the maintainers of the project.

### Revision History

| Date | Change |
|------|--------|
| 2026-05-25 | Major revision: replaced `XBackend.status.discoveredTools` with a dedicated `XToolInventory` CRD (1:1 with XBackend via `backendRef`). Updated all examples to `agentic.networking.x-k8s.io/v1alpha1` with method-based matching (`mcp.methods[].params[]`). Changed default poll interval from 30s to 5m. Added hybrid creation model (explicit + annotation-triggered). Motivated by community feedback from @keithmattix and @david-martin. |
| 2026-04-06 | Added A2A scoping non-goal. |
| 2026-03-16 | Initial proposal. |

## Summary

KAN has no mechanism to discover what tools an MCP backend exposes. Operators
must manually enumerate tool names in `XAccessPolicy` rules, and there is no
feedback loop when tools are added, removed, or misconfigured on backends.

This proposal adds optional, opt-in tool discovery to KAN: a controller that
connects to MCP backends, calls `tools/list`, validates the results, and
surfaces discovered tools in a dedicated `XToolInventory` resource (one per
backend, linked via `backendRef`). This enables policy validation against real
backend state, operator visibility via `kubectl`, and a foundation for future
capabilities like response filtering. Discovery is advisory (i.e., it enhances
observability but does not affect policy enforcement). Backends without
discovery enabled continue to work exactly as they do today.

## Non-Goals

- **`tools/list` response filtering.** Filtering the `tools/list` response
  based on caller identity (so agents only see tools they're authorized to call)
  is a natural next step but would require a separate proposal.
- **Tool prefixing / federation.** Disambiguating tools with the same name
  across multiple backends (e.g., via prefix namespacing) is out of scope.
- **Full tool schema storage.** Storing `inputSchema` and `outputSchema` in
  `XToolInventory.status` risks etcd bloat. Discovery validates schemas but
  does not persist them.
- **Agent capability discovery.** Backends that are AI agents (e.g.,
  exposing capabilities via A2A or similar protocols) use different discovery
  mechanisms than MCP `tools/list`. This proposal is scoped to MCP tool
  discovery only; agent capability discovery is a parallel concern.

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
// No discoveredTools, no tool metadata.
```

This creates three concrete problems:

**1. Stale access policies.** `XAccessPolicy` rules require operators to
manually list tool names. If a backend adds, renames, or removes a tool, the
policy becomes stale with no warning. The ToolAuthAPI proposal (0008) explicitly
acknowledges this as a TODO.

**2. No operator visibility.** There is no way to inspect what tools a backend
exposes without directly calling `tools/list` on the backend. `kubectl` tells
you nothing about the backend's capabilities.

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
The platform engineer creates an `XBackend` pointing at an MCP server and
either creates an `XToolInventory` with a `backendRef` or annotates the
XBackend to trigger auto-creation. Within the poll interval,
`kubectl get xtoolinventory weather-service-tools -o yaml` shows
`status.discoveredTools` populated with the backend's tools. No manual
enumeration required.

**CUJ 2: Operator writes a valid access policy.**
The platform engineer writes an `XAccessPolicy` referencing tool names in
`mcp.methods[].params[]`. The controller validates the tool names against
the corresponding `XToolInventory.status.discoveredTools` and sets a Warning
in the policy's `Accepted` condition message if any tool name doesn't match.

**CUJ 3: Backend adds a new tool.**
A tool developer deploys a new version of their MCP server with an additional
tool. The discovery controller detects the change (via `tools/list_changed`
notification or the next poll) and updates the `XToolInventory` status.
Existing `XAccessPolicy` resources that don't include the new tool are
unaffected; the operator can add it when ready.

**CUJ 4: Backend exposes an invalid tool.**
A tool developer deploys an MCP server with a tool whose `inputSchema` is
invalid JSON Schema. The discovery controller validates the schema, rejects the
tool, and emits a Warning event on the `XToolInventory`. The invalid tool does
not appear in `status.discoveredTools`, preventing it from being referenced in
policies or reaching agents.

## Context

Three recent developments inform this proposal's design:

**XBackend is in flux.** KAN is actively reconsidering XBackend's shape to
align with the AI Gateway WG's Backend resource ([gateway-api PR #4488](https://github.com/kubernetes-sigs/gateway-api/pull/4488)). [Issue
#161](https://github.com/kubernetes-sigs/kube-agentic-networking/issues/161) tracks whether to drop `Service` as a target type; [issue #162](https://github.com/kubernetes-sigs/kube-agentic-networking/issues/162) questions
whether `path` belongs on XBackend or in protocol-specific options.
Additionally, not every backend controller performs discovery — coupling
discovery data to XBackend.status would force all backend controllers to
account for fields they don't manage. A separate `XToolInventory` CRD
decouples discovery lifecycle from backend lifecycle, allowing discovery to
evolve independently of XBackend's ongoing shape changes.

**MCP 2025-11-25 expanded the tool data model.** The MCP spec now includes
`title` (human-readable display name), `outputSchema`, `icons`, pagination on
`tools/list` via cursor, and mandatory JSON Schema 2020-12 validation for
`inputSchema`. The `tools/list_changed` notification (available since
2025-03-26) was not incorporated in the original proposal.

**Kuadrant/mcp-gateway validates the approach.** Three developments in the MCP
Gateway directly inform this proposal: `tools/list_changed` support ([PR #329](https://github.com/Kuadrant/mcp-gateway/pull/329))
validates the hybrid polling + notification approach; [issue #662](https://github.com/Kuadrant/mcp-gateway/issues/662) (invalid
schemas breaking downstream agents) motivates schema validation at the discovery
layer; and [issue #629](https://github.com/Kuadrant/mcp-gateway/issues/629) (usability issues with reflecting discovery data on
CRD status) motivates the choice of a dedicated CRD over embedding in
XBackend.status.

## API

### XToolInventory CRD

A new `XToolInventory` resource provides a 1:1 mapping to an XBackend,
containing the discovery configuration (spec) and discovered tool data
(status). This mirrors patterns like Service → EndpointSlice where observed
state lives in a companion resource rather than on the original object.

```go
// XToolInventory represents the discovered tool set for a single MCP backend.
// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type XToolInventory struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`

    Spec   XToolInventorySpec   `json:"spec"`
    Status XToolInventoryStatus `json:"status,omitempty"`
}

type XToolInventorySpec struct {
    // BackendRef identifies the XBackend this inventory is for.
    // +required
    BackendRef gwapiv1.LocalObjectReference `json:"backendRef"`

    // PollInterval is the interval between discovery polls for backends
    // that do not support tools/list_changed notifications.
    // Defaults to 5 minutes.
    // +optional
    PollInterval *metav1.Duration `json:"pollInterval,omitempty"`
}

type XToolInventoryStatus struct {
    // Conditions describe the current state of tool discovery.
    // +optional
    // +listType=map
    // +listMapKey=type
    Conditions []metav1.Condition `json:"conditions,omitempty"`

    // DiscoveredTools lists the tools discovered on the referenced backend
    // via MCP tools/list. Only tools with valid schemas are included.
    // +optional
    // +listType=map
    // +listMapKey=name
    DiscoveredTools []DiscoveredTool `json:"discoveredTools,omitempty"`

    // LastDiscoveryTime is the timestamp of the last successful
    // tools/list call to the referenced backend.
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

### XToolInventory Conditions

The discovery controller sets the following conditions on `XToolInventory`:

| Type | Status | Reason | Meaning |
|------|--------|--------|---------|
| `Ready` | `True` | `DiscoverySucceeded` | tools/list succeeded, all tools valid |
| `Ready` | `True` | `PartiallyValid` | tools/list succeeded, but some tools had invalid schemas and were excluded |
| `Ready` | `False` | `DiscoveryFailed` | tools/list call itself failed (backend unreachable, protocol error) |

### Complete Example

```yaml
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: XBackend
metadata:
  name: weather-service
  namespace: default
  annotations:
    agentic.networking.x-k8s.io/enable-discovery: "true"
spec:
  mcp:
    serviceName: weather-mcp
    port: 8080
    path: /mcp
---
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: XToolInventory
metadata:
  name: weather-service-tools
  namespace: default
  ownerReferences:
    - apiVersion: agentic.networking.x-k8s.io/v1alpha1
      kind: XBackend
      name: weather-service
      uid: <backend-uid>
spec:
  backendRef:
    group: agentic.networking.x-k8s.io
    kind: XBackend
    name: weather-service
  pollInterval: 5m
status:
  conditions:
    - type: Ready
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
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: XAccessPolicy
metadata:
  name: agent-weather-access
  namespace: default
spec:
  targetRefs:
    - group: agentic.networking.x-k8s.io
      kind: XBackend
      name: weather-service
  rules:
    - name: allow-forecast
      source:
        serviceAccount:
          name: my-agent
          namespace: default
      authorization:
        type: Inline
        mcp:
          methods:
            - name: tools/call
              params:
                - "get_forecast"
                - "get_humidity"  # Not discovered on backend
status:
  ancestors:
    - ancestorRef:
        group: agentic.networking.x-k8s.io
        kind: XBackend
        name: weather-service
      controllerName: agentic.networking.x-k8s.io/controller
      conditions:
        - type: Accepted
          status: "True"
          reason: "Accepted"
          message: "Policy accepted; unverified tools: get_humidity (not found in XToolInventory 'weather-service-tools')"
          lastTransitionTime: "2026-03-16T10:31:00Z"
```

## Implementation

### Discovery Controller

The discovery logic lives in `pkg/discovery/` within the existing
`agentic-net-controller` binary as a new reconciler. Discovery is opt-in via
two mechanisms (a common Kubernetes pattern, analogous to how a Service can
auto-create an EndpointSlice, but operators can also manage EndpointSlices
manually):

1. **Explicit creation.** An operator creates an `XToolInventory` with a
   `backendRef` pointing at an XBackend. The controller reconciles it
   immediately.
2. **Annotation-triggered auto-creation.** When an XBackend carries the
   annotation `agentic.networking.x-k8s.io/enable-discovery: "true"` and no
   corresponding XToolInventory exists, the controller auto-creates one with
   an `ownerReference` back to the XBackend (enabling garbage collection on
   backend deletion).

The discovery controller can be disabled entirely via a controller flag
(`--enable-discovery=false`).

The discovery controller connects to backends using its own service account
identity. This is distinct from agent runtime identities — the controller's
`tools/list` calls are a control-plane operation, while agent `tools/call`
requests at runtime are data-plane operations subject to XAccessPolicy
enforcement.

For each XToolInventory, the controller:

1. **Resolves** the backend address from the referenced XBackend's
   `spec.mcp.serviceName` and port.
2. **Connects** to the backend's MCP endpoint using the `mcp-go` client
   library (`github.com/mark3labs/mcp-go`).
3. **Calls** `tools/list`, handling pagination via cursor for backends with
   many tools.
4. **Validates** each tool's `inputSchema` against JSON Schema draft 2020-12.
   Tools with invalid schemas are rejected and logged as Warning events on the
   XToolInventory resource.
5. **Updates** `XToolInventory.status.discoveredTools[]` with validated tools
   only.
6. **Maintains a persistent connection** to backends that declare the
   `listChanged` capability, listening for `tools/list_changed` notifications
   to trigger immediate re-discovery.
7. **Falls back to polling** (configurable via `spec.pollInterval`, default 5m)
   for backends that don't support `list_changed`, and as a periodic
   consistency check for all backends.
8. **Detects drift** by diffing new vs. old tool sets and emits Kubernetes
   Events when tools are added, removed, or fail validation.

### XAccessPolicy Validation

The existing XAccessPolicy reconciler is extended to cross-reference
`rules[].authorization.mcp.methods[].params[]` against
`XToolInventory.status.discoveredTools` for the policy's target backend:

- The reconciler finds the XToolInventory whose `spec.backendRef` matches the
  policy's `targetRef`.
- Tool names in `params[]` (for `tools/call` method entries) are compared
  against `discoveredTools[].name`.
- If a tool name doesn't match, the unverified tool names are surfaced in the
  `Accepted` condition's `message` field on the relevant ancestor entry
  (not rejection — the tool may not be discovered yet). This follows
  Gateway API convention of using standard condition types rather than
  introducing domain-specific ones.
- Validation runs on both XAccessPolicy changes and XToolInventory status
  changes, so stale policies are detected when a backend removes a tool.

### Phasing

**Phase 1: In-cluster discovery (plain HTTP).** XToolInventory CRD, discovery
controller, schema validation, `list_changed` support, drift detection. The
controller connects to backends using the service name and port from
`XBackend.spec.mcp` over plain HTTP. This is sufficient for in-cluster backends
where trust is assumed. In mesh environments (e.g., Istio sidecar on the
controller pod), mTLS is handled transparently at the infrastructure layer, so
the plain HTTP implementation covers that case without extra work.

Backends that require authentication for `tools/list` will fail gracefully:
the XToolInventory receives a `Ready: False` condition with reason
`DiscoveryFailed`, and XAccessPolicy enforcement continues unaffected. Discovery
is advisory — it does not gate the data plane. The operator sees an early
signal that the backend is unreachable to the control plane, but runtime tool
calls proceed normally as long as the agent's own credentials are valid.

**Phase 2: External backends (TLS and authentication).** Extends the discovery
controller to connect to backends outside the cluster, requiring TLS and
potentially a credential reference for `tools/list` calls. The exact mechanism
(e.g., a `credentialRef` on XToolInventory) is deferred pending stabilization
of the Backend spec between KAN and the AI Gateway WG.

**Phase 3: Policy validation.** XAccessPolicy cross-referencing against
discovered tools. When an XToolInventory has `Ready: False` (discovery failed
or not yet attempted), any XAccessPolicy targeting the corresponding backend
includes a note in the `Accepted` condition message indicating which target
backends had no discovery data available (e.g., "tools not verified against
XBackend 'weather-service': discovery unavailable"). This ensures operators
have visibility without blocking policy acceptance.

### Alternative: Separate Discovery Controller Binary

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
- *Con:* Usability issues with reflecting discovery data directly on CRD status
  ([issue #629](https://github.com/Kuadrant/mcp-gateway/issues/629)) motivate a dedicated resource.

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

### Full tool metadata in XToolInventory.status

Storing `inputSchema`, `outputSchema`, and other fields would provide a
complete picture but risks `etcd` bloat. A backend with 150 tools at ~5 KB each
approaches etcd's ~1.5 MB per-object limit. Name + title + description at
~200-500 bytes per tool is the right middle ground: enough for policy
validation and kubectl inspection, without the storage risk.

### Discovery data in XBackend.status

The initial version of this proposal placed discovered tools in
`XBackend.status.discoveredTools`. Community feedback identified issues with
this approach: not every backend controller performs discovery, so embedding
discovery fields in XBackend.status forces all backend controllers to account
for fields they don't manage; XBackend's shape is actively in flux
([#161](https://github.com/kubernetes-sigs/kube-agentic-networking/issues/161), [#162](https://github.com/kubernetes-sigs/kube-agentic-networking/issues/162)), and coupling discovery to it creates unnecessary
churn; and practical experience in mcp-gateway ([issue #629](https://github.com/Kuadrant/mcp-gateway/issues/629)) showed usability
issues with reflecting discovery data on the backend resource's status. A
dedicated XToolInventory CRD decouples discovery lifecycle from backend
lifecycle.

## Community Consensus Points

### Phase 1

1. **Is XToolInventory with 1:1 backendRef the right granularity?** One
   XToolInventory per XBackend is expected to scale well for typical
   deployments (tens to low hundreds of MCP backends), analogous to
   HTTPRoute-per-route. The opt-in model (only backends that want discovery get
   an XToolInventory) naturally bounds the number of objects.
2. **MCP client library.** Should KAN depend on `github.com/mark3labs/mcp-go`?
   It is the most mature Go MCP client.
3. **Default poll interval.** We propose 5 minutes. Configurable via
   `spec.pollInterval` on XToolInventory.
4. **Hybrid creation model.** Operators can pre-create XToolInventory resources
   or let the controller auto-create them via annotation. Is this acceptable?

### Phase 3

5. **Warning vs. rejection.** Should an XAccessPolicy referencing a
   non-existent tool be admitted with a Warning, or rejected? We recommend
   Warning — the backend may be temporarily unreachable.
6. **Bi-directional validation.** Should validation trigger on both
   XAccessPolicy changes and XToolInventory status changes? We recommend both.

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
- [Kuadrant/mcp-gateway issue #629](https://github.com/Kuadrant/mcp-gateway/issues/629) — Status usability issues motivating dedicated CRD
- [Kuadrant/mcp-gateway PR #329](https://github.com/Kuadrant/mcp-gateway/pull/329) — tools/list_changed support
