# Bounded Authorization Extensions for AccessPolicy

## Context

`XAccessPolicy` supports inline, CEL, and Envoy external authorization. These
mechanisms cover common enforcement paths, but they do not provide a portable
way for another Kubernetes API to describe protocol-specific authorization
logic. [Issue #308](https://github.com/kubernetes-sigs/kube-agentic-networking/issues/308)
requests a generic extension mechanism, including implementations that need
request content and metadata to decide whether an action is allowed.

Forwarding an unbounded or partially buffered request to an extension creates a
security ambiguity: the authorizer can approve one byte sequence while the
backend receives another. Agentic protocols make this especially dangerous
because authorization-relevant fields such as an MCP tool name, tool arguments,
an A2A skill, or a resource URI are carried in the request body.

This proposal defines a bounded extension reference and a normalized decision
contract. It is protocol-neutral so MCP, A2A, HTTP APIs, and future skill-based
protocols can share the same policy attachment model.

## Goals

* Allow an `XAccessPolicy` to reference authorization configuration owned by
  another Kubernetes API without standardizing that API's internal fields.
* Give extensions a deterministic, bounded request context.
* Bind decisions to verified identity, target, policy generation, and request
  content.
* Require fail-closed behavior when context is incomplete or the extension is
  unavailable.
* Permit implementations to return obligations and evidence metadata without
  allowing arbitrary mutation of the upstream request.
* Keep metrics low-cardinality and sensitive request data out of audit records.

## Non-goals

* Replacing the existing Gateway API `ExternalAuth` integration.
* Defining a new policy language, identity format, or extension transport.
* Allowing extensions to inject credentials or arbitrary headers directly.
* Standardizing protocol-specific argument schemas in `XAccessPolicy`.
* Sending unlimited request or response bodies to an authorizer.

## API shape

The proposed API adds an `ExtensionRef` action and a same-namespace local
reference. The referenced object is interpreted by an implementation that
declares support for its Group and Kind.

```go
type AccessPolicySpec struct {
    // Existing fields omitted.
    Action       AccessPolicyActionType       `json:"action"`
    ExtensionRef *AuthorizationExtensionRef   `json:"extensionRef,omitempty"`
}

type AuthorizationExtensionRef struct {
    Group gatewayv1.Group      `json:"group"`
    Kind  gatewayv1.Kind       `json:"kind"`
    Name  gatewayv1.ObjectName `json:"name"`
}
```

The reference deliberately has no namespace field. An extension object must be
in the policy namespace. Cross-namespace references can be considered later
with explicit `ReferenceGrant` semantics.

The following validations apply:

* `extensionRef` is required when `action` is `ExtensionRef`.
* `extensionRef` is forbidden for other actions.
* `group`, `kind`, and `name` are required.
* Core groups and `Secret` references are forbidden.
* An implementation that does not recognize the Group and Kind sets the
  policy's `Accepted` condition to `False` with reason
  `UnsupportedExtensionRef`.
* Missing or unauthorized references set `ResolvedRefs` to `False`.

## Normalized authorization context

Implementations may use Envoy `ext_authz`, an in-process plugin, or another
transport. Regardless of transport, the extension evaluates the following
logical context:

```json
{
  "schemaVersion": "v1alpha1",
  "requestId": "opaque-id",
  "principal": {
    "type": "SPIFFE",
    "id": "spiffe://example.test/ns/agents/sa/researcher",
    "delegatedBy": "optional verified principal"
  },
  "target": {
    "group": "agentic.networking.x-k8s.io",
    "kind": "XBackend",
    "namespace": "tools",
    "name": "source-control"
  },
  "policy": {
    "namespace": "agents",
    "name": "source-control-policy",
    "uid": "opaque-uid",
    "generation": 7
  },
  "request": {
    "protocol": "MCP",
    "method": "tools/call",
    "capability": "create_pull_request",
    "contentLength": 824,
    "contentDigest": "sha256:...",
    "content": "optional bounded protocol context"
  }
}
```

`principal.id` must come from an authenticated source such as mTLS, a validated
JWT, or an implementation-maintained workload identity mapping. Headers
supplied by the calling agent are not verified identity.

`content` is optional. When present, it contains a bounded, protocol-specific
projection rather than an automatically unbounded raw body. Examples include
the MCP method, tool name, and arguments object or the A2A skill and task
parameters. The exact projection is declared by the referenced extension type.

`contentDigest` is calculated over the complete bytes that will be forwarded to
the backend, before any credential injection. It lets an extension bind its
decision and evidence to the executed request without retaining sensitive
content.

## Request body invariants

When body content participates in a decision:

1. The implementation buffers no more than the configured maximum.
2. A body larger than that maximum is rejected before authorization and is not
   forwarded to the backend.
3. A truncated or partial body is never submitted as if it were complete.
4. The bytes authorized are the bytes forwarded, except for explicitly
   declared implementation transformations that occur after authorization.
5. Malformed protocol content fails closed when the extension requires parsed
   protocol context.
6. Compression and content-encoding behavior must be documented; an
   implementation must not authorize compressed bytes and inspect a different
   decompressed representation without binding both representations.

The reference implementation maps these requirements to Envoy
`BufferSettings` with `allow_partial_message: false`. A configured maximum of
zero disables body forwarding rather than installing a zero-byte buffer.

## Decision contract

An extension returns one of `Allow`, `Deny`, or `Indeterminate` plus a stable
reason code. `Indeterminate`, timeout, malformed responses, and transport
failure are denied.

An allow decision may include bounded obligations from an implementation-owned
allowlist, for example:

* `requireApproval`
* `maximumInvocations`
* `credentialBinding`
* `responseDataClass`
* `evidenceProfile`

Unknown obligations cause the decision to fail closed. Extensions cannot
return arbitrary upstream headers. Implementations translate supported
obligations into enforcement behavior after validating their values.

The response may include an opaque evidence receipt and expiry. The receipt is
not itself authority and must not extend the lifetime of the underlying
decision.

## Evaluation and conflict semantics

Extension authorization runs after authentication and before `Allow` policies.
All applicable enforcement layers must allow the request. An extension allow
does not override an inline or CEL denial.

Core support remains limited to one remote callout per target. Multiple policy
objects may refer to the same extension configuration, but implementations must
deduplicate equivalent callouts and retain deterministic policy ordering.

Decision caches, when implemented, are keyed by at least:

* verified principal;
* target identity;
* policy UID and generation;
* extension object UID and generation;
* complete request content digest;
* protocol capability;
* relevant authentication context.

Cached entries must have a bounded lifetime and be invalidated when either
referenced object changes.

## Observability and privacy

Authorization telemetry records decision, normalized reason, protocol, policy
identity, extension Group and Kind, duration, and whether the decision was
cached. Raw bodies, query values, credentials, authorization headers, and
extension responses are excluded by default.

Dynamic identities, request IDs, resource names, and content digests belong in
traces or bounded audit storage, not Prometheus labels.

## Security considerations

* Extension references are configuration authority. Kubernetes RBAC must
  restrict who can create referenced objects and attach them to policies.
* The enforcement implementation must read referenced objects through its own
  typed client or dynamic client and verify Group, Kind, namespace, UID, and
  generation.
* An extension service is a high-value target and should use authenticated,
  encrypted transport with restricted network reachability.
* Extension error text is not returned directly to an untrusted agent.
* Request context supplied through headers must be removed from the downstream
  request unless the implementation explicitly owns that header.
* Credentials are resolved only after authorization and are bound to the same
  target and request digest where supported.

## Implementation phases

1. Enforce complete-body semantics for existing `ExternalAuth` translation.
2. Define conformance tests for oversized, malformed, and partial requests.
3. Add the `ExtensionRef` API and status reasons after API review.
4. Implement one reference extension using the existing Envoy external
   authorization transport.
5. Add MCP and generic skill projections, aligned with
   [issue #260](https://github.com/kubernetes-sigs/kube-agentic-networking/issues/260).
6. Standardize obligation and evidence profiles only after multiple
   implementations demonstrate interoperability.

## Alternatives

### Use only ExternalAuth

Existing external authorization is sufficient when a Service backend and Envoy
transport fully describe the integration. It cannot reference configuration
owned by another API or advertise a protocol-specific extension type.

### Forward the complete raw request without a normalized contract

This is flexible but makes privacy, interoperability, caching, and evidence
binding implementation-specific. It also encourages authorization services to
retain secrets and sensitive tool arguments.

### Add every protocol to XAccessPolicy

Adding MCP, A2A, and each future skill protocol directly would continually
expand the core API. Extension references preserve a small attachment API while
allowing independent protocol evolution.

### Permit partial-body authorization

This was rejected because the authorizer and backend would evaluate different
messages. For tool calls, omitted trailing arguments can contain the exact
resource, command, or amount that determines whether an operation is safe.
