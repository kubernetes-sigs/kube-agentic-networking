Date: 27th November 2025<br/>
Authors: guicassolato<br/>
Status: Provisional<br/>

# Dynamic Auth

This proposal extends the [Tool Authorization proposal (0008)](./0008-ToolAuthAPI.md) with additional structure designed for highly dynamic agentic applications.

Unlike the static authorization model in proposal 0008—where identities and tools are explicitly enumerated in policy resources—this proposal addresses scenarios where both identities and resources are dynamic: identities may be unbounded in number, and registered without prior knowledge of the resource servers, and server resources (tools, prompts, etc.) may change frequently.

A set of new fields proposed to be added the AccessPolicy API can be used in conjunction with the existing ones from proposal 0008, or independently for use cases where this level of dynamism makes explicit enumeration impractical.

----

🚫 **STOP – PROVISIONAL API**
**Do NOT implement. Do NOT use in production.**

This API is **provisional** and subject to change without prior notice. Vendors and integrators should not implement or rely on it, and it must not be enabled in production environments until a stable version is released.

----

## Non-Goals

Agent and user authentication is not within the scope of this proposal.

## Use Cases & Motivation

### Personas

See _Tool Authorization in Agentic Networking_ > [Personas](./0008-ToolAuthAPI.md#personas).

### User Journeys

#### Agent identity federation

As an AI Engineer, I want the identities assigned to my agents running in Kubernetes to be federated with trusted identity sources to which authentication can be offloaded, based on standard protocols (e.g., OAuth 2.0, OpenID Connect), so that my applications can trust verifiable authentication tokens issued by those external systems.

#### Flexible authorization patterns for agentic server resources

As an AI Engineer, I want to restrict access to the server resources (tools, prompts, etc) my agents can use at various levels of granularity, including individual resources specified by name, but also groups of resources expressed in terms of common patterns (using standard expression languages such as CEL) and/or custom authorization decisions performed by an external specialized service.

#### Authorization decision offloading

As an AI Engineer, when controlling access to server resources for my agents, I want to be able to offload authorization decisions to external authorization systems.

## Extended AccessPolicy CRD

The AccessPolicy CRD ([proposal 0008](./0008-ToolAuthAPI.md)) will be extended with fields for defining an authorization enforcement strategy for:
- extracting identity information from the request based on standard authentication protocols (e.g. OIDC), and
- verification methods to authorize an agent-to-Backend request based on pattern-matching rules (e.g. using CEL).

```go
// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// AccessPolicy is the Schema for the authpolicies API.
type AccessPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// metadata is a standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// spec defines the desired state of AccessPolicy.
	// +required
	Spec AccessPolicySpec `json:"spec"`
	// status defines the observed state of AccessPolicy.
	// +optional
	Status AccessPolicyStatus `json:"status,omitempty"`
}

// AccessPolicySpec defines the desired state of AccessPolicy.
type AccessPolicySpec struct {
	// TargetRefs specifies the targets of the AccessPolicy.
	// Currently, only Backend can be used as a target.
	// +required
	TargetRefs []gwapiv1.LocalPolicyTargetReference `json:"targetRefs"`
	// Rules defines a list of rules to be applied to the target.
	// +required
	Rules []AccessRule `json:"rules"`
}

// AccessRule specifies an authorization rule for the targeted backend.
// If the authorization list is empty, the rule denies access to all requests from Source.
type AccessRule struct {
	// Source specifies the source of the request.
	// +required
	Source Source `json:"source"`
	// Authorization specifies a list of rules that at least one must match for access to be granted.
	// +optional
	Authorization []AuthorizationRule `json:"authorization,omitempty"`
}

// Source specifies the source of a request.
//
// Type must be set to indicate the type of source.
type Source struct {
	// +unionDiscriminator
	// +required
	Type AuthorizationSourceType `json:"type"`

	// spiffe specifies an identity that is matched by this rule.
	//
	// spiffe identities must be specified as SPIFFE-formatted URIs following the pattern:
	//   spiffe://<trust_domain>/<workload-identifier>
	//
	// The exact workload identifier structure is implementation-specific.
	//
	// spiffe identities for authorization can be derived in various ways by the underlying
	// implementation. Common methods include:
	// - From peer mTLS certificates: The identity is extracted from the client's
	//   mTLS certificate presented during connection establishment.
	// - From IP-to-identity mappings: The implementation might maintain a dynamic
	//   mapping between source IP addresses (pod IPs) and their associated
	//   identities (e.g., Service Account, SPIFFE IDs).
	// - From JWTs or other request-level authentication tokens.
	//
	// +optional
	SPIFFE *AuthorizationSourceSPIFFE `json:"spiffe,omitempty"`

	// ServiceAccount specifies a Kubernetes Service Account that is
	// matched by this rule. A request originating from a pod associated with
	// this serviceaccount will match the rule.
	//
	// The ServiceAccount listed here is expected to exist within the same
	// trust domain as the targeted workload. Cross-trust-domain access should
	// instead be expressed using the `SPIFFE` field.
	// +optional
	ServiceAccount *AuthorizationSourceServiceAccount `json:"serviceAccount,omitempty"`

 	// OIDC specifies a trusted OpenId Connect (OIDC) authentication server
	// The request is expected to carry a valid ID token issued by the trusted
	// authentication server, in the Authorization: header
	// +optional
	OIDC *AuthorizationSourceOIDC `json:"oidc,omitempty"`
}

// AuthorizationSourceType identifies a type of source for authorization.
// +kubebuilder:validation:Enum=ServiceAccount;SPIFFE;OIDC
type AuthorizationSourceType string

const (
	// AuthorizationSourceTypeSPIFFE is used to identify a request matches a SPIFFE Identity.
	AuthorizationSourceTypeSPIFFE AuthorizationSourceType = "SPIFFE"

	// AuthorizationSourceTypeServiceAccount is used to identify a request matches a ServiceAccount from within the cluster.
	AuthorizationSourceTypeServiceAccount AuthorizationSourceType = "ServiceAccount"

	// AuthorizationSourceTypeOIDC is used to identify a request bears an authentication token issued by a trusted specified OIDC server.
	AuthorizationSourceTypeOIDC AuthorizationSourceType = "OIDC"
)

// +kubebuilder:validation:Pattern=`^spiffe://[a-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$`
type AuthorizationSourceSPIFFE string

type AuthorizationSourceServiceAccount struct {
	// Namespace is the namespace of the ServiceAccount
	// If not specified, current namespace (the namespace of the policy) is used.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Name is the name of the ServiceAccount.
	// +required
	Name string `json:"name"`
}

type AuthorizationSourceOIDC struct {
	// IssuerUrl is the URL of the trusted OpenId Connect (OIDC) issuer
	// A JSON Web Key Set (JWKS) will be fetched from the issuer's
	// `/.well-known/openid-configuration` endpoint to validate the tokens
	// +required
	IssuerUrl string `json:"issuerUrl"`
	// Audiences is a list of acceptable audiences for the OIDC tokens
	// +optional
	Audiences []string `json:"audiences,omitempty"`
	// Scopes is a list of acceptable scopes for the OIDC tokens
	// +optional
	Scopes []string `json:"scopes,omitempty"`
}

// AuthorizationRule specifies an authorization rule.
//
// Type must be set to indicate the type of authorization rule.
type AuthorizationRule struct {
	// +unionDiscriminator
	// +required
	Type AuthorizationRuleType `json:"type"`

	// Tools specifies a list of tools inline.
	// +optional
	Tools []string `json:"tools,omitempty"`

	// CEL specifies a Common Expression Language (CEL) expression.
	// E.g.:
	// - request.body["tool-name"] in identity.authorized_tools
	// - identity.group == "admin"
	// +optional
	CEL *AuthorizationRuleCEL `json:"cel,omitempty"`

	// ExternalAuth specifies an external authorization service.
	// The field is defined as the HTTPExternalAuthFilter type from
	// Gateway API: https://pkg.go.dev/sigs.k8s.io/gateway-api/apis/v1#HTTPExternalAuthFilter
	// +optional
	ExternalAuth *gatewayapiv1.HTTPExternalAuthFilter `json:"externalAuth,omitempty"`
}

// AuthorizationRuleType identifies a type of rule for authorization.
// +kubebuilder:validation:Enum=InlineTools;CEL;ExternalAuth
type AuthorizationRuleType string

const (
	// AuthorizationRuleTypeInlineTools is used to identify a request must match one of the specified tool
	// for access to be granted.
	AuthorizationRuleTypeInlineTools AuthorizationRuleType = "InlineTools"

	// AuthorizationRuleTypeCEL is used to identify a Common Expression Language (CEL) expression
	// whose evaluation determines whether access shall be granted.
	AuthorizationRuleTypeCEL AuthorizationRuleType = "CEL"

	// AuthorizationRuleTypeExternalAuth is used to identify an external authorization endpoint to offload
	// the access control decision to.
	AuthorizationRuleTypeExternalAuth AuthorizationRuleType = "ExternalAuth"
)

// AuthorizationRuleCEL specifies a Common Expression Language (CEL) authorization rule.
type AuthorizationRuleCEL string

// AccessPolicyStatus defines the observed state of AccessPolicy.
type AccessPolicyStatus struct {
	// For Policy Status API conventions, see:
	// https://gateway-api.sigs.k8s.io/geps/gep-713/#the-status-stanza-of-policy-objects
	//
	// Ancestors is a list of ancestor resources (usually Backend) that are
	// associated with the policy, and the status of the policy with respect to
	// each ancestor. When this policy attaches to a parent, the controller that
	// manages the parent and the ancestors MUST add an entry to this list when
	// the controller first sees the policy and SHOULD update the entry as
	// appropriate when the relevant ancestor is modified.
	//
	// Note that choosing the relevant ancestor is left to the Policy designers;
	// an important part of Policy design is designing the right object level at
	// which to namespace this status.
	//
	// Note also that implementations MUST ONLY populate ancestor status for
	// the Ancestor resources they are responsible for. Implementations MUST
	// use the ControllerName field to uniquely identify the entries in this list
	// that they are responsible for.
	//
	// Note that to achieve this, the list of PolicyAncestorStatus structs
	// MUST be treated as a map with a composite key, made up of the AncestorRef
	// and ControllerName fields combined.
	//
	// A maximum of 16 ancestors will be represented in this list. An empty list
	// means the Policy is not relevant for any ancestors.
	//
	// If this slice is full, implementations MUST NOT add further entries.
	// Instead they MUST consider the policy unimplementable and signal that
	// on any related resources such as the ancestor that would be referenced
	// here.
	//
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	Ancestors []PolicyAncestorStatus `json:"ancestors"`
}
```

## Examples

### Example 1 - OIDC source used in combination with inline authorized tools

This example shows how an AccessPolicy resource can combine OIDC-based identity verification with inline authorization rules.

```yaml
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: AccessPolicy
metadata:
  name: access-policy-server1
spec:
  targetRefs:
  - group: agentic.networking.x-k8s.io
    kind: Backend
    name: mcp-server1
  rules:
  - source:
      type: OIDC
      oidc:
        issuerUrl: auth-server.example.com
    authorization:
    - type: InlineTools
      tools:
      - add
      - subtract
```

### Example 2 - Inline SPIFFE identities used in combination with CEL authorization

This example shows how an AccessPolicy resource can combine identity verification based on inline SPIFFE identities with CEL-based authorization rules.

```yaml
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: AccessPolicy
metadata:
  name: access-policy-server1
spec:
  targetRefs:
  - group: agentic.networking.x-k8s.io
    kind: Backend
    name: mcp-server1
  rules:
  - source:
      type: SPIFFE
      spiffe:
      - spiffe://example.org/ns/default/sa/agent-1
      - spiffe://example.org/ns/default/sa/agent-2
    authorization:
    - type: CEL
      cel: 'request.mcp.tool_name.startsWith("read_")'
```

### Example 3 – Multiple OIDC sources used in combination with CEL authorization

This example shows how an AccessPolicy can be used to trust more than one identity source.

Because the two exemplified identity sources differ regarding the structure of the JWTs they issue–one sets the `aud` claim as string, while the other uses lists–the example uses CEL to check the audience according to each corresponding data type.

```yaml
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: AccessPolicy
metadata:
  name: multiple-idps-auth
spec:
  targetRefs: […]
  rules:
  - source:
      type: OIDC
      oidc:
        issuerUrl: auth-server1.example.com
    authorization:
    - type: CEL
      cel: 'identity.aud == "my-server"' # type(identity.aud) == string
  - source:
      type: OIDC
      oidc:
        issuerUrl: auth-server2.example.com
    authorization:
    - type: CEL
      cel: '"my-server" in identity.aud' # type(identity.aud) == list
```

### Example 4 – External authorization service

This example shows how an AccessPolicy can be used to offload authorization decisions to an external authorization service.

```yaml
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: AccessPolicy
metadata:
  name: external-authz
spec:
  targetRefs: […]
  rules:
  - authorization:
    - type: ExternalAuth
      externalAuth:
        protocol: GRPC
        backendRef:
          name: ext-authz-service
```

## Special considerations for the implementation

### Common Expression Language (CEL) for authorization

Common Expression Language (CEL) expressions in AccessPolicy resources have access to a structured context that provides information about the request and the verified identity. Understanding this context is essential for writing effective authorization rules.

#### Available Context Variables

##### `request` Object

The `request` object contains information about the incoming request to the Backend:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `request.method` | `string` | HTTP method | `"POST"` |
| `request.path` | `string` | Request path | `"/mcp"` |
| `request.headers` | `map<string, string>` | HTTP headers (lowercase keys) | `{"content-type": "application/json"}` |
| `request.mcp.method` | `string` | MCP method name | `"tools/call"` |
| `request.mcp.tool_name` | `string` | Name of the MCP tool being invoked | `"add"`, `"subtract"` |
| `request.mcp.params` | `map<string, dyn>` | MCP tool parameters | `{"a": 5, "b": 3}` |

**Note**: The `request.mcp.*` fields are only available when the Backend type is MCP. Future backend types may provide different protocol-specific fields.

##### `identity` Object

The `identity` object is set to one of the following based on the identity source used to verify the request:

- For inline SPIFFE identities: it's a synthetic object with a single field:
  - `identity.spiffe_id` (string): the SPIFFE ID of the verified identity.
- For Kubernetes ServiceAccounts: it's a synthetic object with fields:
  - `identity.service_account` (string): the name of the ServiceAccount.
  - `identity.namespace` (string): the namespace of the ServiceAccount.
- For OIDC tokens: it's the payload of the JWT.

#### Type Handling

CEL is strongly typed. When working with dynamic claims:

- Use type checking: `type(identity.custom_claim) == string`
- Handle nullable fields: `has(identity.field) && identity.field != null`
- Use appropriate comparisons for different types

#### Performance Considerations

- Keep expressions simple: Complex CEL expressions can impact request latency
- Avoid expensive operations: Minimize use of regex matching and large list iterations
- Cache-friendly expressions: Expressions that depend only on identity claims can be cached more effectively than those examining request details

### Security considerations

Implementations of the AccessPolicy API must carefully consider the following security aspects to maintain a secure agentic networking environment:

#### Token Validation Best Practices

OIDC Tokens:
- Implement proper OIDC discovery to fetch issuer metadata and public keys from the `/.well-known/openid-configuration` endpoint
- Validate the issuer URL (`iss` claim) exactly matches the configured `issuerUrl` in the AccessPolicy
- Always validate token signatures using the issuer's published public keys (JWKS)
- Verify standard claims: `exp` (expiration), `nbf` (not before), `iat` (issued at)
- Implement key rotation support by regularly fetching updated JWKS from the issuer

#### Audience Claim Importance

The audience (`aud`) claim is critical for preventing token misuse:

- Always specify and validate audiences. Omitting audience validation (as shown in the standalone example with `kubernetes: {}`) should only be used in controlled development environments
- Reject tokens that do not contain the expected audience in their `aud` claim
- Use backend-specific audiences to ensure tokens issued for one backend cannot be used to access another
- Be aware that some identity providers may return `aud` as a string or an array; implementations must handle both cases (see [Example 3](#example-3--multiple-identity-providers))
- For multi-tenant environments, consider including tenant identifiers in the audience claim

#### Risk of Overly Permissive CEL Expressions

CEL-based authorization provides powerful flexibility but can introduce security risks if not carefully designed:

Common Pitfalls:
- Avoid negation-based policies: Expressions like `!(identity.role == "blocked")` grant access by default and should be avoided. Instead, use explicit allow lists: `identity.role in ["admin", "operator"]`
- Beware of missing fields: CEL expressions must handle cases where claims may not exist. Use the `has()` macro: `has(identity.authorized_tools) && request.mcp.tool_name in identity.authorized_tools`
- Validate data types: Ensure claims are of expected types before comparison to prevent type coercion vulnerabilities
- Limit expression complexity: Overly complex CEL expressions are hard to audit and may have unintended security implications

Recommendations:
- Implement a review process for all CEL expressions before deploying to production
- Test CEL expressions with both positive and negative test cases
- Use the principle of least privilege: start restrictive and gradually expand access as needed
- Consider using well-tested CEL expression libraries or templates for common authorization patterns
- Monitor and log CEL evaluation failures to detect potential attacks or misconfigurations

#### OIDC Issuer Validation

Proper validation of OIDC issuers is essential to prevent token forgery and man-in-the-middle attacks:

- Use HTTPS exclusively: Never accept OIDC issuers using HTTP. Implementations should reject non-HTTPS issuer URLs
- Validate TLS certificates: Ensure proper certificate validation when connecting to OIDC discovery endpoints and JWKS URIs
- Pin trusted issuers: Maintain an explicit allow-list of trusted issuer URLs rather than accepting any issuer
- Implement issuer discovery caching: Cache OIDC discovery documents and JWKS responses with appropriate TTLs to reduce attack surface and improve performance, but ensure caches respect `Cache-Control` headers
- Monitor for issuer changes: Alert on any unexpected changes to issuer metadata or signing keys

#### Defense in Depth

- Check for resource-level authorization: Use AccessPolicy for identity verification and additional resource-level authorization when appropriate
- Implement rate limiting: Protect against brute-force token validation attempts
- Enable audit logging: Log all authentication and authorization decisions for security monitoring and incident response
- Regular security reviews: Periodically review AccessPolicy configurations, especially CEL expressions and trusted issuer lists
- Principle of least privilege: Grant only the minimum necessary permissions to agents and regularly review role bindings

## Prior Art

See [Kuadrant’s AuthPolicy](./0008-ToolAuthAPI.md#kuadrants-authpolicy) and [Envoy Gateway’s SecurityPolicy](./0008-ToolAuthAPI.md#envoy-gateways-securitypolicy).
