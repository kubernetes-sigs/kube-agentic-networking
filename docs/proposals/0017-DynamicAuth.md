Date: 27th November 2025
Authors: guicassolato
Status: Provisional

# Dynamic Auth

This proposal extends the [Tool Authorization proposal (0008)](./0008-ToolAuthAPI.md) with an optional second auth API designed for highly dynamic agentic applications.

Unlike the static authorization model in proposal 0008—where identities and tools are explicitly enumerated in policy resources—this proposal addresses scenarios where both identities and resources are dynamic: identities may be unbounded in number, and registered without prior knowledge of the resource servers, and server resources (tools, prompts, etc.) may change frequently.

The proposed AuthScheme API can be used in conjunction with the tool authorization APIs from proposal 0008, or as a standalone alternative for use cases where this level of dynamism makes explicit enumeration impractical.

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

As an AI Engineer, I want the identities assigned to my agents running in Kubernetes to be federated with trusted identity sources to which authentication can be offloaded, based on standard protocols (e.g., OAuth 2.0, OpenID Connect) and/or authentication capabilities provided by the platform (Kubernetes Service Accounts), so that my applications can trust verifiable access tokens issued by those external systems.

#### Flexible authorization patterns for agentic server resources

As an AI Engineer, I want to restrict access to the server resources (tools, prompts, etc) my agents can use at various levels of granularity, including individual resources specified by name, but also groups of resources expressed in terms of common patterns (using standard expression languages such as CEL) and/or based on well-known authorization models such as Role-Based Access Control (RBAC).

#### Authorization decision offloading

As an AI Engineer, when controlling access to server resources for my agents, I want to be able to leverage authorization capabilities provided by the platform (Kubernetes RBAC) and/or other forms of offloading the authorization decisions to external authorization systems.

## AuthScheme CRD

An AuthScheme resource defines the enforcement strategy for extracting the identity, identifying the requested agentic resource, and verification methods for an agent-to-Backend request. It allows configuring a policy enforcement point (PEP) for enforcing access control policies (permissions) otherwise declared via AccessPolicy resources or other methods.

The AuthScheme API provides language for expressing extraction, trust anchor definitions, and resource identification patterns that allow integrating external authenticators (e.g. OIDC endpoints) and authorizers (Kubernetes RBAC), with a focus on the auth methods rather than the auth data. It can be used in combination or sometimes as an alternative to the AccessPolicy CRD for more advanced use cases and cases where the scale requires offloading auth beyond the limits of a policy resource.

```go
// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// AuthScheme is the Schema for the authschemes API.
type AuthScheme struct {
	metav1.TypeMeta `json:",inline"`
	// metadata is a standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// spec defines the desired state of AuthScheme.
	// +required
	Spec AuthSchemeSpec `json:"spec"`
	// status defines the observed state of AuthScheme.
	// +optional
	Status AuthSchemeStatus `json:"status,omitempty"`
}

// AuthSchemeSpec defines the desired state of AuthScheme.
type AuthSchemeSpec struct {
	// TargetRefs specifies the targets of the AuthScheme.
	// Currently, only Backend can be used as a target.
	// +required
	TargetRefs []gwapiv1.LocalPolicyTargetReference `json:"targetRefs"`
	// Rules defines a list of rules to be applied to the target.
  // Multiple rules are interpreted as a logical OR
	// +listType=map
	// +listMapKey=name
	// +required
	Rules []AuthRule `json:"rules"`
}

// IdentityRuleType defines a type of identity verification rule
// +kubebuilder:validation:Enum=Kubernetes,OIDC
type IdentityRuleType string

const (
	// IdentityRuleKubernetes defines the type of identity verification rule as Kubernetes authentication
	IdentityRuleKubernetes IdentityRuleType = "Kubernetes"
	// IdentityRuleOIDC defines the type of identity verification rule as OIDC token issued by a trusted OIDC authentication server
	IdentityRuleOIDC IdentityRuleType = "OIDC"
)

// IdentityRule specifies the identity verification configuration for an auth scheme rule.
// It defines how to extract and verify the identity of the requester.
type IdentityRule struct {
	// Type specifies the type of the identity verification scheme
	// +required
	Type *IdentityRuleType `json:"type"`
	// Kubernetes defines a Kubernetes identity verification scheme
	// It includes fields such as:
	// - where from in the request to extract a Kubernetes token to verify (default to Authorization header)
	// - for which audiences the Kubernetes token must be valid
	// +optional
	Kubernetes KubernetesIdentityVerification `json:"kubernetes,omitempty"`
	// OIDC defines an OIDC identity verification scheme
	// It includes fields such as:
	// - endpoint of the OIDC server issuer
	// +optional
	OIDC OIDCIdentityVerification `json:"oidc,omitempty"`
}

// AuthorizationRuleType defines a type of authorization verification rule
// +kubebuilder:validation:Enum=Kubernetes,CommonExpressionLanguage
type AuthorizationRuleType string

const (
	// AuthorizationRuleKubernetesRBAC defines the type of the authorization scheme as Kubernetes authorization
	AuthorizationRuleKubernetesRBAC AuthorizationRuleType = "Kubernetes"
	// AuthorizationRuleCEL defines the type of the authorization scheme as Common Expression Language (CEL) expression
	AuthorizationRuleCEL AuthorizationRuleType = "CommonExpressionLanguage"
)

// AuthorizationRule specifies the authorization verification configuration for an auth scheme rule.
// It defines how to evaluate whether the verified identity has permission to access the requested resource.
type AuthorizationRule struct {
	// Type specifies the type of the authorization scheme
	Type *AuthorizationRuleType `json:"type"`
	// Kubernetes defines a scheme for verifying authorization with the Kubernetes authorization system
	// It includes fields such as:
	// - what claim from the identity to use as the `user` (e.g.: `identity.username`)
	// - what claim from the identity to use as the `group` (e.g.: `identity.group`)
	// - where from in the request to extract the name of the resource (e.g.: `request.body["tool-name"]`)
	// +optional
	Kubernetes KubernetesAuthorization `json:"kubernetes,omitempty"`
	// CEL defines Common Expression Language (CEL) expressions for verifying authorization
	// E.g.:
	// - request.body["tool-name"] in identity.authorized_tools
	// - identity.group == "admin"
	// +optional
	CEL CELAuthorization `json:"cel,omitempty"`
}

// AuthRule specifies an auth scheme rule for the targeted backend.
type AuthRule struct {
	// Name specifies the name of the auth scheme rule
	// +required
	Name string `json:"name"`
	// Identity specifies the rules for extracting from the request and verifying the identity access token
	// according to one of the supported identity verification types
	// +optional
	Identity IdentityRule `json:"identity,omitempty"`
	// Authorization specifies the rules for extracting from the request and verifying the authorization for the
	// identity to consume the resource according to one of the supported authorization verification types
	// +optional
	Authorization AuthorizationRule `json:"authorization,omitempty"`
}

// AuthSchemeStatus defines the observed state of AuthScheme.
type AuthSchemeStatus struct {
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

// Note: The following types are referenced but their full definitions are omitted for brevity:
// - KubernetesIdentityVerification: Configuration for Kubernetes token verification
// - OIDCIdentityVerification: Configuration for OIDC token verification
// - KubernetesAuthorization: Configuration for Kubernetes RBAC authorization
// - CELAuthorization: Configuration for CEL-based authorization expressions
// - PolicyAncestorStatus: Defined in Gateway API policy attachment specification
```

## Examples

### Example 1 - AuthScheme used in combination with AccessPolicy

This following example extends the one provided at proposal 0008 (_Tool Authorization in Agentic Networking_ > [A complete example](./0008-ToolAuthAPI.md#a-complete-example)). It defines two AuthScheme resources that, used in combination with the AccessPolicies defined in that example, enhance it with the following additional auth rules:

* Service accounts accessing the `mcp-server1` Backend must present a token issued for the `mcp-server1.cluster.local` audience;

* Agents registered as clients from a trusted OIDC server `auth-server.example.com` can access tools from the `mcp-server2` Backend that are included in an `authorized_tools` JWT claim.

```yaml
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: AuthScheme
metadata:
  name: auth-scheme-server1
spec:
  targetRefs:
  - group: agentic.networking.x-k8s.io
    kind: Backend
    name: mcp-server1
  rules:
  - name: kubernetes-token
    identity:
      type: Kubernetes
      kubernetes:
        audiences:
        - mcp-server1.cluster.local
---
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: AuthScheme
metadata:
  name: auth-scheme-server2
spec:
  targetRefs:
  - group: agentic.networking.x-k8s.io
    kind: Backend
    name: mcp-server2
  rules:
  - name: oidc-with-cel
    identity:
      type: OIDC
      oidc:
        issuerUrl: auth-server.example.com
    authorization:
      type: CommonExpressionLanguage
      cel:
        expressions:
        - request.mcp.tool_name in identity.authorized_tools
```

### Example 2 - Standalone AuthScheme

This example shows how an AuthScheme resource can be used standalone–i.e., as an alternative to the AccessPolicy API–for controlling access to MCP tools from the `mcp-server1` Backend, offloading the identity verification and authorization decision to the Kubernetes authentication and RBAC systems respectively.

The sample AuthScheme knows nothing about specific Service Accounts nor specific MCP tools. Any Kubernetes Service Account in the cluster is considered a valid identity. However, only the Service Accounts that are bound to the proper Kubernetes Role can call one of the provided MCP tools. ServiceAccounts, Roles and RoleBindings can be dynamically managed without having to modify the AuthScheme resource.

```yaml
# Define a Backend resource for a MCP server `mcp-server1`, which runs in the K8s cluster and provides tools `add` and `subtract`
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: Backend
metadata:
  name: mcp-server1
spec:
  type: MCP
  mcp:
    serviceName: server1-svc
    port: 9000
    path: /mcp
---
# AuthScheme that offloads identity verification and authorization to the Kubernetes authentication and RBAC systems
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: AuthScheme
metadata:
  name: auth-scheme-server1
spec:
  targetRefs:
  - group: agentic.networking.x-k8s.io
    kind: Backend
    name: mcp-server1
  rules:
  - name: kubernetes-auth
    identity:
      type: Kubernetes
      kubernetes: {} # not specifying an audience, so any Kubernetes ServiceAccount is a valid identity
    authorization:
      type: Kubernetes
      kubernetes: # attributes to check permission with the Kubernetes RBAC system either statically defined or extracted from the request using CEL
        user: identity.user.username
        resourceAttributes:
          group: '"agentic.networking.x-k8s.io"'
          resource: '"backends"'
          subresource: '"tools"'
          name: request.mcp.tool_name
          verb: '"call"'
---
# Roles and RoleBindings granting access to Service Accounts `sa1` and `sa2` respectivelly to MCP tools `add` and `subtract`
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: adder
rules:
- apiGroups: ["agentic.networking.x-k8s.io"]
  resources: ["backends"]
  subresources: ["tools"]
  resourceNames: ["mcp-server1/add"]
  verbs: ["call"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: subtractor
rules:
- apiGroups: ["agentic.networking.x-k8s.io"]
  resources: ["backends"]
  subresources: ["tools"]
  resourceNames: ["mcp-server1/subtract"]
  verbs: ["call"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: adders
roleRef:
  kind: Role
  name: adder
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: ServiceAccount
  name: sa1
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: subtractors
roleRef:
  kind: Role
  name: subtractor
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: ServiceAccount
  name: sa2
  namespace: default
```

### Example 3 – Multiple identity providers

This example shows how an AuthScheme can be used to trust more than one identity source.

Because the two exemplified identity sources differ regarding the structure of the JWTs they issue–one sets the `aud` claim as string, while the other uses lists–the example uses CEL to check the audience according to each corresponding data type.

```yaml
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: AuthScheme
metadata:
  name: multiple-idps-auth
spec:
  targetRefs: […]
  rules:
  - name: idp-1
    identity:
      type: OIDC
      oidc:
        issuerUrl: auth-server1.example.com
    authorization:
      type: CommonExpressionLanguage
      cel:
        expressions: # type(identity.aud) == string
        - 'identity.aud == "my-server"'
  - name: idp-2
    identity:
      type: OIDC
      oidc:
        issuerUrl: auth-server2.example.com
    authorization:
      type: CommonExpressionLanguage
      cel:
        expressions: # type(identity.aud) == list
        - '"my-server" in identity.aud'
```

## Special considerations for the implementation

### Common Expression Language (CEL) for authorization

Common Expression Language (CEL) expressions in AuthScheme resources have access to a structured context that provides information about the request and the verified identity. Understanding this context is essential for writing effective authorization rules.

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

The `identity` object contains claims extracted from the verified access token:

- For Kubernetes tokens: it's the response of the TokenReview request used to validated the token.
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

### Kubernetes RBAC for agentic networking authorization

The AuthScheme API enables offloading authorization decisions to the Kubernetes RBAC system (as demonstrated in [Example 2](#example-2---standalone-authscheme)). This approach offers compelling advantages for managing access control to agentic networking resources, but also requires careful consideration of operational impacts.

#### Motivations to use Kubernetes RBAC for agentic authorization

- **Platform-native authorization system:** Kubernetes RBAC is an authorization system that comes with the platform itself—as opposed to being implementation-specific. This makes access control configurations less obscure and more portable across different Kubernetes distributions and implementations. By using RBAC, users establish the Kubernetes platform as the single source of truth for all authorization decisions in their cluster, creating consistency between infrastructure access control and agentic networking access control.

- **Simplified permission management:** Using Kubernetes RBAC eliminates the need to repeat identical sets of identities across multiple AccessPolicy objects. When multiple agents require the same set of permissions and/or can consume resources from multiple backends, users can simplify this to a common rule that translates to "check it with this single source of truth." For example, instead of maintaining N separate AccessPolicy resources that enumerate the same identities for each Backend, users can create a single Role and bind it to multiple ServiceAccounts through RoleBindings. Updating permissions becomes significantly simpler: modifying one RoleBinding is far more maintainable than updating N policy objects scattered across the cluster.

- **Role-Based Access Control vs. Access Control Lists:** RBAC is fundamentally different from ACL (Access Control List) based systems. With RBAC, users can leverage roles as reusable permission templates and use Kubernetes user groups as grouping mechanisms, providing better organizational scalability. This doesn't sacrifice granularity—users can still implement fine-grained authorization for specific agents when needed by creating targeted Roles and RoleBindings. The system allows expressing both broad patterns ("all agents in the 'data-processors' group can call any tool from mcp-server1") and specific exceptions ("agent-x can only call the 'read' tool") within the same authorization framework.

- **Standardized language and tooling:** Kubernetes RBAC standardizes the language used to manage all access control within a Kubernetes system. Platform operators, security teams, and developers already familiar with Roles, RoleBindings, and ServiceAccounts can apply that same knowledge to agentic networking authorization. This reduces the learning curve and allows teams to use existing tooling, audit processes, and security policies designed for Kubernetes RBAC. Authorization decisions for agent tool access are expressed using the same constructs as authorization for accessing Deployments, Secrets, or any other Kubernetes resource.

#### Caveats and operational considerations

- **Increased API server load:** The primary operational concern when using Kubernetes RBAC for agentic networking authorization is the additional traffic generated to the Kubernetes API server. Each authorization check requires a SubjectAccessReview API request to validate whether the agent's ServiceAccount has permission to access the requested resource. This authorization traffic competes with the usual cluster management operations, including:
  - Pod lifecycle management
  - Controller reconciliation loops
  - Custom resource updates from operators
  - User kubectl commands
  - Admission webhook calls

  In environments with high-frequency agent operations—such as agents that make hundreds or thousands of tool calls per minute—this can create significant load on the API server. The impact is especially pronounced in clusters that already experience high API server utilization from numerous controllers and operators.

- **Abusive Role and RoleBinding writing permissions:** When using Kubernetes RBAC for agentic networking authorization, cluster users with permissions to create Role and RoleBinding resources could maliciously or inadvertently abuse those privileges by declaring permissions beyond what's needed for the agentic networking authorization use case. Because the `apiGroup`, `resource`, and `subresource` fields in RBAC rules by default accept any value, a user with sufficient permissions could declare a rule that grants access to sensitive cluster resources—for example, granting read access to all Secrets in the namespace or modify permissions on critical workloads. To mitigate this risk, cluster administrators are encouraged to:
  1. Prefer granting write permissions over Roles and RoleBindings rather than ClusterRoles and ClusterRoleBindings. This narrows the blast radius of abusing the permissions to the scope of a single namespace instead of cluster-wide.
  2. Consider implementing a ValidatingAdmissionPolicy that limits the usage of Roles and RoleBindings to authorizing specific kinds of resources only. For example, restrict rules to only allow `apiGroups: ["agentic.networking.x-k8s.io"]` and `resources: ["backends"]` to prevent privilege escalation beyond agentic networking resources.

#### Recommendations for production use

Users should deploy Kubernetes RBAC-based authorization with caution and consider the following operational practices:

- **Monitor API server metrics:** Establish baseline metrics for API server request rates, latency, and resource utilization before enabling RBAC-based authorization. Monitor these metrics continuously to detect degradation.

- **Consider high availability deployment**: For production workloads that rely on Kubernetes RBAC for agentic networking authorization, consider deploying the Kubernetes API server in a high availability (HA) configuration. This distributes the authorization check load across multiple API server instances and provides resilience against API server failures.

- **Rate limiting and backpressure**: Implement rate limiting on the authorization enforcement side to prevent unbounded SubjectAccessReview request bursts. Consider implementing backpressure mechanisms that slow down agent operations when API server latency increases.

- **Evaluate authorization patterns**: Not all authorization patterns benefit equally from RBAC offloading. Static, infrequently-changing authorization policies may be better served by AccessPolicy resources, while highly dynamic scenarios with frequently-changing roles and bindings are better candidates for RBAC delegation.

- **Test under load**: Before deploying RBAC-based authorization to production, conduct load testing to understand the API server impact under realistic agent workload conditions.

When used appropriately and with proper infrastructure planning, Kubernetes RBAC provides a powerful, platform-native approach to managing authorization for agentic networking resources. The key is balancing the operational simplicity and standardization benefits against the infrastructure requirements needed to handle the increased API server load.

### Security considerations

Implementations of the AuthScheme API must carefully consider the following security aspects to maintain a secure agentic networking environment:

#### Token Validation Best Practices

Kubernetes Tokens:
- Always validate token against the Kubernetes authentication system (TokenReview API)
- When specifying audiences, prefer specific backend-scoped audiences (e.g., `mcp-server1.cluster.local`) rather than generic ones to prevent token reuse across backends

OIDC Tokens:
- Implement proper OIDC discovery to fetch issuer metadata and public keys from the `/.well-known/openid-configuration` endpoint
- Validate the issuer URL (`iss` claim) exactly matches the configured `issuerUrl` in the AuthScheme
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

- Combine AuthScheme with AccessPolicy: Use AuthScheme for identity verification and leverage AccessPolicy for additional resource-level authorization when appropriate
- Implement rate limiting: Protect against brute-force token validation attempts
- Enable audit logging: Log all authentication and authorization decisions for security monitoring and incident response
- Regular security reviews: Periodically review AuthScheme configurations, especially CEL expressions and trusted issuer lists
- Principle of least privilege: Grant only the minimum necessary permissions to agents and regularly review role bindings

## Prior Art

See [Kuadrant’s AuthPolicy](./0008-ToolAuthAPI.md#kuadrants-authpolicy) and [Envoy Gateway’s SecurityPolicy](./0008-ToolAuthAPI.md#envoy-gateways-securitypolicy).
