# Tool Authorization in Agentic Networking

This proposal defines authorization policies for tool access from AI agents running inside a Kubernetes cluster to MCP servers running in the Kubernetes cluster or outside of the Kubernetes cluster. By default, an AI agent can call initialize, notifications/initialized and tools/list. To enforce a "zero trust" security posture, a tools/call is denied unless it is allowed through the Tool Auth API described in this proposal.

# Non-Goals

The authentication of MCP tool access is not within the scope of this proposal, and will be explored separately in the future.

# Use Cases & Motivation

## Personas

*AI Engineer*: A hands-on builder focused on the end-to-end development, deployment, and optimization of AI agents. They are distinct from ML Researchers and ML Engineers; AI Engineers are product-first, operating on the other side of the LLM Inference Serving API, and are not responsible for training, tuning, or deploying the models themselves.

*AI Platform Engineer:* A builder and operator of the foundational platform that enables AI engineers to develop and deploy agents at scale.

*Tool Developer:* A builder focused on developing MCP tools that can be leveraged by agents.

*AI Security Engineer:* A specialist focused on designing automated safeguards to ensure AI agents operate safely and securely, while sometimes also wearing multiple hats (e.g., policy architect, risk manager, and compliance advisor) ensuring security is integrated across all aspects of AI development and deployment.

## User Journeys

#### Agent Identity

As an AI Engineer, I want to assign a unique, verifiable identity to my agent running in Kubernetes, so that gateways or external systems can securely authenticate it and make authorization decisions.

#### Protocol-Aware Authorization for MCP Tools

As an AI Engineer, I want to create authorization policies to specify which individual tools (e.g., getWeather, sendEmail) my agent is permitted to call on an allow-listed MCP server, so that I can enforce least-privilege access at the specific tool-function level, not just the network endpoint.

# API

The API introduced two new CRDs: Backend for describing a backend in agentic networking and AuthPolicy for describing the authorization policies for backends in agentic networking.

The CRD names may change depending on the OSS feedback.

## Backend CRD

A Backend resource could reference a standard **Kubernetes Service** or an **External FQDN** (Fully Qualified Domain Name). In addition, it allows protocol-specific backend configuration. For example, for a MCP server, it allows configuring the URL path of the MCP backend for MCP traffic, since a MCP backend may serve both MCP traffic and non-MCP traffic. Currently, the only supported backend type is MCP. We can extend this CRD to support other types of backends involved in agentic networking.

A Backend resource can be referenced in HTTPRoute as a HTTP Backend.

```go
// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// Backend is the Schema for the backends API.
type Backend struct {
	metav1.TypeMeta `json:",inline"`
	// metadata is a standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// spec defines the desired state of Backend.
	// +required
	Spec BackendSpec `json:"spec"`
	// status defines the observed state of Backend.
	// +optional
	Status BackendStatus `json:"status,omitempty"`
}

// BackendSpec defines the desired state of Backend.
type BackendSpec struct {
	// Type specifies the type of the backend.
	// Currently, only "MCP" is supported.
	// +required
	Type *BackendType `json:"type"`
	// MCP defines a MCP backend.
	// +optional
	MCP MCPBackend `json:"mcp,omitempty"`
}

// BackendType defines the type of the Backend.
// +kubebuilder:validation:Enum=MCP
type BackendType string

const (
	// BackendTypeMCP defines the type of the backend as MCP.
	BackendTypeMCP BackendType = "MCP"
)

// MCPBackend describes a MCP Backend.
// ServiceName and Hostname cannot be defined at the same time.
// +kubebuilder:validation:ExactlyOneOf=serviceName;hostname
type MCPBackend struct {
	// ServiceName defines the Kubernetes Service name of a MCP backend.
	// +optional
	ServiceName string `json:"serviceName,omitempty"`
	// Hostname defines the hostname of the external MCP service to connect to.
	// +optional
	Hostname string `json:"hostname,omitempty"`
	// Port defines the port of the backend endpoint.
	// +required
	Port int32 `json:"port"`
	// Path is the URL path of the MCP backend for MCP traffic.
	// A MCP backend may serve both MCP traffic and non-MCP traffic.
	// If not specified, the default is /mcp.
	// +optional
	// +kubebuilder:default:=/mcp
	Path string `json:"path,omitempty"`
}

// BackendStatus defines the observed state of Backend.
type BackendStatus struct {
	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties
	// conditions represent the current state of the Backend resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}
```

## AuthPolicy CRD

An AuthPolicy resource defines the authorization policies for a Backend resource. Each AuthPolicy includes a targetRef for a Backend resource and a list of rules. Each rule defines the tools from the MCP backend allowed to be accessed by the specified principals (which can be Kubernetes ServiceAccounts or SPIFFE IDs). In the future, we can authorize agent-to-agent, and agent-to-LLM access in the AuthPolicy resource.

```go
// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// AuthPolicy is the Schema for the authpolicies API.
type AuthPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// metadata is a standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// spec defines the desired state of AuthPolicy.
	// +required
	Spec AuthPolicySpec `json:"spec"`
	// status defines the observed state of AuthPolicy.
	// +optional
	Status AuthPolicyStatus `json:"status,omitempty"`
}

// AuthPolicySpec defines the desired state of AuthPolicy.
type AuthPolicySpec struct {
	// TargetRef specifies the target of the AuthPolicy.
	// Currently, only Backend can be used as a target.
	// +required
	TargetRef gwapiv1.LocalPolicyTargetReference `json:"targetRef"`
	// Rules defines a list of rules to be applied to the target.
	// +required
	Rules []AuthRule `json:"rules"`
	// Action specifies the action to take when a request matches the rules.
	// +kubebuilder:validation:Required
	// +required
	Action AuthPolicyAction `json:"action"`
}

// AuthPolicyAction specifies the action to take.
// Currently, the only supported action is ALLOW.
// +kubebuilder:validation:Enum=ALLOW
type AuthPolicyAction string

const (
	// ActionAllow allows requests that match the policy rules.
	ActionAllow AuthPolicyAction = "ALLOW"
)

// AuthRule specifies an authorization rule for the targeted backend.
// When the action is ALLOW,
//   - requests from Source are permitted to access the listed Tools.
//   - If the tool list is empty, the rule denies access to all tools from Source.
type AuthRule struct {
	// Source specifies the source of the request.
	// +required
	Source Source `json:"source"`
	// Tools specifies a list of tools.
	// +optional
	Tools []string `json:"tools,omitempty"`
}

// Source specifies the source of a request.
// This struct is same as the Source struct defined in https://github.com/kubernetes-sigs/gateway-api/blob/950c6639afd099b7bba4236f8b894ae4b891d26a/geps/gep-3779/index.md#api-design.
//
// At least one field may be set. If multiple fields are set,
// a request matches this Source if it matches
// **any** of the specified criteria (logical OR across fields).
//
// For example, if both `Identities` and `ServiceAccounts` are provided,
// the rule matches a request if either:
// - the request's identity is in `Identities`
// - OR the request's Serviceaccount matches an entry in `ServiceAccounts`.
//
// Each list within the fields (e.g. `Identities`) is itself an OR list.
//
// If this struct is omitted in a rule, it matches any source.
//
// <gateway:util:excludeFromCRD> NOTE: In the future, if there’s a need to express more complex
// logical conditions (e.g. requiring a request to match multiple
// criteria simultaneously—logical AND), we may evolve this API
// to support richer match expressions or logical operators. </gateway:util:excludeFromCRD>
type Source struct {
	// Identities specifies a list of identities that are matched by this rule.
	// A request's identity must be present in this list to match the rule.
	//
	// Identities must be specified as SPIFFE-formatted URIs following the pattern:
	//   spiffe://<trust_domain>/<workload-identifier>
	//
	// While the exact workload identifier structure is implementation-specific,
	// implementations are encouraged to follow the convention of
	// `spiffe://<trust_domain>/ns/<namespace>/sa/<serviceaccount>`
	// when representing Kubernetes workload identities.
	//
	// +optional
	Identities []string `json:"identities,omitempty"`
	// ServiceAccounts specifies a list of Kubernetes Service Accounts that are
	// matched by this rule. A request originating from a pod associated with
	// one of these Serviceaccounts will match the rule.
	//
	// Values must be in one of the following formats:
	//   - "<namespace>/<serviceaccount-name>": A specific Serviceaccount in a namespace.
	//   - "<namespace>/*": All Serviceaccounts in the given namespace.
	//   - "<serviceaccount-name>": a Serviceaccount in the same namespace as the policy.
	//
	// Use of "*" alone (i.e., all Serviceaccounts in all namespaces) is not allowed.
	// To select all Serviceaccounts in the current namespace, use "<namespace>/*" explicitly.
	//
	// Example:
	//   - "default/bookstore" → Matches Serviceaccount "bookstore" in namespace "default"
	//   - "payments/*" → Matches any Serviceaccount in namespace "payments"
	//   - "frontend" → Matches "frontend" Serviceaccount in the same namespace as the policy
	//
	// The ServiceAccounts listed here are expected to exist within the same
	// trust domain as the targeted workload, which in many environments means
	// the same Kubernetes cluster. Cross-cluster or cross-trust-domain access
	// should instead be expressed using the `Identities` field.
	//
	// +optional
	ServiceAccounts []string `json:"serviceAccounts,omitempty"`
}

// AuthPolicyStatus defines the observed state of AuthPolicy.
type AuthPolicyStatus struct {
	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties
	// conditions represent the current state of the AuthPolicy resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}
```

# A complete example

Imagine we have two MCP backends: `mcp-server1` running inside a Kubernetes cluster, and `mcp-server2` running outside of the Kubernetes cluster ([https://docs.devin.ai/work-with-devin/deepwiki-mcp](https://docs.devin.ai/work-with-devin/deepwiki-mcp)). We have two agents running inside the Kubernetes cluster using the Kubernetes Service Account `default/sa1` and `default/sa2`.

* `mcp-server1` has two tools: `add` and `subtract`.

* `mcp-server2` has three tools: `read_wiki_structure`, `read_wiki_contents`, and `ask_question`.

The following example shows how we can utilize AuthPolicy, Backend and HTTPRoute to authorize:

* `default/sa1` has access to the tool `add` and `subtract` provided by `mcp-server1`;

* `default/sa2` has access to the tool `subtract` provided by `mcp-server1`;

* `default/sa2` has access to the tool `read_wiki_structure` provided by `mcp-server2`.

```yaml
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: AuthPolicy
metadata:
  name: auth-policy-server1
spec:
  # AuthPolicy targets a single Backend.
  targetRef:
    group: gateway.networking.x-k8s.io
    kind: Backend
    name: mcp-server1
  action: ALLOW
  rules:
  - source:
      serviceAccounts:
      - "default/sa1"
    tools:
    - "add"
    - "subtract"
  - source:
      serviceAccounts:
      - "default/sa2"
    tools:
    - "subtract"
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: httproute-server1
spec:
  parentRefs:
  - name: agentic-net-gateway
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /mcp-server1/mcp
    filters:
    - type: URLRewrite
      urlRewrite:
        path:
          type: ReplacePrefixMatch
          replacePrefixMatch: /mcp
    backendRefs:
    - name: mcp-server1 # server1 running in the Kubernetes cluster
      group: agentic.networking.x-k8s.io
      kind: Backend
---
# Define a Backend resource for server1, which runs in the K8s cluster.
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
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: AuthPolicy
metadata:
  name: auth-policy-server2
spec:
  targetRef:
    group: gateway.networking.x-k8s.io
    kind: Backend
    name: mcp-server2
  action: ALLOW
  rules:
  - source:
      serviceAccounts:
      - "default/sa2"
    tools:
    - "read_wiki_structure"
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: httproute-server2
spec:
  parentRefs:
  - name: agentic-net-gateway
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /mcp-server2/mcp
    filters:
    - type: URLRewrite
      urlRewrite:
        path:
          type: ReplacePrefixMatch
          replacePrefixMatch: /mcp
    backendRefs:
    - name: mcp-server2
      group: agentic.networking.x-k8s.io
      kind: Backend
---
# Define a Backend resource for server2, which is external.
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: Backend
metadata:
  name: mcp-server2
spec:
  type: MCP
  mcp:
    hostname: mcp.deepwiki.com
    port: 443
    path: /mcp
```

# A note on Envoy-based Implementations

When a [HTTPRouteRule](https://gateway-api.sigs.k8s.io/reference/spec/#httprouterule) has multiple backendRefs. The backendRefs can be translated into the `route.weighted_clusters` field of an Envoy [Route](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#config-route-v3-route). The AuthPolicy for a Backend resource can be translated into a `typed_per_filter_config` [RBAC filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/rbac_filter) for an Envoy cluster under the `route.weighted_clusters` field of the Envoy Route.

For example, if a `HTTPRouteRule` refers to two backends: `backend1` and `backend2`, and a separate `AuthPolicy` resource is defined for both backends. Here is an Envoy config demonstrating how `typed_per_filter_config` RBAC filter can be used
to define authorization policies for each backend.

```
  listeners:
  - name: listener_0
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 10001
    filter_chains:
      - filters:
        - name: envoy.filters.network.http_connection_manager
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
            stat_prefix: ingress_http
            route_config:
              name: local_route
              virtual_hosts:
              - name: local_service
                domains: ["*"]
                routes:
                - match:
                    path: "/mcp"
                  route:
                    weighted_clusters:
                      clusters:
                        - name: backend1
                          weight: 50
                          typed_per_filter_config:
                            envoy.filters.http.rbac:
                              "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBACPerRoute
                              rbac:
                                rules:
                                  action: ALLOW
                                  policies:
								    ... # the policies are translated from the AuthPolicy resource for backend1.
                        - name: backend2
                          weight: 50
                          typed_per_filter_config:
                            envoy.filters.http.rbac:
                              "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBACPerRoute
                              rbac:
                                rules:
                                  action: ALLOW
                                  policies:
								    ... # the policies are translated from the AuthPolicy resource for backend2.
            http_filters:
            - name: envoy.filters.http.rbac
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC
            - name: envoy.filters.http.router
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
  - name: backend1
    ...
  - name: backend2
    ...
```

# Alternative - Backend + Kubernetes RBAC

One alternative is to use a Kubernetes Role to track the permissions for accessing MCP Backends, and use a Kubernetes RoleBinding
to grant the permissions defined in a Role to a ServiceAccount.

Here are the Roles and RoleBindings for the previous [example](#a-complete-example).

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: calculator-add-subtract
rules:
- apiGroups: ["agentic.networking.x-k8s.io"]
  resources: ["backends"]
  resourceNames: ["mcp-server1"]
  verbs: ["add", "subtract"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: calculator-subtract
rules:
- apiGroups: ["agentic.networking.x-k8s.io"]
  resources: ["backends"]
  resourceNames: ["mcp-server1"]
  verbs: ["subtract"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: sa1-calculator-add-subtract-binding
subjects:
- kind: ServiceAccount
  name: sa1
  namespace: default
roleRef:
  kind: Role
  name: calculator-add-subtract
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: sa2-calculator-subtract-binding
subjects:
- kind: ServiceAccount
  name: sa2
  namespace: default
roleRef:
  kind: Role
  name: calculator-subtract
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: read-wiki-structure
rules:
- apiGroups: ["agentic.networking.x-k8s.io"]
  resources: ["backends"]
  resourceNames: ["mcp-server2"]
  verbs: ["read_wiki_structure"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: sa2-read-wiki-structure-binding
subjects:
- kind: ServiceAccount
  name: sa2
  namespace: default
roleRef:
  kind: Role
  name: read-wiki-structure
  apiGroup: rbac.authorization.k8s.io
```

# Prior Art

## Kubernetes NetworkPolicy

Kubernetes [NetworkPolicies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) allow you to specify rules for traffic flow within your cluster, and also between Pods and the outside world. It controls Layer 3 (IP) and Layer 4 (TCP/UDP/SCTP) traffic, and acts like a classic packet-filter firewall. However, it has absolutely no idea what is *inside* the data packets.

## Kubernetes RBAC

Kubernetes [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) is designed to control access to the **Kubernetes API** (verbs like `get`, `list`, `delete` on resources like `Pods`), but using it to control **application-level** access (like specific tools within an MCP Backend) has significant limitations. It does not natively understand or intercept the subsequent protocol traffic (the MCP tool calls) that happens between your agent and the backend, hence cannot prevent an agent from calling a specific tool *after* it has connected to the backend.

## Istio’s AuthorizationPolicy

Istio's [AuthorizationPolicy](https://istio.io/latest/docs/reference/config/security/authorization-policy/) is the primary mechanism for securing services within an Istio service mesh. It allows you to define fine-grained access control rules—L7 "who can do what"—that are enforced by the Envoy proxies. Unlike Kubernetes NetworkPolicies that rely on IP addresses (which can change), Istio uses secure identities. Every workload in the mesh receives a cryptographically verifiable identity (a SPIFFE ID assigned via mTLS certificate).

### **Pros**

#### **Decoupled Security from Application Code**

Developers do not need to write authentication or authorization logic into every microservice. The sidecar (Envoy) handles policy enforcement transparently. Policies can be updated dynamically without restarting applications.

#### **Granular, Layer 7 Awareness**

Unlike standard Kubernetes NetworkPolicies (which only operate at Layer 3/4: IP and Port), Istio understands Layer 7 (HTTP/gRPC). You can create rules based on HTTP methods (GET vs. DELETE), URL paths (`/api/admin` vs. `/api/public`), and request headers (including JWT claims).

#### **Native Zero-Trust Integration**

It tightly integrates with Istio's peer authentication. You can easily base policies on cryptographically verified SPIFFE IDs rather than weak identifiers like IP addresses. Supports a "fail-closed" security posture (default deny) easily, which is essential for zero-trust architectures.

#### **Flexibility (Namespace & Workload Scope)**

Policies can be applied broadly to an entire namespace or narrowly to a specific workload using standard Kubernetes label selectors.

#### **Integration with External Auth**

Supports `CUSTOM` actions to delegate complex decisions to external authorization engines like Open Policy Agent (OPA) or bespoke dedicated auth services.

### **Cons**

#### **Complexity and Learning Curve**

Writing correct policies, especially when combining multiple `ALLOW` and `DENY` rules, can be complex. Misunderstanding the evaluation order can lead to security holes or accidental denial of service.

#### **Debugging Challenges**

When a request is denied, it can sometimes be difficult to immediately determine *which* policy denied it without digging into Envoy proxy logs and understanding RBAC debug logging.

#### **Operational Overhead**

It requires running the Istio control plane and a sidecar proxy next to every workload, which adds CPU/Memory overhead and a small amount of latency to every request.

#### **Potential for Broad Outages (Fail-Closed Risk)**

Because Istio fails closed (if you add one ALLOW policy, everything else is denied), a poorly written policy applied at the wrong scope (e.g., incorrectly targeting an entire namespace) can immediately break all traffic flow in that namespace.

#### **Scalability**

Storing authorization policies as Kubernetes resources inherently faces scalability issues in large clusters due to the sheer number of CR objects, the resulting load on the Kubernetes API server, and the memory overhead for controllers watching these objects.

## Kuadrant’s AuthPolicy

Kuadrant's [AuthPolicy](https://docs.kuadrant.io/dev/kuadrant-operator/doc/overviews/auth/) is a specialized Kubernetes Custom Resource specifically designed to bring complex Authentication (AuthN) and Authorization (AuthZ) to the **Kubernetes Gateway API**.

While Istio's `AuthorizationPolicy` is excellent for mesh-internal (East/West) traffic and basic Gateway security, Kuadrant's `AuthPolicy` is laser-focused on the complex, messy reality of **North/South (Ingress)** traffic at the network edge. It has first-class support for common standards like OIDC, API Keys, User Metadata.

Kuadrant isn't an enforcement engine itself; it's a control plane. When you create a Kuadrant `AuthPolicy`, it configures **Authorino** behind the scenes. **Authorino** is a highly capable "Envoy External Authorization" (ext_authz) server.

### Pros

#### **Native to Gateway API (Policy Attachment)**

It was built from the ground up for the modern Kubernetes Gateway API. It uses the standard **Policy Attachment** model (`targetRef`), allowing different personas (Cluster Ops vs App Devs) to attach policies at different levels (`Gateway` vs `HTTPRoute`) securely and predictably.

#### **Complex Identity Chaining (Pipeline)**

This is its superpower. Unlike native Envoy which prefers a single auth mechanism at a time, Kuadrant (via Authorino) can define a pipeline:

* Step 1: Is there an mTLS cert? If yes, validate and done.
* Step 2: If no cert, is there a JWT? Validate it against Keycloak.
* Step 3: If no JWT, is there an API Key? Check it against a Kubernetes Secret.
* Step 4: If all fail, trigger an OIDC redirect flow to Google Login.

#### **"Batteries Included" for Common Standards**

It has first-class support for common standards like OIDC, API Keys, and User Metadata.

#### **Declarative & GitOps Friendly**

It turns complex, multi-step authentication flows into standard Kubernetes YAML. This makes your entire ingress security posture version-controllable and deployable via ArgoCD or Flux, rather than hidden inside opaque identity provider console settings.

### **Cons**

#### **Latency (The `ext_authz` Hop)**

Because it relies on Envoy's *external authorization* API, every request that hits your Gateway must pause, make a network hop to the Authorino service, wait for a decision, and then resume.

#### **Operational Complexity**

You are adding another control plane to your cluster. You now have to manage:

* The Kuadrant Operator.
* The Authorino highly-available service (if it goes down, your ingress is dead).
* Redis (often required if you use features like rate limiting or caching complex auth decisions).

#### **Learning Curve**

While it abstracts Authorino, effective use still requires understanding how Authorino thinks (Identity -> Metadata -> Authorization -> Response). Debugging why a complex chained auth policy is failing can be difficult compared to a simple "allow all" Istio rule.

## Envoy Gateway’s SecurityPolicy

Envoy Gateway’s [SecurityPolicy](https://gateway.envoyproxy.io/docs/api/extension_types/#securitypolicy) is another Kubernetes Custom Resource, built entirely around the Kubernetes Gateway API and  specifically designed to enforce standard authentication and authorization checks at the network edge. It has native support for CORS, JWT OIDC, basic auth & API Keys, and external authorization for complex scenarios.

# References

* [https://istio.io/latest/docs/reference/config/security/authorization-policy/](https://istio.io/latest/docs/reference/config/security/authorization-policy/)
* [https://docs.kuadrant.io/dev/kuadrant-operator/doc/overviews/auth/](https://docs.kuadrant.io/dev/kuadrant-operator/doc/overviews/auth/)
* [https://gateway.envoyproxy.io/docs/concepts/gateway_api_extensions/security-policy/](https://gateway.envoyproxy.io/docs/concepts/gateway_api_extensions/security-policy/)
* [https://docs.devin.ai/work-with-devin/deepwiki-mcp](https://docs.devin.ai/work-with-devin/deepwiki-mcp)