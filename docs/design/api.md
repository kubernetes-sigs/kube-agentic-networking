# Agentic Networking API

The Agentic Networking API introduces two Custom Resource Definitions (CRDs) to extend the functionality of the Kubernetes Gateway API for agentic use cases.

## XBackend CRD

An `XBackend` resource describes an upstream "tool" server. It can represent either a standard Kubernetes `Service` within the cluster or an external service identified by its FQDN. This resource allows for protocol-specific configuration. For the Model Context Protocol (MCP), it enables defining the specific URL path for MCP traffic.

```go
// api/v0alpha0/backend_types.go

// BackendSpec defines the desired state of Backend.
type BackendSpec struct {
	// MCP defines a MCP backend.
	// +required
	MCP MCPBackend `json:"mcp"`
}

// MCPBackend describes a MCP Backend.
// ServiceName and Hostname cannot be defined at the same time.
// +kubebuilder:validation:ExactlyOneOf=serviceName;hostname
type MCPBackend struct {
	// ServiceName defines the Kubernetes Service name of a MCP backend.
	// +optional
	ServiceName *string `json:"serviceName,omitempty"`

	// Hostname defines the hostname of the external MCP service to connect to.
	// +optional
	Hostname *string `json:"hostname,omitempty"`

	// Port defines the port of the backend endpoint.
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// Path is the URL path of the MCP backend for MCP traffic.
	// A MCP backend may serve both MCP traffic and non-MCP traffic.
	// If not specified, the default is /mcp.
	// +optional
	// +kubebuilder:default:=/mcp
	Path string `json:"path,omitempty"`
}
```

An `XBackend` resource is referenced by an `HTTPRoute` as a backend, allowing traffic from a `Gateway` to be routed to it.

## XAccessPolicy CRD

An `XAccessPolicy` resource defines the authorization policies for an `XBackend`. It specifies which clients (identified by `ServiceAccount` or SPIFFE ID) are permitted to access which tools on the targeted MCP server.

```go
// api/v0alpha0/accesspolicy_types.go

// AccessPolicySpec defines the desired state of AccessPolicy.
type AccessPolicySpec struct {
	// TargetRefs specifies the targets of the AccessPolicy.
	// An AccessPolicy must target at least one resource.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	// +kubebuilder:validation:XValidation:rule="self.all(x, x.group == 'agentic.prototype.x-k8s.io' && x.kind == 'XBackend')",message="TargetRef must have group agentic.prototype.x-k8s.io group and kind XBackend"
	TargetRefs []gwapiv1.LocalPolicyTargetReferenceWithSectionName `json:"targetRefs"`
	// Rules defines a list of rules to be applied to the target.
	// An AccessPolicy must have at least one rule.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	Rules []AccessRule `json:"rules"`
}

// AccessRule specifies an authorization rule for the targeted backend.
// If the tool list is empty, the rule denies access to all tools from Source.
type AccessRule struct {
	// Source specifies the source of the request.
	// +required
	Source Source `json:"source"`
	// Tools specifies a list of tools.
	// +listType=set
	// +optional
	Tools []string `json:"tools,omitempty"`
}

// Source specifies the source of a request.
type Source struct {
	// +unionDiscriminator
	// +required
	Type AuthorizationSourceType `json:"type"`
	// +optional
	SPIFFE *AuthorizationSourceSPIFFE `json:"spiffe,omitempty"`
	// +optional
	ServiceAccount *AuthorizationSourceServiceAccount `json:"serviceAccount,omitempty"`
}
```

By default, an AI agent can call `initialize`, `notifications/initialized`, and `tools/list`. Any `tools/call` action is denied unless explicitly allowed by an `XAccessPolicy`.
