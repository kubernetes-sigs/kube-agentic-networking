/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package constants

import "time"

const (
	// DefaultExternalAuthPort is the default port for external authorization services if not specified in the BackendRef.
	DefaultExternalAuthPort = 5000

	// URITimeout is the timeout for URI requests.
	URITimeout = 5 * time.Second

	// WellknownJWTAuthnFilter is the name of the well-known JWT authentication filter.
	WellknownJWTAuthnFilter = "envoy.filters.http.jwt_authn"

	// ExternalAuthzShadowRulePrefix is the prefix for stat names of shadow rules generated from AccessPolicies with ExternalAuthz.
	ExternalAuthzShadowRulePrefix = "access_policy_ext_authz"

	// DefaultConnectTimeout is the timeout for new network connections to hosts in the cluster.
	DefaultConnectTimeout = 5 * time.Second

	// MCPSessionIDHeader is the header name for MCP session ID.
	MCPSessionIDHeader = "mcp-session-id"

	// ToolsCallMethod is the method name for calling tools.
	ToolsCallMethod = "tools/call"

	// MCPProxyFilterName is the name of the MCP proxy filter.
	MCPProxyFilterName = "mcp_proxy"

	// InitializeMethod is the method name for session initialization.
	InitializeMethod = "initialize"

	// InitializedMethod is the method name for session initialized notification.
	InitializedMethod = "notifications/initialized"

	// ToolsListMethod is the method name for listing tools.
	ToolsListMethod = "tools/list"

	// DefaultServicePort is the default service port when BackendRef.Port is not set.
	DefaultServicePort = 80

	// AllowMCPSessionClosePolicyName is the name of the RBAC policy that allows agents to close MCP sessions.
	AllowMCPSessionClosePolicyName = "allow-mcp-session-close"

	// AllowAnyoneToInitializeAndListToolsPolicyName is the name of the RBAC policy that allows anyone to initialize a session and list available tools.
	AllowAnyoneToInitializeAndListToolsPolicyName = "allow-anyone-to-initialize-and-list-tools"

	// AllowHTTPGetPolicyName is the name of the RBAC policy that allows an HTTP GET to the MCP endpoint for SSE stream.
	AllowHTTPGetPolicyName = "allow-http-get"

	// SpiffeIDFormat is the standard SPIFFE ID format for Kubernetes workloads.
	// Format: spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>
	SpiffeIDFormat = "spiffe://%s/ns/%s/sa/%s"
)
