/*
Copyright 2025 The Kubernetes Authors.

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

package translator

import (
	"fmt"

	rbacconfigv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"k8s.io/apimachinery/pkg/labels"
	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticlisters "sigs.k8s.io/kube-agentic-networking/k8s/client/listers/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

const (
	// allowMCPSessionClosePolicyName is the name of the RBAC policy that allows agents to close MCP sessions.
	allowMCPSessionClosePolicyName = "allow-mcp-session-close"

	// allowAnyoneToInitializeAndListToolsPolicyName is the name of the RBAC policy that allows anyone to initialize a session and list available tools.
	allowAnyoneToInitializeAndListToolsPolicyName = "allow-anyone-to-initialize-and-list-tools"
	initializeMethod                              = "initialize"
	initializedMethod                             = "notifications/initialized"
	toolsListMethod                               = "tools/list"

	// allowHTTPGet is the name of the RBAC policy that allows an HTTP GET to the MCP endpoint for SSE stream.
	allowHTTPGet = "allow-http-get"

	mcpSessionIDHeader = "mcp-session-id"
	toolsCallMethod    = "tools/call"
	mcpProxyFilterName = "mcp_proxy"
)

// rbacConfigFromAccessPolicy generates all RBAC policies for a given backend, including common policies
// and those derived from AccessPolicy resources.
func rbacConfigFromAccessPolicy(accessPolicyLister agenticlisters.XAccessPolicyLister, backend *agenticv0alpha0.XBackend) (*rbacv3.RBAC, error) {
	var rbacPolicies = make(map[string]*rbacconfigv3.Policy)

	// Add AuthPolicy-derived RBAC policies.
	// Currently, we assume only one AuthPolicy targets a given backend.
	accessPolicy, err := findAccessPolicyForBackend(backend, accessPolicyLister)
	if err != nil {
		return nil, err
	}
	if accessPolicy != nil {
		rbacPolicies = translateAccessPolicyToRBAC(accessPolicy, backend)
	}
	// It's deny-by-default (a.k.a ALLOW action), we explicitly allow necessary
	// MCP operations for all backends. These policies are essential for MCP
	// session management and tool initialization.
	rbacPolicies[allowMCPSessionClosePolicyName] = buildAllowMCPSessionClosePolicy()
	rbacPolicies[allowAnyoneToInitializeAndListToolsPolicyName] = buildAllowAnyoneToInitializeAndListToolsPolicy()
	rbacPolicies[allowHTTPGet] = buildAllowHTTPGetPolicy()

	rbacConfig := &rbacv3.RBAC{
		Rules: &rbacconfigv3.RBAC{
			Action:   rbacconfigv3.RBAC_ALLOW,
			Policies: rbacPolicies,
		},
	}

	return rbacConfig, nil
}

// findAccessPolicyForBackend finds the AccessPolicy that targets the given backend.
// It assumes that there is only one AccessPolicy for each backend.
func findAccessPolicyForBackend(backend *agenticv0alpha0.XBackend, accessPolicyLister agenticlisters.XAccessPolicyLister) (*agenticv0alpha0.XAccessPolicy, error) {
	// List all AccessPolicies in the Backend's namespace.
	allAccessPolicies, err := accessPolicyLister.XAccessPolicies(backend.Namespace).List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to list AccessPolicies in namespace %s: %w", backend.Namespace, err)
	}

	// Find the first AuthPolicy that targets this specific backend.
	// We assume only one AccessPolicy will target a given backend.
	// TODO: Enforce this uniqueness constraint at the API level or merge multiple policies if needed.
	for _, accessPolicy := range allAccessPolicies {
		for _, targetRef := range accessPolicy.Spec.TargetRefs {
			if targetRef.Kind == "XBackend" && string(targetRef.Name) == backend.Name {
				return accessPolicy, nil
			}
		}
	}
	return nil, nil // No AccessPolicy found for the backend.
}

func translateAccessPolicyToRBAC(accessPolicy *agenticv0alpha0.XAccessPolicy, backend *agenticv0alpha0.XBackend) map[string]*rbacconfigv3.Policy {
	policies := make(map[string]*rbacconfigv3.Policy)

	for i, rule := range accessPolicy.Spec.Rules {
		policyName := fmt.Sprintf(constants.RBACPolicyNameFormat, backend.Namespace, backend.Name, i)
		var principalIDs []*rbacconfigv3.Principal

		var allSources []string
		if rule.Source.SPIFFE != nil {
			allSources = append(allSources, string(*rule.Source.SPIFFE))
		}
		if rule.Source.ServiceAccount != nil {
			ns := rule.Source.ServiceAccount.Namespace
			if ns == "" {
				ns = accessPolicy.Namespace
			}
			allSources = append(allSources, fmt.Sprintf("system:serviceaccount:%s:%s", ns, rule.Source.ServiceAccount.Name))
		}

		if len(allSources) > 0 {
			var sourcePrincipals []*rbacconfigv3.Principal
			for _, source := range allSources {
				sourcePrincipal := &rbacconfigv3.Principal{
					Identifier: &rbacconfigv3.Principal_Header{
						Header: &routev3.HeaderMatcher{
							Name: "x-user-role",
							HeaderMatchSpecifier: &routev3.HeaderMatcher_StringMatch{
								StringMatch: &matcherv3.StringMatcher{
									MatchPattern: &matcherv3.StringMatcher_Exact{Exact: source},
								},
							},
						},
					},
				}
				sourcePrincipals = append(sourcePrincipals, sourcePrincipal)
			}
			principalIDs = append(principalIDs, &rbacconfigv3.Principal{
				Identifier: &rbacconfigv3.Principal_OrIds{
					OrIds: &rbacconfigv3.Principal_Set{Ids: sourcePrincipals},
				},
			})
		}

		// Build permissions based on tools if specified
		var permissions []*rbacconfigv3.Permission
		if len(rule.Tools) > 0 {
			var toolValueMatchers []*matcherv3.ValueMatcher
			for _, tool := range rule.Tools {
				toolValueMatchers = append(toolValueMatchers, &matcherv3.ValueMatcher{
					MatchPattern: &matcherv3.ValueMatcher_StringMatch{
						StringMatch: &matcherv3.StringMatcher{
							MatchPattern: &matcherv3.StringMatcher_Exact{Exact: tool},
						},
					},
				})
			}

			var toolsMatcher *matcherv3.ValueMatcher
			if len(toolValueMatchers) == 1 {
				toolsMatcher = toolValueMatchers[0]
			} else {
				toolsMatcher = &matcherv3.ValueMatcher{
					MatchPattern: &matcherv3.ValueMatcher_OrMatch{OrMatch: &matcherv3.OrMatcher{ValueMatchers: toolValueMatchers}},
				}
			}

			permissions = append(permissions, &rbacconfigv3.Permission{
				Rule: &rbacconfigv3.Permission_AndRules{
					AndRules: &rbacconfigv3.Permission_Set{
						Rules: []*rbacconfigv3.Permission{
							{
								Rule: &rbacconfigv3.Permission_SourcedMetadata{
									SourcedMetadata: &rbacconfigv3.SourcedMetadata{
										MetadataMatcher: &matcherv3.MetadataMatcher{
											Filter: mcpProxyFilterName,
											Path:   []*matcherv3.MetadataMatcher_PathSegment{{Segment: &matcherv3.MetadataMatcher_PathSegment_Key{Key: "method"}}},
											Value:  &matcherv3.ValueMatcher{MatchPattern: &matcherv3.ValueMatcher_StringMatch{StringMatch: &matcherv3.StringMatcher{MatchPattern: &matcherv3.StringMatcher_Exact{Exact: toolsCallMethod}}}},
										},
									},
								},
							},
							{
								Rule: &rbacconfigv3.Permission_SourcedMetadata{
									SourcedMetadata: &rbacconfigv3.SourcedMetadata{
										MetadataMatcher: &matcherv3.MetadataMatcher{
											Filter: mcpProxyFilterName,
											Path:   []*matcherv3.MetadataMatcher_PathSegment{{Segment: &matcherv3.MetadataMatcher_PathSegment_Key{Key: "params"}}, {Segment: &matcherv3.MetadataMatcher_PathSegment_Key{Key: "name"}}},
											Value:  toolsMatcher,
										},
									},
								},
							},
						},
					},
				},
			})
		}

		policies[policyName] = &rbacconfigv3.Policy{
			Principals:  principalIDs,
			Permissions: permissions,
		}
	}
	return policies
}

// buildAllowMCPSessionClosePolicy creates the RBAC policy that allows agents to close MCP sessions.
func buildAllowMCPSessionClosePolicy() *rbacconfigv3.Policy {
	return &rbacconfigv3.Policy{
		Principals: []*rbacconfigv3.Principal{
			{
				Identifier: &rbacconfigv3.Principal_AndIds{
					AndIds: &rbacconfigv3.Principal_Set{
						Ids: []*rbacconfigv3.Principal{
							{ // Condition 1: The HTTP method must be DELETE
								Identifier: &rbacconfigv3.Principal_Header{
									Header: &routev3.HeaderMatcher{
										Name: ":method",
										HeaderMatchSpecifier: &routev3.HeaderMatcher_StringMatch{
											StringMatch: &matcherv3.StringMatcher{
												MatchPattern: &matcherv3.StringMatcher_Exact{Exact: "DELETE"},
											},
										},
									},
								},
							},
							{ // Condition 2: The 'mcp-session-id' header must exist
								Identifier: &rbacconfigv3.Principal_Header{
									Header: &routev3.HeaderMatcher{Name: mcpSessionIDHeader, HeaderMatchSpecifier: &routev3.HeaderMatcher_PresentMatch{PresentMatch: true}},
								},
							},
						},
					},
				},
			},
		},
		Permissions: []*rbacconfigv3.Permission{
			{
				// If the principal (the request's identity) matches, allow it.
				Rule: &rbacconfigv3.Permission_Any{
					Any: true,
				},
			},
		},
	}
}

// buildAllowAnyoneToInitializeAndListToolsPolicy creates the RBAC policy that allows anyone to
// initialize a session and list available tools.
func buildAllowAnyoneToInitializeAndListToolsPolicy() *rbacconfigv3.Policy {
	return &rbacconfigv3.Policy{
		Principals: []*rbacconfigv3.Principal{
			{
				Identifier: &rbacconfigv3.Principal_Any{
					Any: true,
				},
			},
		},
		Permissions: []*rbacconfigv3.Permission{
			{
				Rule: &rbacconfigv3.Permission_AndRules{
					AndRules: &rbacconfigv3.Permission_Set{
						Rules: []*rbacconfigv3.Permission{
							{
								Rule: &rbacconfigv3.Permission_SourcedMetadata{
									SourcedMetadata: &rbacconfigv3.SourcedMetadata{
										MetadataMatcher: &matcherv3.MetadataMatcher{
											Filter: mcpProxyFilterName,
											Path:   []*matcherv3.MetadataMatcher_PathSegment{{Segment: &matcherv3.MetadataMatcher_PathSegment_Key{Key: "method"}}},
											Value: &matcherv3.ValueMatcher{
												MatchPattern: &matcherv3.ValueMatcher_OrMatch{
													OrMatch: &matcherv3.OrMatcher{
														ValueMatchers: []*matcherv3.ValueMatcher{
															{MatchPattern: &matcherv3.ValueMatcher_StringMatch{StringMatch: &matcherv3.StringMatcher{MatchPattern: &matcherv3.StringMatcher_Exact{Exact: initializeMethod}}}},
															{MatchPattern: &matcherv3.ValueMatcher_StringMatch{StringMatch: &matcherv3.StringMatcher{MatchPattern: &matcherv3.StringMatcher_Exact{Exact: initializedMethod}}}},
															{MatchPattern: &matcherv3.ValueMatcher_StringMatch{StringMatch: &matcherv3.StringMatcher{MatchPattern: &matcherv3.StringMatcher_Exact{Exact: toolsListMethod}}}},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// This policy explicitly allows GET requests for streamable HTTP transports.
// In the MCP protocol, after an initial POST handshake, a long-lived GET request
// is established to receive server-sent events (SSE). Without this rule, the RBAC
// filter would implicitly deny these GET requests, leading to a 403 Forbidden error.
// https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#streamable-http
func buildAllowHTTPGetPolicy() *rbacconfigv3.Policy {
	return &rbacconfigv3.Policy{
		Principals: []*rbacconfigv3.Principal{
			{
				Identifier: &rbacconfigv3.Principal_Any{
					Any: true,
				},
			},
		},
		Permissions: []*rbacconfigv3.Permission{
			{
				Rule: &rbacconfigv3.Permission_Header{
					Header: &routev3.HeaderMatcher{
						Name: ":method",
						HeaderMatchSpecifier: &routev3.HeaderMatcher_StringMatch{
							StringMatch: &matcherv3.StringMatcher{
								MatchPattern: &matcherv3.StringMatcher_Exact{Exact: "GET"},
							},
						},
					},
				},
			},
		},
	}
}
