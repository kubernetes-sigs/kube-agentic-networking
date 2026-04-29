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
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/api/v0alpha0/helpers"
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

	// spiffeIDFormat is the standard SPIFFE ID format for Kubernetes workloads.
	// Format: spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>
	spiffeIDFormat = "spiffe://%s/ns/%s/sa/%s"

	// externalAuthzShadowRulePrefix is the prefix for stat names of shadow rules generated from AccessPolicies with ExternalAuthz.
	// This allows us to monitor the presence of RBAC rules that are evaluated (though not enforced), with the purpose of signaling the need to call an ext_authz service.
	externalAuthzShadowRulePrefix = "access_policy_ext_authz"
)

// buildGatewayLevelRBACFilters finds all AccessPolicies targeting the Gateway and translates them into HTTP filters.
func (t *Translator) buildGatewayLevelRBACFilters(gateway *gatewayv1.Gateway) ([]*hcm.HttpFilter, error) {
	gwPolicies, err := t.findAccessPoliciesForTarget(gatewayv1.GroupName, "Gateway", gateway.Namespace, gateway.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to find Gateway access policies: %w", err)
	}
	var filters []*hcm.HttpFilter

	rbacConfigs := t.buildRBACConfigsForPolicies(gwPolicies)

	for _, rbacConfig := range rbacConfigs {
		rbacAny, err := anypb.New(rbacConfig)
		if err != nil {
			return nil, err
		}
		filters = append(filters, &hcm.HttpFilter{
			Name: fmt.Sprintf("%s%d", constants.GatewayRBACFilterNamePrefix, len(filters)+1),
			ConfigType: &hcm.HttpFilter_TypedConfig{
				TypedConfig: rbacAny,
			},
		})
	}

	return filters, nil
}

// buildRBACConfigsForPolicies creates RBAC configs for merged InlineTools and individual ExternalAuth rules.
func (t *Translator) buildRBACConfigsForPolicies(policies []*agenticv0alpha0.XAccessPolicy) []*rbacv3.RBAC {
	mergedInlineToolsRBAC := &rbacv3.RBAC{
		Rules: &rbacconfigv3.RBAC{
			Action:   rbacconfigv3.RBAC_ALLOW,
			Policies: map[string]*rbacconfigv3.Policy{},
		},
	}
	hasInlineToolsRules := false

	var extAuthConfigs []*rbacv3.RBAC

	for _, policy := range policies {
		var extAuthRBAC *rbacv3.RBAC
		hasExtAuthInThisPolicy := false

		for _, rule := range policy.Spec.Rules {
			rbacPolicy, isExternalAuth, extAuthStatPrefix, err := t.translateAccessRuleToRBACPolicy(policy.Namespace, rule)
			if err != nil {
				klog.Errorf("Failed to translate access rule %s in policy %s/%s: %v", rule.Name, policy.Namespace, policy.Name, err)
				continue
			}

			if isExternalAuth {
				hasExtAuthInThisPolicy = true
				if extAuthRBAC == nil {
					extAuthRBAC = &rbacv3.RBAC{
						ShadowRules: &rbacconfigv3.RBAC{
							Action:   rbacconfigv3.RBAC_DENY,
							Policies: map[string]*rbacconfigv3.Policy{},
						},
						ShadowRulesStatPrefix: extAuthStatPrefix,
						Rules: &rbacconfigv3.RBAC{
							Action:   rbacconfigv3.RBAC_ALLOW,
							Policies: map[string]*rbacconfigv3.Policy{},
						},
					}
				}
				extAuthRBAC.ShadowRules.Policies[rule.Name] = rbacPolicy
				extAuthRBAC.Rules.Policies[rule.Name] = rbacPolicy
			} else {
				// InlineTools rule
				prefixedName := fmt.Sprintf("%s.%s.%s", policy.Namespace, policy.Name, rule.Name)
				mergedInlineToolsRBAC.Rules.Policies[prefixedName] = rbacPolicy
				hasInlineToolsRules = true
			}
		}

		if hasExtAuthInThisPolicy {
			// Add common policies to this filter
			t.addCommonPoliciesToRBAC(extAuthRBAC)
			extAuthConfigs = append(extAuthConfigs, extAuthRBAC)
		}
	}

	// Inject merged InlineTools rules into ExternalAuth filters
	if len(extAuthConfigs) > 0 && hasInlineToolsRules {
		for _, extAuthRBAC := range extAuthConfigs {
			for ruleName, routePolicy := range mergedInlineToolsRBAC.GetRules().GetPolicies() {
				extAuthRBAC.Rules.Policies[ruleName] = routePolicy
			}
		}
	}

	// Return logic to avoid redundant filters
	var result []*rbacv3.RBAC
	if len(extAuthConfigs) > 0 {
		result = extAuthConfigs
	} else if hasInlineToolsRules {
		t.addCommonPoliciesToRBAC(mergedInlineToolsRBAC)
		result = []*rbacv3.RBAC{mergedInlineToolsRBAC}
	}

	return result
}

// buildBackendLevelRBACFilters creates placeholder RBAC filters for backends.
// These will be overridden at the cluster level by actual policies.
func (t *Translator) buildBackendLevelRBACFilters(count int) ([]*hcm.HttpFilter, error) {
	var filters []*hcm.HttpFilter
	rbacProto := &rbacv3.RBAC{}
	rbacAny, err := anypb.New(rbacProto)
	if err != nil {
		return nil, err
	}

	for i := 0; i < count; i++ {
		filters = append(filters, &hcm.HttpFilter{
			Name: fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, i+1),
			ConfigType: &hcm.HttpFilter_TypedConfig{
				TypedConfig: rbacAny,
			},
		})
	}
	return filters, nil
}

// calculateMaxBackendRBACFilters determines the maximum number of backend-level RBAC filters
// needed for a Gateway by inspecting all reachable XBackends.
func (t *Translator) calculateMaxBackendRBACFilters(gateway *gatewayv1.Gateway) int {
	// 1. Identify all HTTPRoutes targeting this Gateway.
	routes := t.getHTTPRoutesForGateway(gateway)

	// 2. Identify all unique XBackends referenced by these routes.
	backendNames := make(map[types.NamespacedName]struct{})
	for _, route := range routes {
		for _, rule := range route.Spec.Rules {
			for _, beRef := range rule.BackendRefs {
				if beRef.Group != nil && *beRef.Group == agenticv0alpha0.GroupName &&
					beRef.Kind != nil && *beRef.Kind == "XBackend" {
					ns := route.Namespace
					if beRef.Namespace != nil {
						ns = string(*beRef.Namespace)
					}
					backendNames[types.NamespacedName{Namespace: ns, Name: string(beRef.Name)}] = struct{}{}
				}
			}
		}
	}

	maxCount := 0

	// 3. For each backend, count its needed filters after merging.
	for beKey := range backendNames {
		policies, err := t.findAccessPoliciesForTarget(agenticv0alpha0.GroupName, "XBackend", beKey.Namespace, beKey.Name)
		if err != nil {
			klog.Errorf("Failed to count policies for backend %s: %v", beKey, err)
			continue
		}

		hasInlineTools := false
		extAuthCount := 0

		for _, policy := range policies {
			hasPolicyExtAuth := false

			for _, rule := range policy.Spec.Rules {
				if rule.Authorization != nil && rule.Authorization.Type == agenticv0alpha0.AuthorizationRuleTypeExternalAuth {
					hasPolicyExtAuth = true
				} else {
					hasInlineTools = true
				}
			}
			// only increase the count by 1 for each policy that contains ExternalAuth,
			// as all rules of this type in a policy are handled by a single filter.
			if hasPolicyExtAuth {
				extAuthCount++
			}
		}

		count := extAuthCount
		if count == 0 && hasInlineTools {
			count = 1
		}

		if count > maxCount {
			maxCount = count
		}
	}

	return maxCount
}

// buildBackendLevelRBACOverrides creates the TypedPerFilterConfig for a cluster, specifically for the RBAC filter overrides.
func (t *Translator) buildBackendLevelRBACOverrides(backend *agenticv0alpha0.XBackend) (map[string]*anypb.Any, error) {
	perFilterConfig := make(map[string]*anypb.Any)

	// 1. Find and sort AccessPolicies targeting the Backend.
	backendPolicies, err := t.findAccessPoliciesForTarget(agenticv0alpha0.GroupName, "XBackend", backend.Namespace, backend.Name)
	if err != nil {
		return nil, err
	}

	rbacConfigs := t.buildRBACConfigsForPolicies(backendPolicies)

	for _, rbacConfig := range rbacConfigs {
		rbacPerRouteProto := &rbacv3.RBACPerRoute{
			Rbac: rbacConfig,
		}
		rbacAny, err := anypb.New(rbacPerRouteProto)
		if err != nil {
			return nil, err
		}
		filterName := fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, len(perFilterConfig)+1)
		perFilterConfig[filterName] = rbacAny
	}

	return perFilterConfig, nil
}

// buildRBACConfigWithCommonPolicies generates an RBAC config for an AccessPolicy.
// It includes the common policies needed for MCP session management to avoid blocking basic operations.
func (t *Translator) buildRBACConfigWithCommonPolicies(accessPolicy *agenticv0alpha0.XAccessPolicy) *rbacv3.RBAC {
	rbacConfig := t.translateAccessPolicyToRBAC(accessPolicy)

	// Add common policies to avoid blocking basic MCP operations.
	t.addCommonPoliciesToRBAC(rbacConfig)

	return rbacConfig
}

// addCommonPoliciesToRBAC adds the common policies needed for MCP session management to the RBAC config.
func (t *Translator) addCommonPoliciesToRBAC(rbacConfig *rbacv3.RBAC) {
	addPolicyToRBACRules(rbacConfig, allowMCPSessionClosePolicyName, buildAllowMCPSessionClosePolicy())
	addPolicyToRBACRules(rbacConfig, allowAnyoneToInitializeAndListToolsPolicyName, buildAllowAnyoneToInitializeAndListToolsPolicy())
	addPolicyToRBACRules(rbacConfig, allowHTTPGet, buildAllowHTTPGetPolicy())
}

// findAccessPoliciesForTarget finds all AccessPolicies that target the given resource.
// It returns only accepted policies.
// TODO: Indexing AccessPolicies by their target refs for more efficient lookups.
// https://github.com/kubernetes-sigs/kube-agentic-networking/issues/168
func (t *Translator) findAccessPoliciesForTarget(group, kind, namespace, name string) ([]*agenticv0alpha0.XAccessPolicy, error) {
	// List all AccessPolicies in the target's namespace.
	allAccessPolicies, err := t.accessPolicyLister.XAccessPolicies(namespace).List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to list AccessPolicies in namespace %s: %w", namespace, err)
	}

	var policies []*agenticv0alpha0.XAccessPolicy
	for _, accessPolicy := range allAccessPolicies {
		// Only consider policies that have been accepted by the controller.
		if !helpers.IsXAccessPolicyAccepted(accessPolicy) {
			continue
		}

		for _, targetRef := range accessPolicy.Spec.TargetRefs {
			if string(targetRef.Group) == group && string(targetRef.Kind) == kind && string(targetRef.Name) == name {
				policies = append(policies, accessPolicy)
				break
			}
		}
	}

	return policies, nil
}

// convertSAtoSPIFFEID constructs a standard SPIFFE ID for a Kubernetes ServiceAccount.
// Format: spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>
func convertSAtoSPIFFEID(trustDomain, namespace, saName string) string {
	return fmt.Sprintf(spiffeIDFormat, trustDomain, namespace, saName)
}

func (t *Translator) translateAccessPolicyToRBAC(accessPolicy *agenticv0alpha0.XAccessPolicy) *rbacv3.RBAC {
	rbacConfig := &rbacv3.RBAC{}

	// Each AccessRule in the XAccessPolicy is translated into a named policy within the Envoy RBAC filter.
	for _, rule := range accessPolicy.Spec.Rules {
		rbacPolicy, isExternalAuth, extAuthStatPrefix, err := t.translateAccessRuleToRBACPolicy(accessPolicy.Namespace, rule)
		if err != nil {
			klog.Errorf("Failed to translate access rule %s in policy %s/%s: %v", rule.Name, accessPolicy.Namespace, accessPolicy.Name, err)
			continue
		}

		if isExternalAuth {
			rbacConfig.ShadowRulesStatPrefix = extAuthStatPrefix
			addPolicyToRBACShadowRules(rbacConfig, rule.Name, rbacPolicy)
		}

		addPolicyToRBACRules(rbacConfig, rule.Name, rbacPolicy)
	}

	return rbacConfig
}

// translateAccessRuleToRBACPolicy translates a single AccessRule into an Envoy RBAC Policy.
// It returns the policy, a boolean indicating if it is an ExternalAuth rule, the shadow rule stat prefix if applicable, and an error.
func (t *Translator) translateAccessRuleToRBACPolicy(policyNamespace string, rule agenticv0alpha0.AccessRule) (*rbacconfigv3.Policy, bool, string, error) {
	source := t.ruleSourceToPrincipalName(policyNamespace, rule.Source)

	var principalIDs []*rbacconfigv3.Principal
	if source != "" {
		principalIDs = append(principalIDs, &rbacconfigv3.Principal{
			Identifier: &rbacconfigv3.Principal_Authenticated_{
				Authenticated: &rbacconfigv3.Principal_Authenticated{
					PrincipalName: &matcherv3.StringMatcher{
						MatchPattern: &matcherv3.StringMatcher_Exact{Exact: source},
					},
				},
			},
		})
	}

	if len(principalIDs) == 0 {
		principalIDs = []*rbacconfigv3.Principal{buildAnyPrincipal()}
	}

	rbacPolicy := &rbacconfigv3.Policy{
		Principals: principalIDs,
	}

	isExternalAuth := false
	shadowRulesStatPrefix := ""

	if rule.Authorization != nil {
		switch rule.Authorization.Type {
		case agenticv0alpha0.AuthorizationRuleTypeInlineTools:
			if permission := translateInlineToolsToRBACPermission(rule.Authorization.Tools); permission != nil {
				rbacPolicy.Permissions = []*rbacconfigv3.Permission{permission}
			}
		case agenticv0alpha0.AuthorizationRuleTypeExternalAuth:
			if rule.Authorization.ExternalAuth != nil {
				hash, err := externalAuthUniqueID(rule.Authorization.ExternalAuth)
				if err != nil {
					return nil, false, "", fmt.Errorf("failed to generate unique ID for externalAuth config: %w", err)
				}
				isExternalAuth = true
				shadowRulesStatPrefix = fmt.Sprintf("%s_%s_", externalAuthzShadowRulePrefix, hash)
				rbacPolicy.Permissions = []*rbacconfigv3.Permission{buildToolsCallMethodPermission()}
			}
		}
	}

	// Ensure permissions is never empty to satisfy Envoy's schema validation (min_items: 1).
	// If authorization is omitted or unsupported, we default to a "Disallow tool call" permission.
	if len(rbacPolicy.GetPermissions()) == 0 {
		rbacPolicy.Permissions = []*rbacconfigv3.Permission{buildDisallowToolCallPermission()}
	}

	return rbacPolicy, isExternalAuth, shadowRulesStatPrefix, nil
}

// ruleSourceToPrincipalName converts an AccessRule source into a SPIFFE ID string.
func (t *Translator) ruleSourceToPrincipalName(policyNamespace string, source agenticv0alpha0.Source) string {
	switch source.Type {
	case agenticv0alpha0.AuthorizationSourceTypeSPIFFE:
		if source.SPIFFE != nil {
			return string(*source.SPIFFE)
		}
	case agenticv0alpha0.AuthorizationSourceTypeServiceAccount:
		if source.ServiceAccount != nil {
			ns := source.ServiceAccount.Namespace
			if ns == "" {
				ns = policyNamespace
			}
			// Convert K8s ServiceAccount to SPIFFE ID
			return convertSAtoSPIFFEID(t.agenticIdentityTrustDomain, ns, source.ServiceAccount.Name)
		}
	}
	return ""
}

// addPolicyToRBACRules mutates the RBAC config by adding the given policy to the Rules section with the specified name.
func addPolicyToRBACRules(rbacConfig *rbacv3.RBAC, policyName string, policy *rbacconfigv3.Policy) {
	if rbacConfig.GetRules() == nil {
		rbacConfig.Rules = &rbacconfigv3.RBAC{
			Action:   rbacconfigv3.RBAC_ALLOW,
			Policies: map[string]*rbacconfigv3.Policy{},
		}
	}
	rbacConfig.Rules.Policies[policyName] = policy
}

// addPolicyToRBACShadowRules mutates the RBAC config by adding the given policy to the ShadowRules section with the specified name.
func addPolicyToRBACShadowRules(rbacConfig *rbacv3.RBAC, policyName string, policy *rbacconfigv3.Policy) {
	if rbacConfig.GetShadowRules() == nil {
		rbacConfig.ShadowRules = &rbacconfigv3.RBAC{
			Action:   rbacconfigv3.RBAC_DENY, // the action for the shadow rule doesn't really matter in this case since we only use it to trigger ext_authz from emitted stats
			Policies: map[string]*rbacconfigv3.Policy{},
		}
	}
	rbacConfig.ShadowRules.Policies[policyName] = policy
}

// buildDisallowToolCallPermission returns a permission that matches anything EXCEPT tool calls.
// This is used to satisfy Envoy RBAC's requirement that the permissions list must have
// at least one item (min_items: 1) while effectively denying tool access.
func buildDisallowToolCallPermission() *rbacconfigv3.Permission {
	return &rbacconfigv3.Permission{
		Rule: &rbacconfigv3.Permission_NotRule{
			NotRule: buildToolsCallMethodPermission(),
		},
	}
}

func translateInlineToolsToRBACPermission(tools []string) *rbacconfigv3.Permission {
	if len(tools) == 0 {
		return buildDisallowToolCallPermission()
	}

	var toolValueMatchers []*matcherv3.ValueMatcher
	for _, tool := range tools {
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

	return &rbacconfigv3.Permission{
		Rule: &rbacconfigv3.Permission_AndRules{
			AndRules: &rbacconfigv3.Permission_Set{
				Rules: []*rbacconfigv3.Permission{
					buildToolsCallMethodPermission(),
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
	}
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
		Permissions: []*rbacconfigv3.Permission{buildAnyPermission()},
	}
}

func buildAnyPermission() *rbacconfigv3.Permission {
	return &rbacconfigv3.Permission{
		Rule: &rbacconfigv3.Permission_Any{
			Any: true,
		},
	}
}

func buildToolsCallMethodPermission() *rbacconfigv3.Permission {
	return &rbacconfigv3.Permission{
		Rule: &rbacconfigv3.Permission_SourcedMetadata{
			SourcedMetadata: &rbacconfigv3.SourcedMetadata{
				MetadataMatcher: &matcherv3.MetadataMatcher{
					Filter: mcpProxyFilterName,
					Path:   []*matcherv3.MetadataMatcher_PathSegment{{Segment: &matcherv3.MetadataMatcher_PathSegment_Key{Key: "method"}}},
					Value:  &matcherv3.ValueMatcher{MatchPattern: &matcherv3.ValueMatcher_StringMatch{StringMatch: &matcherv3.StringMatcher{MatchPattern: &matcherv3.StringMatcher_Exact{Exact: toolsCallMethod}}}},
				},
			},
		},
	}
}

func buildAnyPrincipal() *rbacconfigv3.Principal {
	return &rbacconfigv3.Principal{
		Identifier: &rbacconfigv3.Principal_Any{
			Any: true,
		},
	}
}

// buildAllowAnyoneToInitializeAndListToolsPolicy creates the RBAC policy that allows anyone to
// initialize a session and list available tools.
func buildAllowAnyoneToInitializeAndListToolsPolicy() *rbacconfigv3.Policy {
	return &rbacconfigv3.Policy{
		Principals: []*rbacconfigv3.Principal{buildAnyPrincipal()},
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
		Principals: []*rbacconfigv3.Principal{buildAnyPrincipal()},
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
