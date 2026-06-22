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
	"sort"

	rbacconfigv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticv1alpha1 "sigs.k8s.io/kube-agentic-networking/api/v1alpha1"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
	helpersv1alpha1 "sigs.k8s.io/kube-agentic-networking/pkg/helpers"
)

// buildGatewayLevelRBACFilters finds all AccessPolicies targeting the Gateway and translates them into HTTP filters.
func (t *Translator) buildGatewayLevelRBACFilters(gateway *gatewayv1.Gateway) ([]*hcm.HttpFilter, error) {
	gwPolicies, err := t.findAccessPoliciesForTarget(gatewayv1.GroupName, "Gateway", gateway.Namespace, gateway.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to find Gateway access policies: %w", err)
	}

	var filters []*hcm.HttpFilter
	var extAuthPolicy *agenticv1alpha1.XAccessPolicy
	var allowPolicies []*agenticv1alpha1.XAccessPolicy

	for _, policy := range gwPolicies {
		if policy.Spec.Action == agenticv1alpha1.ActionTypeExternalAuth {
			if extAuthPolicy == nil {
				extAuthPolicy = policy
			}
		} else if policy.Spec.Action == agenticv1alpha1.ActionTypeAllow {
			allowPolicies = append(allowPolicies, policy)
		}
	}

	// 1. Handle ExternalAuth policy (at most one)
	if extAuthPolicy != nil {
		rbacProto := t.buildRBACConfigWithCommonPolicies(extAuthPolicy)
		rbacTypedConfig, err := anypb.New(rbacProto)
		if err != nil {
			return nil, err
		}
		filters = append(filters, &hcm.HttpFilter{
			Name: constants.GatewayExtAuthRBACFilterName,
			ConfigType: &hcm.HttpFilter_TypedConfig{
				TypedConfig: rbacTypedConfig,
			},
		})
	}

	// 2. Handle all Allow policies (merged into one filter)
	if len(allowPolicies) > 0 {
		rbacProto := t.mergeAllowPoliciesToRBAC(allowPolicies)
		rbacTypedConfig, err := anypb.New(rbacProto)
		if err != nil {
			return nil, err
		}
		filters = append(filters, &hcm.HttpFilter{
			Name: constants.GatewayAllowRBACFilterName,
			ConfigType: &hcm.HttpFilter_TypedConfig{
				TypedConfig: rbacTypedConfig,
			},
		})
	}

	return filters, nil
}

// buildBackendLevelRBACFilters creates placeholder RBAC filters for backends.
// These will be overridden at the cluster level by actual policies.
func (t *Translator) buildBackendLevelRBACFilters() ([]*hcm.HttpFilter, error) {
	var filters []*hcm.HttpFilter
	rbacProto := &rbacv3.RBAC{}
	rbacTypedConfig, err := anypb.New(rbacProto)
	if err != nil {
		return nil, err
	}

	filters = append(filters, &hcm.HttpFilter{
		Name: constants.BackendExtAuthRBACFilterName,
		ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: rbacTypedConfig,
		},
	})

	filters = append(filters, &hcm.HttpFilter{
		Name: constants.BackendAllowRBACFilterName,
		ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: rbacTypedConfig,
		},
	})

	return filters, nil
}

// buildBackendLevelRBACOverrides creates the TypedPerFilterConfig for a cluster, specifically for the RBAC filter overrides.
func (t *Translator) buildBackendLevelRBACOverrides(backend *agenticv0alpha0.XBackend) (map[string]*anypb.Any, error) {
	perFilterConfig := make(map[string]*anypb.Any)

	// 1. Find and sort AccessPolicies targeting the Backend.
	backendPolicies, err := t.findAccessPoliciesForTarget(agenticv0alpha0.GroupName, "XBackend", backend.Namespace, backend.Name)
	if err != nil {
		return nil, err
	}

	var extAuthPolicy *agenticv1alpha1.XAccessPolicy
	var allowPolicies []*agenticv1alpha1.XAccessPolicy

	for _, policy := range backendPolicies {
		if policy.Spec.Action == agenticv1alpha1.ActionTypeExternalAuth {
			if extAuthPolicy == nil {
				extAuthPolicy = policy
			}
		} else if policy.Spec.Action == agenticv1alpha1.ActionTypeAllow {
			allowPolicies = append(allowPolicies, policy)
		}
	}

	// 1. Handle ExternalAuth policy (at most one)
	if extAuthPolicy != nil {
		rbacProto := t.buildRBACConfigWithCommonPolicies(extAuthPolicy)
		rbacPerRouteProto := &rbacv3.RBACPerRoute{
			Rbac: rbacProto,
		}
		rbacTypedConfig, err := anypb.New(rbacPerRouteProto)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal RBACPerRoute proto: %w", err)
		}
		perFilterConfig[constants.BackendExtAuthRBACFilterName] = rbacTypedConfig
	}

	// 2. Handle all Allow policies (merged into one filter)
	if len(allowPolicies) > 0 {
		rbacProto := t.mergeAllowPoliciesToRBAC(allowPolicies)
		rbacPerRouteProto := &rbacv3.RBACPerRoute{
			Rbac: rbacProto,
		}
		rbacTypedConfig, err := anypb.New(rbacPerRouteProto)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal RBACPerRoute proto: %w", err)
		}
		perFilterConfig[constants.BackendAllowRBACFilterName] = rbacTypedConfig
	}

	return perFilterConfig, nil
}

// buildRBACConfigWithCommonPolicies generates an RBAC config for an AccessPolicy.
// It includes the common policies needed for MCP session management to avoid blocking basic operations.
func (t *Translator) buildRBACConfigWithCommonPolicies(accessPolicy *agenticv1alpha1.XAccessPolicy) *rbacv3.RBAC {
	rbacConfig := t.translateAccessPolicyToRBAC(accessPolicy)

	// Add common policies to avoid blocking basic MCP operations.
	// These are added to the 'Rules' section which is where allowed traffic is defined.
	addPolicyToRBACRules(rbacConfig, constants.AllowMCPSessionClosePolicyName, buildAllowMCPSessionClosePolicy())
	addPolicyToRBACRules(rbacConfig, constants.AllowAnyoneToInitializeAndListToolsPolicyName, buildAllowAnyoneToInitializeAndListToolsPolicy())
	addPolicyToRBACRules(rbacConfig, constants.AllowHTTPGetPolicyName, buildAllowHTTPGetPolicy())

	return rbacConfig
}

func (t *Translator) mergeAllowPoliciesToRBAC(policies []*agenticv1alpha1.XAccessPolicy) *rbacv3.RBAC {
	rbacConfig := &rbacv3.RBAC{}

	for _, policy := range policies {
		for _, rule := range policy.Spec.Rules {
			policyName := rule.Name
			source := t.ruleSourceToPrincipalName(policy.Namespace, rule.Source)

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

			if rule.Authorization != nil {
				switch rule.Authorization.Type {
				case agenticv1alpha1.AuthorizationRuleTypeInline:
					if permission := t.translateMCPToRBACPermission(&rule.Authorization.MCP); permission != nil {
						rbacPolicy.Permissions = []*rbacconfigv3.Permission{permission}
					}
				case agenticv1alpha1.AuthorizationRuleTypeCEL:
					if rule.Authorization.CEL != nil {
						ast, err := CompileCelExpression(rule.Authorization.CEL.Expression)
						if err != nil {
							klog.Errorf("Failed to compile CEL expression %q: %v", rule.Authorization.CEL.Expression, err)
							continue
						}
						rbacPolicy.Condition = ast.Expr()
						rbacPolicy.Permissions = []*rbacconfigv3.Permission{buildToolsCallMethodPermission()}
					}
				}
			}

			if len(rbacPolicy.GetPermissions()) == 0 {
				rbacPolicy.Permissions = []*rbacconfigv3.Permission{buildAnyPermission()}
			}

			addPolicyToRBACRules(rbacConfig, policyName, rbacPolicy)
			addPolicyToRBACShadowRules(rbacConfig, policyName, rbacPolicy)
		}
	}

	addPolicyToRBACRules(rbacConfig, constants.AllowMCPSessionClosePolicyName, buildAllowMCPSessionClosePolicy())
	addPolicyToRBACRules(rbacConfig, constants.AllowAnyoneToInitializeAndListToolsPolicyName, buildAllowAnyoneToInitializeAndListToolsPolicy())
	addPolicyToRBACRules(rbacConfig, constants.AllowHTTPGetPolicyName, buildAllowHTTPGetPolicy())

	return rbacConfig
}

// findAccessPoliciesForTarget finds all AccessPolicies that target the given resource.
// It returns only accepted policies.
// TODO: Indexing AccessPolicies by their target refs for more efficient lookups.
// https://github.com/kubernetes-sigs/kube-agentic-networking/issues/168
func (t *Translator) findAccessPoliciesForTarget(group, kind, namespace, name string) ([]*agenticv1alpha1.XAccessPolicy, error) {
	// List all AccessPolicies in the target's namespace.
	allAccessPolicies, err := t.accessPolicyLister.XAccessPolicies(namespace).List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to list AccessPolicies in namespace %s: %w", namespace, err)
	}

	var policies []*agenticv1alpha1.XAccessPolicy
	for _, accessPolicy := range allAccessPolicies {
		// Only consider policies that have been accepted by the controller.
		if !helpersv1alpha1.IsXAccessPolicyAccepted(accessPolicy) {
			continue
		}

		for _, targetRef := range accessPolicy.Spec.TargetRefs {
			if string(targetRef.Group) == group && string(targetRef.Kind) == kind && string(targetRef.Name) == name {
				policies = append(policies, accessPolicy)
				break
			}
		}
	}

	// Sort policies by action first (ExternalAuth before Allow), then creation timestamp (oldest first). Break ties by name for deterministic output.
	sort.Slice(policies, func(i, j int) bool {
		if policies[i].Spec.Action != policies[j].Spec.Action {
			return policies[i].Spec.Action == agenticv1alpha1.ActionTypeExternalAuth
		}
		if policies[i].CreationTimestamp.Time.Equal(policies[j].CreationTimestamp.Time) {
			return policies[i].Name < policies[j].Name
		}
		return policies[i].CreationTimestamp.Time.Before(policies[j].CreationTimestamp.Time)
	})

	return policies, nil
}

// convertSAtoSPIFFEID constructs a standard SPIFFE ID for a Kubernetes ServiceAccount.
// Format: spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>
func convertSAtoSPIFFEID(trustDomain, namespace, saName string) string {
	return fmt.Sprintf(constants.SpiffeIDFormat, trustDomain, namespace, saName)
}

func (t *Translator) translateAccessPolicyToRBAC(accessPolicy *agenticv1alpha1.XAccessPolicy) *rbacv3.RBAC {
	rbacConfig := &rbacv3.RBAC{}

	// Each AccessRule in the XAccessPolicy is translated into a named policy within the Envoy RBAC filter.
	for _, rule := range accessPolicy.Spec.Rules {
		policyName := rule.Name

		source := t.ruleSourceToPrincipalName(accessPolicy.Namespace, rule.Source)

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

		if rule.Authorization != nil {
			switch rule.Authorization.Type {
			case agenticv1alpha1.AuthorizationRuleTypeInline:
				// TODO: Only MCP is currently supported. Add support for more generic inline auth in the future
				if permission := t.translateMCPToRBACPermission(&rule.Authorization.MCP); permission != nil {
					rbacPolicy.Permissions = []*rbacconfigv3.Permission{permission}
				}
			case agenticv1alpha1.AuthorizationRuleTypeCEL:
				if rule.Authorization.CEL != nil {
					ast, err := CompileCelExpression(rule.Authorization.CEL.Expression)
					if err != nil {
						klog.Errorf("Failed to compile CEL expression %q: %v", rule.Authorization.CEL.Expression, err)
						continue
					}
					rbacPolicy.Condition = ast.Expr()
					rbacPolicy.Permissions = []*rbacconfigv3.Permission{buildToolsCallMethodPermission()}
				}
			}
		}

		// Shadow rules serve two purposes depending on the action type:
		// - ExternalAuth: RBAC_DENY shadow rules write dynamic metadata used as a gate to fire the ext_authz call.
		// - Allow: RBAC_ALLOW shadow rules mirror enforcement so shadow stats expose which rule matched for tracing.
		// Handle ExternalAuth at policy level
		if accessPolicy.Spec.Action == agenticv1alpha1.ActionTypeExternalAuth && accessPolicy.Spec.ExternalAuth != nil {
			hash, err := externalAuthUniqueID(accessPolicy.Spec.ExternalAuth)
			if err != nil {
				klog.Errorf("Failed to generate unique ID for externalAuth config in AccessPolicy %s/%s: %v", accessPolicy.Namespace, accessPolicy.Name, err)
				continue
			}
			rbacConfig.ShadowRulesStatPrefix = fmt.Sprintf("%s_%s_", constants.ExternalAuthzShadowRulePrefix, hash)

			// Ensure permissions is never empty for shadow rule too.
			// Spec guidance: If omitted, all access from the specified source is allowed.
			if len(rbacPolicy.GetPermissions()) == 0 {
				rbacPolicy.Permissions = []*rbacconfigv3.Permission{buildAnyPermission()}
			}

			addPolicyToRBACShadowRulesForExtAuth(rbacConfig, policyName, rbacPolicy)
			// Ensure the regular Rules section transparently allows all traffic through so that secondary policies evaluate non-matching streams.
			allowAllPolicy := &rbacconfigv3.Policy{
				Principals:  []*rbacconfigv3.Principal{buildAnyPrincipal()},
				Permissions: []*rbacconfigv3.Permission{buildAnyPermission()},
			}
			addPolicyToRBACRules(rbacConfig, policyName, allowAllPolicy)
		} else {
			// Action is Allow
			// Ensure permissions is never empty to satisfy Envoy's schema validation (min_items: 1).
			// Spec guidance: If omitted, all access from the specified source is allowed.
			if len(rbacPolicy.GetPermissions()) == 0 {
				rbacPolicy.Permissions = []*rbacconfigv3.Permission{buildAnyPermission()}
			}
			addPolicyToRBACRules(rbacConfig, policyName, rbacPolicy)
			addPolicyToRBACShadowRules(rbacConfig, policyName, rbacPolicy)
		}
	}

	return rbacConfig
}

func (t *Translator) translateMCPToRBACPermission(mcp *agenticv1alpha1.MCPAttributes) *rbacconfigv3.Permission {
	if mcp == nil || len(mcp.Methods) == 0 {
		return buildAnyPermission()
	}

	var methodPermissions []*rbacconfigv3.Permission
	for _, method := range mcp.Methods {
		methodPermissions = append(methodPermissions, translateMCPMethodToRBACPermission(method))
	}

	if len(methodPermissions) == 1 {
		return methodPermissions[0]
	}

	return &rbacconfigv3.Permission{
		Rule: &rbacconfigv3.Permission_OrRules{
			OrRules: &rbacconfigv3.Permission_Set{
				Rules: methodPermissions,
			},
		},
	}
}

func translateMCPMethodToRBACPermission(method agenticv1alpha1.MCPMethod) *rbacconfigv3.Permission {
	// Match method name
	methodMatcher := &rbacconfigv3.Permission{
		Rule: &rbacconfigv3.Permission_SourcedMetadata{
			SourcedMetadata: &rbacconfigv3.SourcedMetadata{
				MetadataMatcher: &matcherv3.MetadataMatcher{
					Filter: constants.MCPProxyFilterName,
					Path:   []*matcherv3.MetadataMatcher_PathSegment{{Segment: &matcherv3.MetadataMatcher_PathSegment_Key{Key: "method"}}},
					Value:  buildMCPMethodStringMatcher(string(method.Name)),
				},
			},
		},
	}

	if len(method.Params) == 0 {
		return methodMatcher
	}

	// Match params (assuming they are values for "name")
	var paramMatchers []*matcherv3.ValueMatcher
	for _, param := range method.Params {
		paramMatchers = append(paramMatchers, &matcherv3.ValueMatcher{
			MatchPattern: &matcherv3.ValueMatcher_StringMatch{
				StringMatch: &matcherv3.StringMatcher{
					MatchPattern: &matcherv3.StringMatcher_Exact{Exact: string(param)},
				},
			},
		})
	}

	var paramsMatcher *matcherv3.ValueMatcher
	if len(paramMatchers) == 1 {
		paramsMatcher = paramMatchers[0]
	} else {
		paramsMatcher = &matcherv3.ValueMatcher{
			MatchPattern: &matcherv3.ValueMatcher_OrMatch{OrMatch: &matcherv3.OrMatcher{ValueMatchers: paramMatchers}},
		}
	}

	paramPermission := &rbacconfigv3.Permission{
		Rule: &rbacconfigv3.Permission_SourcedMetadata{
			SourcedMetadata: &rbacconfigv3.SourcedMetadata{
				MetadataMatcher: &matcherv3.MetadataMatcher{
					Filter: constants.MCPProxyFilterName,
					Path:   []*matcherv3.MetadataMatcher_PathSegment{{Segment: &matcherv3.MetadataMatcher_PathSegment_Key{Key: "params"}}, {Segment: &matcherv3.MetadataMatcher_PathSegment_Key{Key: "name"}}},
					Value:  paramsMatcher,
				},
			},
		},
	}

	return &rbacconfigv3.Permission{
		Rule: &rbacconfigv3.Permission_AndRules{
			AndRules: &rbacconfigv3.Permission_Set{
				Rules: []*rbacconfigv3.Permission{methodMatcher, paramPermission},
			},
		},
	}
}

func buildMCPMethodStringMatcher(name string) *matcherv3.ValueMatcher {
	if name == "tools" || name == "prompts" || name == "resources" {
		return &matcherv3.ValueMatcher{
			MatchPattern: &matcherv3.ValueMatcher_StringMatch{
				StringMatch: &matcherv3.StringMatcher{
					MatchPattern: &matcherv3.StringMatcher_Prefix{Prefix: name + "/"},
				},
			},
		}
	}
	return &matcherv3.ValueMatcher{
		MatchPattern: &matcherv3.ValueMatcher_StringMatch{
			StringMatch: &matcherv3.StringMatcher{
				MatchPattern: &matcherv3.StringMatcher_Exact{Exact: name},
			},
		},
	}
}

// ruleSourceToPrincipalName converts an AccessRule source into a SPIFFE ID string.
func (t *Translator) ruleSourceToPrincipalName(policyNamespace string, source agenticv1alpha1.AccessRuleSource) string {
	switch source.Type {
	case agenticv1alpha1.AuthorizationSourceTypeSPIFFE:
		if source.SPIFFE != nil {
			return string(*source.SPIFFE)
		}
	case agenticv1alpha1.AuthorizationSourceTypeServiceAccount:
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

// addPolicyToRBACShadowRules adds the policy to ShadowRules with RBAC_ALLOW, mirroring enforcement so shadow stats
// expose the matching rule for tracing.
func addPolicyToRBACShadowRules(rbacConfig *rbacv3.RBAC, policyName string, policy *rbacconfigv3.Policy) {
	if rbacConfig.GetShadowRules() == nil {
		rbacConfig.ShadowRules = &rbacconfigv3.RBAC{
			Action:   rbacconfigv3.RBAC_ALLOW,
			Policies: map[string]*rbacconfigv3.Policy{},
		}
	}
	rbacConfig.ShadowRules.Policies[policyName] = policy
}

// addPolicyToRBACShadowRulesForExtAuth uses RBAC_DENY to trigger ext_authz from emitted stats.
func addPolicyToRBACShadowRulesForExtAuth(rbacConfig *rbacv3.RBAC, policyName string, policy *rbacconfigv3.Policy) {
	if rbacConfig.GetShadowRules() == nil {
		rbacConfig.ShadowRules = &rbacconfigv3.RBAC{
			Action:   rbacconfigv3.RBAC_DENY,
			Policies: map[string]*rbacconfigv3.Policy{},
		}
	}
	rbacConfig.ShadowRules.Policies[policyName] = policy
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
									Header: &routev3.HeaderMatcher{Name: constants.MCPSessionIDHeader, HeaderMatchSpecifier: &routev3.HeaderMatcher_PresentMatch{PresentMatch: true}},
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
					Filter: constants.MCPProxyFilterName,
					Path:   []*matcherv3.MetadataMatcher_PathSegment{{Segment: &matcherv3.MetadataMatcher_PathSegment_Key{Key: "method"}}},
					Value:  &matcherv3.ValueMatcher{MatchPattern: &matcherv3.ValueMatcher_StringMatch{StringMatch: &matcherv3.StringMatcher{MatchPattern: &matcherv3.StringMatcher_Exact{Exact: constants.ToolsCallMethod}}}},
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
											Filter: constants.MCPProxyFilterName,
											Path:   []*matcherv3.MetadataMatcher_PathSegment{{Segment: &matcherv3.MetadataMatcher_PathSegment_Key{Key: "method"}}},
											Value: &matcherv3.ValueMatcher{
												MatchPattern: &matcherv3.ValueMatcher_OrMatch{
													OrMatch: &matcherv3.OrMatcher{
														ValueMatchers: []*matcherv3.ValueMatcher{
															{MatchPattern: &matcherv3.ValueMatcher_StringMatch{StringMatch: &matcherv3.StringMatcher{MatchPattern: &matcherv3.StringMatcher_Exact{Exact: constants.InitializeMethod}}}},
															{MatchPattern: &matcherv3.ValueMatcher_StringMatch{StringMatch: &matcherv3.StringMatcher{MatchPattern: &matcherv3.StringMatcher_Exact{Exact: constants.InitializedMethod}}}},
															{MatchPattern: &matcherv3.ValueMatcher_StringMatch{StringMatch: &matcherv3.StringMatcher{MatchPattern: &matcherv3.StringMatcher_Exact{Exact: constants.ToolsListMethod}}}},
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
