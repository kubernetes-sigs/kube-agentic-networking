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

package translator

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	rbacconfigv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
)

const testTrustDomain = "cluster.local"

type expectedRule struct {
	principals  []string
	permissions []string
}

func TestTranslateAccessPolicyToRBAC(t *testing.T) {
	tests := []struct {
		name                string
		accessPolicy        *agenticv0alpha0.XAccessPolicy
		backend             *agenticv0alpha0.XBackend
		expectedRules       map[string]expectedRule
		expectedShadowRules map[string]expectedRule
	}{
		{
			name: "single rule with specific name",
			accessPolicy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "policy-1",
				},
				Spec: agenticv0alpha0.AccessPolicySpec{
					Rules: []agenticv0alpha0.AccessRule{
						{
							Name: "allow-all",
							Source: agenticv0alpha0.Source{
								Type: agenticv0alpha0.AuthorizationSourceTypeSPIFFE,
								SPIFFE: func() *agenticv0alpha0.AuthorizationSourceSPIFFE {
									s := agenticv0alpha0.AuthorizationSourceSPIFFE("spiffe://example.com/ns/default/sa/default")
									return &s
								}(),
							},
						},
					},
				},
			},
			backend: &agenticv0alpha0.XBackend{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "backend-1",
				},
			},
			expectedRules: map[string]expectedRule{
				"allow-all": {principals: []string{"spiffe://example.com/ns/default/sa/default"}},
			},
		},
		{
			name: "multiple rules",
			accessPolicy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "policy-2",
				},
				Spec: agenticv0alpha0.AccessPolicySpec{
					Rules: []agenticv0alpha0.AccessRule{
						{
							Name: "rule-1",
							Source: agenticv0alpha0.Source{
								Type: agenticv0alpha0.AuthorizationSourceTypeSPIFFE,
								SPIFFE: func() *agenticv0alpha0.AuthorizationSourceSPIFFE {
									s := agenticv0alpha0.AuthorizationSourceSPIFFE("spiffe://example.com/ns/default/sa/foo")
									return &s
								}(),
							},
						},
						{
							Name: "rule-2",
							Source: agenticv0alpha0.Source{
								Type: agenticv0alpha0.AuthorizationSourceTypeSPIFFE,
								SPIFFE: func() *agenticv0alpha0.AuthorizationSourceSPIFFE {
									s := agenticv0alpha0.AuthorizationSourceSPIFFE("spiffe://example.com/ns/default/sa/bar")
									return &s
								}(),
							},
						},
					},
				},
			},
			backend: &agenticv0alpha0.XBackend{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "backend-1",
				},
			},
			expectedRules: map[string]expectedRule{
				"rule-1": {principals: []string{"spiffe://example.com/ns/default/sa/foo"}},
				"rule-2": {principals: []string{"spiffe://example.com/ns/default/sa/bar"}},
			},
		},
		{
			name: "service account mapping",
			accessPolicy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-1",
					Name:      "policy-sa",
				},
				Spec: agenticv0alpha0.AccessPolicySpec{
					Rules: []agenticv0alpha0.AccessRule{
						{
							Name: "allow-sa",
							Source: agenticv0alpha0.Source{
								Type: agenticv0alpha0.AuthorizationSourceTypeServiceAccount,
								ServiceAccount: &agenticv0alpha0.AuthorizationSourceServiceAccount{
									Name:      "my-sa",
									Namespace: "my-ns",
								},
							},
						},
					},
				},
			},
			backend: &agenticv0alpha0.XBackend{},
			expectedRules: map[string]expectedRule{
				"allow-sa": {principals: []string{convertSAtoSPIFFEID(testTrustDomain, "my-ns", "my-sa")}},
			},
		},
		{
			name: "inline tools rule",
			accessPolicy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "policy-1",
				},
				Spec: agenticv0alpha0.AccessPolicySpec{
					Rules: []agenticv0alpha0.AccessRule{
						{
							Name: "allow-tools-a-and-b",
							Source: agenticv0alpha0.Source{
								Type: agenticv0alpha0.AuthorizationSourceTypeSPIFFE,
								SPIFFE: func() *agenticv0alpha0.AuthorizationSourceSPIFFE {
									s := agenticv0alpha0.AuthorizationSourceSPIFFE("spiffe://example.com/ns/default/sa/default")
									return &s
								}(),
							},
							Authorization: &agenticv0alpha0.AuthorizationRule{
								Type:  agenticv0alpha0.AuthorizationRuleTypeInlineTools,
								Tools: []string{"tool-a", "tool-b"},
							},
						},
					},
				},
			},
			backend: &agenticv0alpha0.XBackend{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "backend-1",
				},
			},
			expectedRules: map[string]expectedRule{
				"allow-tools-a-and-b": {
					principals:  []string{"spiffe://example.com/ns/default/sa/default"},
					permissions: []string{`(metadata["mcp_proxy"]["method"] == "tools/call" && metadata["mcp_proxy"]["params"]["name"] (== "tool-a" || == "tool-b"))`},
				},
			},
		},
		{
			name: "ext_authz rule",
			accessPolicy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "policy-1",
				},
				Spec: agenticv0alpha0.AccessPolicySpec{
					Rules: []agenticv0alpha0.AccessRule{
						{
							Name: "ext-authz-rule",
							Source: agenticv0alpha0.Source{
								Type: agenticv0alpha0.AuthorizationSourceTypeSPIFFE,
								SPIFFE: func() *agenticv0alpha0.AuthorizationSourceSPIFFE {
									s := agenticv0alpha0.AuthorizationSourceSPIFFE("spiffe://example.com/ns/default/sa/default")
									return &s
								}(),
							},
							Authorization: &agenticv0alpha0.AuthorizationRule{
								Type: agenticv0alpha0.AuthorizationRuleTypeExternalAuth,
								ExternalAuth: &gwapiv1.HTTPExternalAuthFilter{
									ExternalAuthProtocol: gwapiv1.HTTPRouteExternalAuthGRPCProtocol,
									BackendRef: gwapiv1.BackendObjectReference{
										Name: "ext-authz-backend",
									},
								},
							},
						},
					},
				},
			},
			backend: &agenticv0alpha0.XBackend{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "backend-1",
				},
			},
			expectedRules: map[string]expectedRule{
				"ext-authz-rule": {
					principals:  []string{"spiffe://example.com/ns/default/sa/default"},
					permissions: []string{`metadata["mcp_proxy"]["method"] == "tools/call"`},
				},
			},
			expectedShadowRules: map[string]expectedRule{
				"ext-authz-rule": {
					principals:  []string{"spiffe://example.com/ns/default/sa/default"},
					permissions: []string{`metadata["mcp_proxy"]["method"] == "tools/call"`},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := &Translator{agenticIdentityTrustDomain: testTrustDomain}
			rbacConfig := tr.translatesAccessPolicyToRBAC(tc.accessPolicy)
			verifyRBACConfigContainsRule(t, rbacConfig.GetRules(), tc.expectedRules)
			verifyRBACConfigContainsRule(t, rbacConfig.GetShadowRules(), tc.expectedShadowRules)
		})
	}
}

func TestConvertSAtoSPIFFEID(t *testing.T) {
	tests := []struct {
		trustDomain string
		namespace   string
		name        string
		want        string
	}{
		{
			trustDomain: "cluster.local",
			namespace:   "ns-1",
			name:        "sa-1",
			want:        "spiffe://cluster.local/ns/ns-1/sa/sa-1",
		},
		{
			trustDomain: "example.com",
			namespace:   "default",
			name:        "builder",
			want:        "spiffe://example.com/ns/default/sa/builder",
		},
	}

	for _, tt := range tests {
		got := convertSAtoSPIFFEID(tt.trustDomain, tt.namespace, tt.name)
		if got != tt.want {
			t.Errorf("convertSAtoSPIFFEID(%q, %q, %q) = %q, want %q", tt.trustDomain, tt.namespace, tt.name, got, tt.want)
		}
	}
}

func verifyRBACConfigContainsRule(t *testing.T, rules *rbacconfigv3.RBAC, expectedRules map[string]expectedRule) {
	policies := rules.GetPolicies()
	if len(policies) != len(expectedRules) {
		t.Errorf("expected %d policies, got %d", len(expectedRules), len(policies))
	}
	for key, expectedRule := range expectedRules {
		if _, ok := policies[key]; !ok {
			t.Errorf("expected policy with key %q not found", key)
		}
		verifyRBACPolicyPrincipals(t, policies[key], expectedRule.principals)
		verifyRBACPolicyPermissions(t, policies[key], expectedRule.permissions)
	}
}

func verifyRBACPolicyPrincipals(t *testing.T, policy *rbacconfigv3.Policy, expectedPrincipals []string) {
	if len(policy.Principals) != len(expectedPrincipals) {
		t.Errorf("expected %d principals, got %d", len(expectedPrincipals), len(policy.Principals))
	}
	foundPrincipals := make(map[string]bool)
	for _, p := range policy.Principals {
		auth := p.GetAuthenticated()
		if auth != nil {
			foundPrincipals[auth.PrincipalName.GetExact()] = true
			if !slices.Contains(expectedPrincipals, auth.PrincipalName.GetExact()) {
				t.Errorf("unexpected principal %q found in policy", auth.PrincipalName.GetExact())
			}
		}
	}
	for _, expected := range expectedPrincipals {
		if !foundPrincipals[expected] {
			t.Errorf("expected principal %q not found in policy", expected)
		}
	}
}

func verifyRBACPolicyPermissions(t *testing.T, policy *rbacconfigv3.Policy, expectedPermissions []string) {
	if len(policy.Permissions) != len(expectedPermissions) {
		t.Errorf("expected %d permissions, got %d", len(expectedPermissions), len(policy.Permissions))
	}
	foundPermissions := make(map[string]bool)
	for _, p := range policy.Permissions {
		permExpr := permissionToExpr(p)
		foundPermissions[permExpr] = true
		if !slices.Contains(expectedPermissions, permExpr) {
			t.Errorf("unexpected permission %q found in policy", permExpr)
		}
	}
	for _, expected := range expectedPermissions {
		if !foundPermissions[expected] {
			t.Errorf("expected permissions %q not found in policy", expected)
		}
	}
}

// permissionToExpr converts a *rbacconfigv3.Permission into a simple string expression
// that can be used for comparison in tests.
func permissionToExpr(p *rbacconfigv3.Permission) string {
	if p == nil {
		return "nil"
	}

	switch rule := p.Rule.(type) {
	case *rbacconfigv3.Permission_Any:
		return "any"

	case *rbacconfigv3.Permission_AndRules:
		if rule.AndRules == nil || len(rule.AndRules.Rules) == 0 {
			return ""
		}
		var exprs []string
		for _, subRule := range rule.AndRules.Rules {
			exprs = append(exprs, permissionToExpr(subRule))
		}
		return "(" + strings.Join(exprs, " && ") + ")"

	case *rbacconfigv3.Permission_OrRules:
		if rule.OrRules == nil || len(rule.OrRules.Rules) == 0 {
			return ""
		}
		var exprs []string
		for _, subRule := range rule.OrRules.Rules {
			exprs = append(exprs, permissionToExpr(subRule))
		}
		return "(" + strings.Join(exprs, " || ") + ")"

	case *rbacconfigv3.Permission_NotRule:
		return fmt.Sprintf("!(%s)", permissionToExpr(rule.NotRule))

	case *rbacconfigv3.Permission_Header:
		if rule.Header == nil {
			return "header_match(nil)"
		}
		headerName := rule.Header.Name
		var matchValue string
		switch match := rule.Header.HeaderMatchSpecifier.(type) {
		case *routev3.HeaderMatcher_StringMatch:
			matchValue = stringMatcherToExpr(match.StringMatch)
		case *routev3.HeaderMatcher_PresentMatch:
			matchValue = ".exists?"
		default:
			matchValue = "unknown_match"
		}
		return fmt.Sprintf("request.header[%q]%s", headerName, matchValue)

	case *rbacconfigv3.Permission_SourcedMetadata:
		if rule.SourcedMetadata == nil || rule.SourcedMetadata.MetadataMatcher == nil {
			return "metadata_match(nil)"
		}
		mm := rule.SourcedMetadata.MetadataMatcher
		filter := mm.Filter
		var pathStr string
		for _, segment := range mm.Path {
			if key, ok := segment.Segment.(*matcherv3.MetadataMatcher_PathSegment_Key); ok {
				pathStr += "[" + fmt.Sprintf("%q", key.Key) + "]"
			}
		}
		var valueStr string
		if mm.Value != nil {
			valueStr = valueMatcherToExpr(mm.Value)
		}
		return fmt.Sprintf("metadata[%q]%s %s", filter, pathStr, valueStr)

	default:
		return fmt.Sprintf("unknown(%T)", rule)
	}
}

// stringMatcherToExpr converts a StringMatcher into a string expression.
func stringMatcherToExpr(sm *matcherv3.StringMatcher) string {
	if sm == nil {
		return "string_match(nil)"
	}

	switch strPattern := sm.MatchPattern.(type) {
	case *matcherv3.StringMatcher_Exact:
		return fmt.Sprintf("== %q", strPattern.Exact)
	case *matcherv3.StringMatcher_Prefix:
		return fmt.Sprintf("startsWith(%q)", strPattern.Prefix)
	case *matcherv3.StringMatcher_Suffix:
		return fmt.Sprintf("endsWith(%q)", strPattern.Suffix)
	default:
		return "string_match"
	}
}

// valueMatcherToExpr converts a ValueMatcher into a string expression.
func valueMatcherToExpr(vm *matcherv3.ValueMatcher) string {
	if vm == nil {
		return "nil"
	}

	switch pattern := vm.MatchPattern.(type) {
	case *matcherv3.ValueMatcher_StringMatch:
		return stringMatcherToExpr(pattern.StringMatch)

	case *matcherv3.ValueMatcher_OrMatch:
		if pattern.OrMatch == nil || len(pattern.OrMatch.ValueMatchers) == 0 {
			return ""
		}
		var exprs []string
		for _, matcher := range pattern.OrMatch.ValueMatchers {
			exprs = append(exprs, valueMatcherToExpr(matcher))
		}
		return "(" + strings.Join(exprs, " || ") + ")"

	default:
		return "unknown_value_matcher"
	}
}
