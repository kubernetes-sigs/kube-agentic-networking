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
	"testing"

	rbacconfigv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticclient "sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned/fake"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

const (
	testTrustDomain = "cluster.local"
)

var (
	acceptedStatus = agenticv0alpha0.AccessPolicyStatus{
		Ancestors: []gatewayv1.PolicyAncestorStatus{
			{
				Conditions: []metav1.Condition{
					{
						Type:   string(agenticv0alpha0.PolicyConditionAccepted),
						Status: metav1.ConditionTrue,
					},
				},
			},
		},
	}

	rejectedStatus = agenticv0alpha0.AccessPolicyStatus{
		Ancestors: []gatewayv1.PolicyAncestorStatus{
			{
				Conditions: []metav1.Condition{
					{
						Type:   string(agenticv0alpha0.PolicyConditionAccepted),
						Status: metav1.ConditionFalse,
					},
				},
			},
		},
	}
)

type expectedRule struct {
	principal      string
	permissions    []string
	isExternalAuth bool
}

func TestBuildGatewayLevelRBACFilters(t *testing.T) {
	ns := "test-ns"
	gwName := "test-gw"

	tests := []struct {
		name            string
		policies        []runtime.Object
		gatewaysToCheck map[string][]string // gateway name -> expected filter names in order
	}{
		{
			name:     "no policies targeting gateway",
			policies: []runtime.Object{},
			gatewaysToCheck: map[string][]string{
				gwName: {},
			},
		},
		{
			name: "single policy targeting gateway",
			policies: []runtime.Object{
				&agenticv0alpha0.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "gw-policy", Namespace: ns},
					Spec: agenticv0alpha0.AccessPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
							LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
								Group: gatewayv1.Group(gatewayv1.GroupName),
								Kind:  gatewayv1.Kind("Gateway"),
								Name:  gatewayv1.ObjectName(gwName),
							},
						}},
						Rules: []agenticv0alpha0.AccessRule{{Name: "rule-name"}},
					},
					Status: acceptedStatus,
				},
			},
			gatewaysToCheck: map[string][]string{
				gwName: {fmt.Sprintf("%s%d", constants.GatewayRBACFilterNamePrefix, 1)},
			},
		},
		{
			name: "multiple policies targeting the same gateway",
			policies: []runtime.Object{
				&agenticv0alpha0.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "gw-policy-1", Namespace: ns, CreationTimestamp: metav1.Now()},
					Spec: agenticv0alpha0.AccessPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
							LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
								Group: gatewayv1.Group(gatewayv1.GroupName),
								Kind:  gatewayv1.Kind("Gateway"),
								Name:  gatewayv1.ObjectName(gwName),
							},
						}},
						Rules: []agenticv0alpha0.AccessRule{{Name: "rule-name"}},
					},
					Status: acceptedStatus,
				},
				&agenticv0alpha0.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "gw-policy-2", Namespace: ns, CreationTimestamp: metav1.Now()},
					Spec: agenticv0alpha0.AccessPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
							LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
								Group: gatewayv1.Group(gatewayv1.GroupName),
								Kind:  gatewayv1.Kind("Gateway"),
								Name:  gatewayv1.ObjectName(gwName),
							},
						}},
						Rules: []agenticv0alpha0.AccessRule{{Name: "rule-name"}},
					},
					Status: acceptedStatus,
				},
			},
			gatewaysToCheck: map[string][]string{
				gwName: {
					fmt.Sprintf("%s%d", constants.GatewayRBACFilterNamePrefix, 1),
					fmt.Sprintf("%s%d", constants.GatewayRBACFilterNamePrefix, 2),
				},
			},
		},
		{
			name: "one policy targeting multiple gateways",
			policies: []runtime.Object{
				&agenticv0alpha0.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "multi-gw-policy", Namespace: ns},
					Spec: agenticv0alpha0.AccessPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: gatewayv1.Group(gatewayv1.GroupName),
									Kind:  gatewayv1.Kind("Gateway"),
									Name:  gatewayv1.ObjectName(gwName),
								},
							},
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: gatewayv1.Group(gatewayv1.GroupName),
									Kind:  gatewayv1.Kind("Gateway"),
									Name:  "other-gw",
								},
							},
						},
						Rules: []agenticv0alpha0.AccessRule{{Name: "rule-name"}},
					},
					Status: acceptedStatus,
				},
			},
			gatewaysToCheck: map[string][]string{
				gwName:     {fmt.Sprintf("%s%d", constants.GatewayRBACFilterNamePrefix, 1)},
				"other-gw": {fmt.Sprintf("%s%d", constants.GatewayRBACFilterNamePrefix, 1)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agenticClient := agenticclient.NewSimpleClientset(tt.policies...)
			agenticInformerFactory := agenticinformers.NewSharedInformerFactory(agenticClient, 0)
			lister := agenticInformerFactory.Agentic().V0alpha0().XAccessPolicies().Lister()

			for _, p := range tt.policies {
				_ = agenticInformerFactory.Agentic().V0alpha0().XAccessPolicies().Informer().GetIndexer().Add(p)
			}

			tr := &Translator{accessPolicyLister: lister}

			for gwn, expectedNames := range tt.gatewaysToCheck {
				gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: gwn, Namespace: ns}}
				filters, err := tr.buildGatewayLevelRBACFilters(gw)
				if err != nil {
					t.Fatalf("Gateway %s: Failed to build filters: %v", gwn, err)
				}

				if len(filters) != len(expectedNames) {
					t.Errorf("Gateway %s: Expected %d filters, got %d", gwn, len(expectedNames), len(filters))
				}

				for i, f := range filters {
					if f.Name != expectedNames[i] {
						t.Errorf("Gateway %s, Filter %d: expected name %s, got %s", gwn, i, expectedNames[i], f.Name)
					}
				}
			}
		})
	}
}

func TestBuildBackendLevelRBACFilters(t *testing.T) {
	tr := &Translator{maxAccessPoliciesPerTarget: 5}
	filters, err := tr.buildBackendLevelRBACFilters()
	if err != nil {
		t.Fatalf("Failed to build filters: %v", err)
	}

	if len(filters) != 5 {
		t.Errorf("Expected 5 filters, got %d", len(filters))
	}

	for i, f := range filters {
		expectedName := fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, i+1)
		if f.Name != expectedName {
			t.Errorf("Filter %d: expected name %s, got %s", i, expectedName, f.Name)
		}

		// Verify it's an RBAC filter
		rbac := &rbacv3.RBAC{}
		if err := f.GetTypedConfig().UnmarshalTo(rbac); err != nil {
			t.Errorf("Filter %d: failed to unmarshal to RBAC: %v", i, err)
		}
	}
}

func TestBuildBackendLevelRBACOverrides(t *testing.T) {
	ns := "test-ns"
	beName := "test-backend"

	tests := []struct {
		name            string
		policies        []runtime.Object
		backendsToCheck map[string][]string // backend name -> expected filter names in order
	}{
		{
			name:     "no policies targeting backend",
			policies: []runtime.Object{},
			backendsToCheck: map[string][]string{
				beName: {},
			},
		},
		{
			name: "single policy targeting backend",
			policies: []runtime.Object{
				&agenticv0alpha0.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "be-policy", Namespace: ns},
					Spec: agenticv0alpha0.AccessPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
							LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
								Group: gatewayv1.Group(agenticv0alpha0.GroupName),
								Kind:  gatewayv1.Kind("XBackend"),
								Name:  gatewayv1.ObjectName(beName),
							},
						}},
						Rules: []agenticv0alpha0.AccessRule{{Name: "rule-name"}},
					},
					Status: acceptedStatus,
				},
			},
			backendsToCheck: map[string][]string{
				beName: {fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, 1)},
			},
		},
		{
			name: "multiple policies targeting the same backend",
			policies: []runtime.Object{
				&agenticv0alpha0.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "be-policy-1", Namespace: ns, CreationTimestamp: metav1.Now()},
					Spec: agenticv0alpha0.AccessPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
							LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
								Group: gatewayv1.Group(agenticv0alpha0.GroupName),
								Kind:  gatewayv1.Kind("XBackend"),
								Name:  gatewayv1.ObjectName(beName),
							},
						}},
						Rules: []agenticv0alpha0.AccessRule{{Name: "rule-name"}},
					},
					Status: acceptedStatus,
				},
				&agenticv0alpha0.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "be-policy-2", Namespace: ns, CreationTimestamp: metav1.Now()},
					Spec: agenticv0alpha0.AccessPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
							LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
								Group: gatewayv1.Group(agenticv0alpha0.GroupName),
								Kind:  gatewayv1.Kind("XBackend"),
								Name:  gatewayv1.ObjectName(beName),
							},
						}},
						Rules: []agenticv0alpha0.AccessRule{{Name: "rule-name"}},
					},
					Status: acceptedStatus,
				},
			},
			backendsToCheck: map[string][]string{
				beName: {
					fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, 1),
					fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, 2),
				},
			},
		},
		{
			name: "one policy targeting multiple backends",
			policies: []runtime.Object{
				&agenticv0alpha0.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "multi-be-policy", Namespace: ns},
					Spec: agenticv0alpha0.AccessPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: gatewayv1.Group(agenticv0alpha0.GroupName),
									Kind:  gatewayv1.Kind("XBackend"),
									Name:  gatewayv1.ObjectName(beName),
								},
							},
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: gatewayv1.Group(agenticv0alpha0.GroupName),
									Kind:  gatewayv1.Kind("XBackend"),
									Name:  "other-backend",
								},
							},
						},
						Rules: []agenticv0alpha0.AccessRule{{Name: "rule-name"}},
					},
					Status: acceptedStatus,
				},
			},
			backendsToCheck: map[string][]string{
				beName:          {fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, 1)},
				"other-backend": {fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, 1)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agenticClient := agenticclient.NewSimpleClientset(tt.policies...)
			agenticInformerFactory := agenticinformers.NewSharedInformerFactory(agenticClient, 0)
			lister := agenticInformerFactory.Agentic().V0alpha0().XAccessPolicies().Lister()

			for _, p := range tt.policies {
				_ = agenticInformerFactory.Agentic().V0alpha0().XAccessPolicies().Informer().GetIndexer().Add(p)
			}

			tr := &Translator{accessPolicyLister: lister}

			for ben, expectedFilterNames := range tt.backendsToCheck {
				xbackend := &agenticv0alpha0.XBackend{ObjectMeta: metav1.ObjectMeta{Name: ben, Namespace: ns}}

				configs, err := tr.buildBackendLevelRBACOverrides(xbackend)
				if err != nil {
					t.Fatalf("Backend %s: Failed to build configs: %v", ben, err)
				}

				if len(configs) != len(expectedFilterNames) {
					t.Errorf("Backend %s: Expected %d configs, got %d", ben, len(expectedFilterNames), len(configs))
				}

				for _, expectedName := range expectedFilterNames {
					if _, ok := configs[expectedName]; !ok {
						t.Errorf("Backend %s: Expected config for filter %s not found", ben, expectedName)
					}
				}
			}
		})
	}
}

func TestBuildRBACConfigWithCommonPolicies(t *testing.T) {
	tr := &Translator{}
	policy := &agenticv0alpha0.XAccessPolicy{
		Spec: agenticv0alpha0.AccessPolicySpec{
			Rules: []agenticv0alpha0.AccessRule{{Name: "custom-rule"}},
		},
	}

	rbac := tr.buildRBACConfigWithCommonPolicies(policy)

	expectedPolicies := []string{
		"custom-rule",
		allowMCPSessionClosePolicyName,
		allowAnyoneToInitializeAndListToolsPolicyName,
		allowHTTPGet,
	}

	for _, p := range expectedPolicies {
		if _, ok := rbac.Rules.Policies[p]; !ok {
			t.Errorf("Expected policy %s not found", p)
		}
	}
}

func TestFindAccessPoliciesForTarget(t *testing.T) {
	ns := "test-ns"

	policies := []runtime.Object{
		&agenticv0alpha0.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-accepted", Namespace: ns},
			Spec: agenticv0alpha0.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: gatewayv1.Group(agenticv0alpha0.GroupName),
						Kind:  gatewayv1.Kind("XBackend"),
						Name:  "my-backend",
					},
				}},
			},
			Status: acceptedStatus,
		},
		&agenticv0alpha0.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-rejected", Namespace: ns},
			Spec: agenticv0alpha0.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: gatewayv1.Group(agenticv0alpha0.GroupName),
						Kind:  gatewayv1.Kind("XBackend"),
						Name:  "my-backend",
					},
				}},
			},
			Status: rejectedStatus,
		},
		&agenticv0alpha0.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-targeting-other-backend", Namespace: ns},
			Spec: agenticv0alpha0.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: gatewayv1.Group(agenticv0alpha0.GroupName),
						Kind:  gatewayv1.Kind("XBackend"),
						Name:  "other-backend",
					},
				}},
			},
			Status: acceptedStatus,
		},
	}

	agenticClient := agenticclient.NewSimpleClientset(policies...)
	agenticInformerFactory := agenticinformers.NewSharedInformerFactory(agenticClient, 0)
	lister := agenticInformerFactory.Agentic().V0alpha0().XAccessPolicies().Lister()

	// Populate cache
	for _, p := range policies {
		_ = agenticInformerFactory.Agentic().V0alpha0().XAccessPolicies().Informer().GetIndexer().Add(p)
	}

	tr := &Translator{accessPolicyLister: lister}

	found, err := tr.findAccessPoliciesForTarget(agenticv0alpha0.GroupName, "XBackend", ns, "my-backend")
	if err != nil {
		t.Fatalf("Failed to find policies: %v", err)
	}

	if len(found) != 1 {
		t.Errorf("Expected 1 accepted policy, got %d", len(found))
	}

	if found[0].Name != "policy-accepted" {
		t.Errorf("Expected policy-accepted, got %s", found[0].Name)
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
			trustDomain: testTrustDomain,
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

func TestTranslateAccessPolicyToRBAC(t *testing.T) {
	tests := []struct {
		name                   string
		accessPolicy           *agenticv0alpha0.XAccessPolicy
		expectedRules          map[string]expectedRule // rule name -> expected results in Rules
		expectedShadowRules    map[string]expectedRule // rule name -> expected results in ShadowRules
		expectShadowStatPrefix bool
	}{
		{
			name: "one rule with tools",
			accessPolicy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "policy-1"},
				Spec: agenticv0alpha0.AccessPolicySpec{
					Rules: []agenticv0alpha0.AccessRule{
						{
							Name: "rule-1",
							Source: agenticv0alpha0.Source{
								Type: agenticv0alpha0.AuthorizationSourceTypeSPIFFE,
								SPIFFE: func() *agenticv0alpha0.AuthorizationSourceSPIFFE {
									s := agenticv0alpha0.AuthorizationSourceSPIFFE("spiffe://example.com/ns/default/sa/caller")
									return &s
								}(),
							},
							Authorization: &agenticv0alpha0.AuthorizationRule{
								Type:  agenticv0alpha0.AuthorizationRuleTypeInlineTools,
								Tools: []string{"tool-1"},
							},
						},
					},
				},
			},
			expectedRules: map[string]expectedRule{
				"rule-1": {
					principal:   "spiffe://example.com/ns/default/sa/caller",
					permissions: []string{"tool-1"},
				},
			},
		},
		{
			name: "one rule with empty tools",
			accessPolicy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "policy-2"},
				Spec: agenticv0alpha0.AccessPolicySpec{
					Rules: []agenticv0alpha0.AccessRule{
						{
							Name: "rule-1",
							Source: agenticv0alpha0.Source{
								Type: agenticv0alpha0.AuthorizationSourceTypeSPIFFE,
								SPIFFE: func() *agenticv0alpha0.AuthorizationSourceSPIFFE {
									s := agenticv0alpha0.AuthorizationSourceSPIFFE("spiffe://example.com/ns/default/sa/caller")
									return &s
								}(),
							},
							Authorization: &agenticv0alpha0.AuthorizationRule{
								Type:  agenticv0alpha0.AuthorizationRuleTypeInlineTools,
								Tools: []string{},
							},
						},
					},
				},
			},
			expectedRules: map[string]expectedRule{
				"rule-1": {
					principal:   "spiffe://example.com/ns/default/sa/caller",
					permissions: []string{},
				},
			},
		},
		{
			name: "one rule with nil authorization",
			accessPolicy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "policy-3"},
				Spec: agenticv0alpha0.AccessPolicySpec{
					Rules: []agenticv0alpha0.AccessRule{
						{
							Name: "rule-1",
							Source: agenticv0alpha0.Source{
								Type: agenticv0alpha0.AuthorizationSourceTypeSPIFFE,
								SPIFFE: func() *agenticv0alpha0.AuthorizationSourceSPIFFE {
									s := agenticv0alpha0.AuthorizationSourceSPIFFE("spiffe://example.com/ns/default/sa/caller")
									return &s
								}(),
							},
						},
					},
				},
			},
			expectedRules: map[string]expectedRule{
				"rule-1": {
					principal:   "spiffe://example.com/ns/default/sa/caller",
					permissions: []string{},
				},
			},
		},
		{
			name: "multi rule with tools",
			accessPolicy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: "policy-4"},
				Spec: agenticv0alpha0.AccessPolicySpec{
					Rules: []agenticv0alpha0.AccessRule{
						{
							Name: "rule-1",
							Source: agenticv0alpha0.Source{
								Type: agenticv0alpha0.AuthorizationSourceTypeServiceAccount,
								ServiceAccount: &agenticv0alpha0.AuthorizationSourceServiceAccount{
									Name:      "my-sa",
									Namespace: "my-ns",
								},
							},
							Authorization: &agenticv0alpha0.AuthorizationRule{
								Type:  agenticv0alpha0.AuthorizationRuleTypeInlineTools,
								Tools: []string{"tool-a"},
							},
						},
						{
							Name: "rule-2",
							Source: agenticv0alpha0.Source{
								Type: agenticv0alpha0.AuthorizationSourceTypeSPIFFE,
								SPIFFE: func() *agenticv0alpha0.AuthorizationSourceSPIFFE {
									s := agenticv0alpha0.AuthorizationSourceSPIFFE("spiffe://example.com/ns/default/sa/caller")
									return &s
								}(),
							},
							Authorization: &agenticv0alpha0.AuthorizationRule{
								Type:  agenticv0alpha0.AuthorizationRuleTypeInlineTools,
								Tools: []string{"tool-b", "tool-c"},
							},
						},
					},
				},
			},
			expectedRules: map[string]expectedRule{
				"rule-1": {
					principal:   "spiffe://" + testTrustDomain + "/ns/my-ns/sa/my-sa",
					permissions: []string{"tool-a"},
				},
				"rule-2": {
					principal:   "spiffe://example.com/ns/default/sa/caller",
					permissions: []string{"tool-b", "tool-c"},
				},
			},
		},
		{
			name: "one rule with service account in same namespace (empty ns in source)",
			accessPolicy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "my-ns", Name: "policy-5"},
				Spec: agenticv0alpha0.AccessPolicySpec{
					Rules: []agenticv0alpha0.AccessRule{
						{
							Name: "rule-1",
							Source: agenticv0alpha0.Source{
								Type: agenticv0alpha0.AuthorizationSourceTypeServiceAccount,
								ServiceAccount: &agenticv0alpha0.AuthorizationSourceServiceAccount{
									Name: "my-sa",
									// Namespace is omitted
								},
							},
							Authorization: &agenticv0alpha0.AuthorizationRule{
								Type:  agenticv0alpha0.AuthorizationRuleTypeInlineTools,
								Tools: []string{"tool-1"},
							},
						},
					},
				},
			},
			expectedRules: map[string]expectedRule{
				"rule-1": {
					principal:   "spiffe://" + testTrustDomain + "/ns/my-ns/sa/my-sa",
					permissions: []string{"tool-1"},
				},
			},
		},
		{
			name: "external authz",
			accessPolicy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "policy-ext-auth"},
				Spec: agenticv0alpha0.AccessPolicySpec{
					Rules: []agenticv0alpha0.AccessRule{
						{
							Name: "rule-ext-auth",
							Source: agenticv0alpha0.Source{
								Type: agenticv0alpha0.AuthorizationSourceTypeSPIFFE,
								SPIFFE: func() *agenticv0alpha0.AuthorizationSourceSPIFFE {
									s := agenticv0alpha0.AuthorizationSourceSPIFFE("spiffe://example.com/ns/default/sa/caller")
									return &s
								}(),
							},
							Authorization: &agenticv0alpha0.AuthorizationRule{
								Type: agenticv0alpha0.AuthorizationRuleTypeExternalAuth,
								ExternalAuth: &gatewayv1.HTTPExternalAuthFilter{
									ExternalAuthProtocol: gatewayv1.HTTPRouteExternalAuthGRPCProtocol,
									BackendRef: gatewayv1.BackendObjectReference{
										Name: "ext-auth-svc",
									},
								},
							},
						},
					},
				},
			},
			expectedRules: map[string]expectedRule{
				"rule-ext-auth": {
					principal:      "spiffe://example.com/ns/default/sa/caller",
					permissions:    []string{toolsCallMethod},
					isExternalAuth: true,
				},
			},
			expectedShadowRules: map[string]expectedRule{
				"rule-ext-auth": {
					principal:      "spiffe://example.com/ns/default/sa/caller",
					permissions:    []string{toolsCallMethod},
					isExternalAuth: true,
				},
			},
			expectShadowStatPrefix: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := &Translator{agenticIdentityTrustDomain: testTrustDomain}
			rbac := tr.translateAccessPolicyToRBAC(tc.accessPolicy)

			verifyRBAC(t, rbac.Rules, tc.expectedRules)
			verifyRBAC(t, rbac.ShadowRules, tc.expectedShadowRules)

			if (rbac.ShadowRulesStatPrefix != "") != tc.expectShadowStatPrefix {
				t.Errorf("ShadowRulesStatPrefix: expected set=%v, got %q", tc.expectShadowStatPrefix, rbac.ShadowRulesStatPrefix)
			}
		})
	}
}

func TestTranslateInlineToolsToRBACPermission(t *testing.T) {
	tests := []struct {
		name          string
		tools         []string
		expectedTools []string
	}{
		{
			name:          "no tools",
			tools:         []string{},
			expectedTools: []string{},
		},
		{
			name:          "single tool",
			tools:         []string{"tool-1"},
			expectedTools: []string{"tool-1"},
		},
		{
			name:          "multiple tools",
			tools:         []string{"tool-1", "tool-2"},
			expectedTools: []string{"tool-1", "tool-2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := translateInlineToolsToRBACPermission(tt.tools)
			// Create a dummy policy to use verifyPolicy helper
			policy := &rbacconfigv3.Policy{
				Permissions: []*rbacconfigv3.Permission{p},
			}
			verifyPolicy(t, policy, expectedRule{permissions: tt.expectedTools})
		})
	}
}

func TestBuildAllowMCPSessionClosePolicy(t *testing.T) {
	policy := buildAllowMCPSessionClosePolicy()
	ids := policy.Principals[0].GetAndIds().Ids
	if len(ids) != 2 {
		t.Errorf("expected 2 ID matchers, got %d", len(ids))
	}
	// DELETE method
	if ids[0].GetHeader().GetStringMatch().GetExact() != "DELETE" {
		t.Errorf("expected DELETE method matcher")
	}
	// Session ID header presence
	if !ids[1].GetHeader().GetPresentMatch() {
		t.Errorf("expected session-id present matcher")
	}
}

func TestBuildAllowAnyoneToInitializeAndListToolsPolicy(t *testing.T) {
	policy := buildAllowAnyoneToInitializeAndListToolsPolicy()
	if !policy.Principals[0].GetAny() {
		t.Errorf("principal should be ANY")
	}
	matcher := policy.Permissions[0].GetAndRules().Rules[0].GetSourcedMetadata().MetadataMatcher
	if matcher.Filter != mcpProxyFilterName || matcher.Path[0].GetKey() != "method" {
		t.Errorf("policy incorrectly configured")
	}
	orMethods := matcher.Value.GetOrMatch()
	if orMethods == nil || len(orMethods.ValueMatchers) != 3 {
		t.Errorf("expected 3 allowed methods")
	}
}

func TestBuildAllowHTTPGetPolicy(t *testing.T) {
	policy := buildAllowHTTPGetPolicy()
	if !policy.Principals[0].GetAny() {
		t.Errorf("principal should be ANY")
	}
	if policy.Permissions[0].GetHeader().Name != ":method" ||
		policy.Permissions[0].GetHeader().GetStringMatch().GetExact() != "GET" {
		t.Errorf("policy incorrectly configured")
	}
}

func verifyRBAC(t *testing.T, rbacRules *rbacconfigv3.RBAC, expectedRules map[string]expectedRule) {
	t.Helper()
	if len(expectedRules) == 0 {
		if rbacRules != nil && len(rbacRules.Policies) > 0 {
			t.Errorf("did not expect any policies, but got %d", len(rbacRules.Policies))
		}
		return
	}

	if rbacRules == nil {
		t.Fatal("expected RBAC rules to be populated")
	}

	if len(rbacRules.Policies) != len(expectedRules) {
		t.Errorf("expected %d policies, got %d", len(expectedRules), len(rbacRules.Policies))
	}

	for ruleName, expected := range expectedRules {
		rbacPolicy, ok := rbacRules.Policies[ruleName]
		if !ok {
			t.Errorf("expected policy with key %q not found", ruleName)
			continue
		}
		verifyPolicy(t, rbacPolicy, expected)
	}
}

func verifyPolicy(t *testing.T, rbacPolicy *rbacconfigv3.Policy, expected expectedRule) {
	t.Helper()
	// Verify Principal
	if expected.principal != "" {
		found := false
		for _, p := range rbacPolicy.Principals {
			auth := p.GetAuthenticated()
			if auth != nil && auth.PrincipalName.GetExact() == expected.principal {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("did not find expected principal %q", expected.principal)
		}
	} else if len(rbacPolicy.Principals) > 0 {
		// If no principal expected, should match 'Any'
		foundAny := false
		for _, p := range rbacPolicy.Principals {
			if p.GetAny() {
				foundAny = true
				break
			}
		}
		if !foundAny {
			t.Errorf("expected 'Any' principal but not found")
		}
	}

	// Verify Tools Permissions
	if len(rbacPolicy.Permissions) == 0 {
		t.Errorf("expected permissions for tools, but found none")
		return
	}

	if len(expected.permissions) == 0 {
		// Verify it's a "Never match" permission (NotRule of Any)
		notRule := rbacPolicy.Permissions[0].GetNotRule()
		if notRule == nil || notRule.GetAny() != true {
			t.Errorf("expected 'deny all' (Never match) permission for empty tools list")
		}
		return
	}

	if expected.isExternalAuth {
		if len(rbacPolicy.Permissions) != 1 {
			t.Errorf("expected 1 permission for external auth, got %d", len(rbacPolicy.Permissions))
			return
		}
		methodRule := rbacPolicy.Permissions[0].GetSourcedMetadata()
		if methodRule == nil || methodRule.MetadataMatcher.Value.GetStringMatch().GetExact() != toolsCallMethod {
			t.Errorf("expected tools/call method permission for external auth")
		}
		return
	}

	// The top level permission should be an AndRules
	andRules := rbacPolicy.Permissions[0].GetAndRules()
	if andRules == nil || len(andRules.Rules) != 2 {
		t.Errorf("expected tools permission to have 2 ANDed rules (method and tools)")
		return
	}

	// Rule 1: method must be tools/call
	methodRule := andRules.Rules[0].GetSourcedMetadata()
	if methodRule == nil || methodRule.MetadataMatcher == nil || methodRule.MetadataMatcher.Filter != mcpProxyFilterName {
		t.Errorf("first AND rule should be sourced metadata from %s", mcpProxyFilterName)
		return
	}
	// Verify Path ["method"]
	if methodRule.MetadataMatcher.Path[0].GetKey() != "method" {
		t.Errorf("tools/call matcher should have path ['method']")
	}
	// Verify Value "tools/call"
	if methodRule.MetadataMatcher.Value.GetStringMatch().GetExact() != toolsCallMethod {
		t.Errorf("tools/call matcher should match exact string %q", toolsCallMethod)
	}

	// Rule 2: tool names match
	toolsRule := andRules.Rules[1].GetSourcedMetadata()
	if toolsRule == nil || toolsRule.MetadataMatcher == nil {
		t.Errorf("second AND rule should be tool name matchers")
		return
	}
	// Verify Path ["params", "name"]
	if toolsRule.MetadataMatcher.Path[0].GetKey() != "params" || toolsRule.MetadataMatcher.Path[1].GetKey() != "name" {
		t.Errorf("tools matcher should have path ['params', 'name']")
	}

	// Verify tool names exactly match
	if len(expected.permissions) == 1 {
		// Single tool uses StringMatch directly
		got := toolsRule.MetadataMatcher.Value.GetStringMatch().GetExact()
		if got != expected.permissions[0] {
			t.Errorf("tool name: expected %q, got %q", expected.permissions[0], got)
		}
	} else {
		// Multiple tools use OrMatch
		orMatch := toolsRule.MetadataMatcher.Value.GetOrMatch()
		if orMatch == nil {
			t.Errorf("expected OrMatch for multiple tools")
			return
		}
		if len(orMatch.ValueMatchers) != len(expected.permissions) {
			t.Errorf("expected %d tools in OrMatch, got %d", len(expected.permissions), len(orMatch.ValueMatchers))
			return
		}
		// Convert actual matchers to a map for easy lookup
		actualTools := make(map[string]bool)
		for _, v := range orMatch.ValueMatchers {
			actualTools[v.GetStringMatch().GetExact()] = true
		}
		for _, expectedTool := range expected.permissions {
			if !actualTools[expectedTool] {
				t.Errorf("expected tool %q not found in OrMatch", expectedTool)
			}
		}
	}
}
