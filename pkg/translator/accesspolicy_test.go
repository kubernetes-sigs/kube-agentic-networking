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
	"testing"
	"time"

	rbacconfigv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticv1alpha1 "sigs.k8s.io/kube-agentic-networking/api/v1alpha1"
	agenticclient "sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned/fake"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

const (
	testTrustDomain = "cluster.local"
)

var (
	acceptedStatus = agenticv1alpha1.AccessPolicyStatus{
		Ancestors: []gatewayv1.PolicyAncestorStatus{
			{
				Conditions: []metav1.Condition{
					{
						Type:   string(agenticv1alpha1.PolicyConditionAccepted),
						Status: metav1.ConditionTrue,
					},
				},
			},
		},
	}

	rejectedStatus = agenticv1alpha1.AccessPolicyStatus{
		Ancestors: []gatewayv1.PolicyAncestorStatus{
			{
				Conditions: []metav1.Condition{
					{
						Type:   string(agenticv1alpha1.PolicyConditionAccepted),
						Status: metav1.ConditionFalse,
					},
				},
			},
		},
	}
)

type expectedRule struct {
	principal           string
	permissions         []string
	isExternalAuth      bool
	hasCelCondition     bool
	expectAnyPermission bool
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
				newTestAccessPolicy("gw-policy", ns, gwName, "Gateway", "spiffe://cluster.local/ns/ns1/sa/sa1"),
			},
			gatewaysToCheck: map[string][]string{
				gwName: {constants.GatewayAllowRBACFilterName},
			},
		},
		{
			name: "multiple policies targeting the same gateway",
			policies: []runtime.Object{
				newTestAccessPolicy("gw-policy-1", ns, gwName, "Gateway", "spiffe://cluster.local/ns/ns1/sa/sa1"),
				newTestAccessPolicy("gw-policy-2", ns, gwName, "Gateway", "spiffe://cluster.local/ns/ns2/sa/sa2"),
			},
			gatewaysToCheck: map[string][]string{
				gwName: {constants.GatewayAllowRBACFilterName},
			},
		},
		{
			name: "one policy targeting multiple gateways",
			policies: []runtime.Object{
				&agenticv1alpha1.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "multi-gw-policy", Namespace: ns},
					Spec: agenticv1alpha1.AccessPolicySpec{
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
						Action: agenticv1alpha1.ActionTypeAllow,
						Rules:  []agenticv1alpha1.AccessRule{{Name: "rule-name"}},
					},
					Status: acceptedStatus,
				},
			},
			gatewaysToCheck: map[string][]string{
				gwName:     {constants.GatewayAllowRBACFilterName},
				"other-gw": {constants.GatewayAllowRBACFilterName},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agenticClient := agenticclient.NewSimpleClientset(tt.policies...)
			agenticInformerFactory := agenticinformers.NewSharedInformerFactory(agenticClient, 0)
			lister := agenticInformerFactory.Agentic().V1alpha1().XAccessPolicies().Lister()

			for _, p := range tt.policies {
				_ = agenticInformerFactory.Agentic().V1alpha1().XAccessPolicies().Informer().GetIndexer().Add(p)
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
					if f.GetName() != expectedNames[i] {
						t.Errorf("Gateway %s, Filter %d: expected name %s, got %s", gwn, i, expectedNames[i], f.GetName())
					}
				}
			}
		})
	}
}

func TestBuildBackendLevelRBACFilters(t *testing.T) {
	tr := &Translator{}
	filters, err := tr.buildBackendLevelRBACFilters()
	if err != nil {
		t.Fatalf("Failed to build filters: %v", err)
	}

	if len(filters) != 2 {
		t.Errorf("Expected 2 filters, got %d", len(filters))
	}

	expectedNames := []string{constants.BackendExtAuthRBACFilterName, constants.BackendAllowRBACFilterName}
	for i, f := range filters {
		if f.GetName() != expectedNames[i] {
			t.Errorf("Filter %d: expected name %s, got %s", i, expectedNames[i], f.GetName())
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
				newTestAccessPolicy("be-policy", ns, beName, "XBackend", "spiffe://cluster.local/ns/ns1/sa/sa1"),
			},
			backendsToCheck: map[string][]string{
				beName: {constants.BackendAllowRBACFilterName},
			},
		},
		{
			name: "multiple policies targeting the same backend",
			policies: []runtime.Object{
				newTestAccessPolicy("be-policy-1", ns, beName, "XBackend", "spiffe://cluster.local/ns/ns1/sa/sa1"),
				newTestAccessPolicy("be-policy-2", ns, beName, "XBackend", "spiffe://cluster.local/ns/ns2/sa/sa2"),
			},
			backendsToCheck: map[string][]string{
				beName: {constants.BackendAllowRBACFilterName},
			},
		},
		{
			name: "one policy targeting multiple backends",
			policies: []runtime.Object{
				&agenticv1alpha1.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "multi-be-policy", Namespace: ns},
					Spec: agenticv1alpha1.AccessPolicySpec{
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
						Action: agenticv1alpha1.ActionTypeAllow,
						Rules:  []agenticv1alpha1.AccessRule{{Name: "rule-name"}},
					},
					Status: acceptedStatus,
				},
			},
			backendsToCheck: map[string][]string{
				beName:          {constants.BackendAllowRBACFilterName},
				"other-backend": {constants.BackendAllowRBACFilterName},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agenticClient := agenticclient.NewSimpleClientset(tt.policies...)
			agenticInformerFactory := agenticinformers.NewSharedInformerFactory(agenticClient, 0)
			lister := agenticInformerFactory.Agentic().V1alpha1().XAccessPolicies().Lister()

			for _, p := range tt.policies {
				_ = agenticInformerFactory.Agentic().V1alpha1().XAccessPolicies().Informer().GetIndexer().Add(p)
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
	policy := &agenticv1alpha1.XAccessPolicy{
		Spec: agenticv1alpha1.AccessPolicySpec{
			Rules: []agenticv1alpha1.AccessRule{{Name: "custom-rule"}},
		},
	}

	rbac := tr.buildRBACConfigWithCommonPolicies(policy)

	expectedPolicies := []string{
		"custom-rule",
		constants.AllowMCPSessionClosePolicyName,
		constants.AllowAnyoneToInitializeAndListToolsPolicyName,
		constants.AllowHTTPGetPolicyName,
	}

	for _, p := range expectedPolicies {
		if _, ok := rbac.GetRules().GetPolicies()[p]; !ok {
			t.Errorf("Expected policy %s not found", p)
		}
	}
}

func TestFindAccessPoliciesForTarget(t *testing.T) {
	ns := "test-ns"

	policies := []runtime.Object{
		&agenticv1alpha1.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-accepted", Namespace: ns},
			Spec: agenticv1alpha1.AccessPolicySpec{
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
		&agenticv1alpha1.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-rejected", Namespace: ns},
			Spec: agenticv1alpha1.AccessPolicySpec{
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
		&agenticv1alpha1.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-targeting-other-backend", Namespace: ns},
			Spec: agenticv1alpha1.AccessPolicySpec{
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
	lister := agenticInformerFactory.Agentic().V1alpha1().XAccessPolicies().Lister()

	// Populate cache
	for _, p := range policies {
		_ = agenticInformerFactory.Agentic().V1alpha1().XAccessPolicies().Informer().GetIndexer().Add(p)
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

func TestFindAccessPoliciesForTargetSorting(t *testing.T) {
	ns := "test-ns"
	now := metav1.Now()
	past := metav1.NewTime(now.Add(-1 * time.Hour))
	future := metav1.NewTime(now.Add(1 * time.Hour))

	policies := []runtime.Object{
		&agenticv1alpha1.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-future", Namespace: ns, CreationTimestamp: future},
			Spec: agenticv1alpha1.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: gatewayv1.Group(agenticv0alpha0.GroupName),
						Kind:  gatewayv1.Kind("XBackend"),
						Name:  "my-backend",
					},
				}},
				Action: agenticv1alpha1.ActionTypeAllow,
				Rules:  []agenticv1alpha1.AccessRule{{Name: "rule-1"}},
			},
			Status: acceptedStatus,
		},
		&agenticv1alpha1.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-past", Namespace: ns, CreationTimestamp: past},
			Spec: agenticv1alpha1.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: gatewayv1.Group(agenticv0alpha0.GroupName),
						Kind:  gatewayv1.Kind("XBackend"),
						Name:  "my-backend",
					},
				}},
				Action: agenticv1alpha1.ActionTypeAllow,
				Rules:  []agenticv1alpha1.AccessRule{{Name: "rule-1"}},
			},
			Status: acceptedStatus,
		},
		&agenticv1alpha1.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-now", Namespace: ns, CreationTimestamp: now},
			Spec: agenticv1alpha1.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: gatewayv1.Group(agenticv0alpha0.GroupName),
						Kind:  gatewayv1.Kind("XBackend"),
						Name:  "my-backend",
					},
				}},
				Action: agenticv1alpha1.ActionTypeAllow,
				Rules:  []agenticv1alpha1.AccessRule{{Name: "rule-1"}},
			},
			Status: acceptedStatus,
		},
	}

	agenticClient := agenticclient.NewSimpleClientset(policies...)
	agenticInformerFactory := agenticinformers.NewSharedInformerFactory(agenticClient, 0)
	lister := agenticInformerFactory.Agentic().V1alpha1().XAccessPolicies().Lister()

	for _, p := range policies {
		_ = agenticInformerFactory.Agentic().V1alpha1().XAccessPolicies().Informer().GetIndexer().Add(p)
	}

	tr := &Translator{accessPolicyLister: lister}

	found, err := tr.findAccessPoliciesForTarget(agenticv0alpha0.GroupName, "XBackend", ns, "my-backend")
	if err != nil {
		t.Fatalf("Failed to find policies: %v", err)
	}

	if len(found) != 3 {
		t.Errorf("Expected 3 policies, got %d", len(found))
	}

	// Expected order: past, now, future
	if found[0].Name != "policy-past" {
		t.Errorf("Expected policy-past, got %s", found[0].Name)
	}
	if found[1].Name != "policy-now" {
		t.Errorf("Expected policy-now, got %s", found[1].Name)
	}
	if found[2].Name != "policy-future" {
		t.Errorf("Expected policy-future, got %s", found[2].Name)
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
		accessPolicy           *agenticv1alpha1.XAccessPolicy
		expectedRules          map[string]expectedRule // rule name -> expected results in Rules
		expectedShadowRules    map[string]expectedRule // rule name -> expected results in ShadowRules
		expectShadowStatPrefix bool
	}{
		{
			name: "one rule with tools",
			accessPolicy: func() *agenticv1alpha1.XAccessPolicy {
				p := newTestAccessPolicy("policy-1", "default", "dummy", "Gateway", "spiffe://example.com/ns/default/sa/caller")
				p.Spec.Rules[0].Authorization = &agenticv1alpha1.AuthorizationRule{
					Type: agenticv1alpha1.AuthorizationRuleTypeInline,
					MCP: agenticv1alpha1.MCPAttributes{
						Methods: []agenticv1alpha1.MCPMethod{
							{
								Name:   "tools/call",
								Params: []agenticv1alpha1.MCPMethodParam{"tool-1"},
							},
						},
					},
				}
				return p
			}(),
			expectedRules: map[string]expectedRule{
				"rule-1": {
					principal:   "spiffe://example.com/ns/default/sa/caller",
					permissions: []string{"tool-1"},
				},
			},
			expectedShadowRules: map[string]expectedRule{
				"rule-1": {
					principal:   "spiffe://example.com/ns/default/sa/caller",
					permissions: []string{"tool-1"},
				},
			},
		},
		{
			name: "one rule with empty tools",
			accessPolicy: func() *agenticv1alpha1.XAccessPolicy {
				p := newTestAccessPolicy("policy-2", "default", "dummy", "Gateway", "spiffe://example.com/ns/default/sa/caller")
				p.Spec.Rules[0].Authorization = &agenticv1alpha1.AuthorizationRule{
					Type: agenticv1alpha1.AuthorizationRuleTypeInline,
					MCP: agenticv1alpha1.MCPAttributes{
						Methods: []agenticv1alpha1.MCPMethod{},
					},
				}
				return p
			}(),
			expectedRules: map[string]expectedRule{
				"rule-1": {
					principal:           "spiffe://example.com/ns/default/sa/caller",
					permissions:         []string{},
					expectAnyPermission: true,
				},
			},
			expectedShadowRules: map[string]expectedRule{
				"rule-1": {
					principal:           "spiffe://example.com/ns/default/sa/caller",
					permissions:         []string{},
					expectAnyPermission: true,
				},
			},
		},
		{
			name:         "one rule with nil authorization",
			accessPolicy: newTestAccessPolicy("policy-3", "default", "dummy", "Gateway", "spiffe://example.com/ns/default/sa/caller"),
			expectedRules: map[string]expectedRule{
				"rule-1": {
					principal:           "spiffe://example.com/ns/default/sa/caller",
					permissions:         []string{},
					expectAnyPermission: true,
				},
			},
			expectedShadowRules: map[string]expectedRule{
				"rule-1": {
					principal:           "spiffe://example.com/ns/default/sa/caller",
					permissions:         []string{},
					expectAnyPermission: true,
				},
			},
		},
		{
			name: "multi rule with tools",
			accessPolicy: &agenticv1alpha1.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: "policy-4"},
				Spec: agenticv1alpha1.AccessPolicySpec{
					Rules: []agenticv1alpha1.AccessRule{
						{
							Name: "rule-1",
							Source: agenticv1alpha1.AccessRuleSource{
								Type: agenticv1alpha1.AuthorizationSourceTypeServiceAccount,
								ServiceAccount: &agenticv1alpha1.AuthorizationSourceServiceAccount{
									Name:      "my-sa",
									Namespace: "my-ns",
								},
							},
							Authorization: &agenticv1alpha1.AuthorizationRule{
								Type: agenticv1alpha1.AuthorizationRuleTypeInline,
								MCP: agenticv1alpha1.MCPAttributes{
									Methods: []agenticv1alpha1.MCPMethod{
										{
											Name:   "tools/call",
											Params: []agenticv1alpha1.MCPMethodParam{"tool-a"},
										},
									},
								},
							},
						},
						{
							Name: "rule-2",
							Source: agenticv1alpha1.AccessRuleSource{
								Type: agenticv1alpha1.AuthorizationSourceTypeSPIFFE,
								SPIFFE: func() *agenticv1alpha1.AuthorizationSourceSPIFFE {
									s := agenticv1alpha1.AuthorizationSourceSPIFFE("spiffe://example.com/ns/default/sa/caller")
									return &s
								}(),
							},
							Authorization: &agenticv1alpha1.AuthorizationRule{
								Type: agenticv1alpha1.AuthorizationRuleTypeInline,
								MCP: agenticv1alpha1.MCPAttributes{
									Methods: []agenticv1alpha1.MCPMethod{
										{
											Name:   "tools/call",
											Params: []agenticv1alpha1.MCPMethodParam{"tool-b", "tool-c"},
										},
									},
								},
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
			expectedShadowRules: map[string]expectedRule{
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
			accessPolicy: &agenticv1alpha1.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "my-ns", Name: "policy-5"},
				Spec: agenticv1alpha1.AccessPolicySpec{
					Rules: []agenticv1alpha1.AccessRule{
						{
							Name: "rule-1",
							Source: agenticv1alpha1.AccessRuleSource{
								Type: agenticv1alpha1.AuthorizationSourceTypeServiceAccount,
								ServiceAccount: &agenticv1alpha1.AuthorizationSourceServiceAccount{
									Name: "my-sa",
									// Namespace is omitted
								},
							},
							Authorization: &agenticv1alpha1.AuthorizationRule{
								Type: agenticv1alpha1.AuthorizationRuleTypeInline,
								MCP: agenticv1alpha1.MCPAttributes{
									Methods: []agenticv1alpha1.MCPMethod{
										{
											Name:   "tools/call",
											Params: []agenticv1alpha1.MCPMethodParam{"tool-1"},
										},
									},
								},
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
			expectedShadowRules: map[string]expectedRule{
				"rule-1": {
					principal:   "spiffe://" + testTrustDomain + "/ns/my-ns/sa/my-sa",
					permissions: []string{"tool-1"},
				},
			},
		},
		{
			name: "external authz",
			accessPolicy: &agenticv1alpha1.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "policy-ext-auth"},
				Spec: agenticv1alpha1.AccessPolicySpec{
					Action: agenticv1alpha1.ActionTypeExternalAuth,
					ExternalAuth: &gatewayv1.HTTPExternalAuthFilter{
						ExternalAuthProtocol: gatewayv1.HTTPRouteExternalAuthGRPCProtocol,
						BackendRef: gatewayv1.BackendObjectReference{
							Name: "ext-auth-svc",
						},
					},
					Rules: []agenticv1alpha1.AccessRule{
						{
							Name: "rule-ext-auth",
							Source: agenticv1alpha1.AccessRuleSource{
								Type: agenticv1alpha1.AuthorizationSourceTypeSPIFFE,
								SPIFFE: func() *agenticv1alpha1.AuthorizationSourceSPIFFE {
									s := agenticv1alpha1.AuthorizationSourceSPIFFE("spiffe://example.com/ns/default/sa/caller")
									return &s
								}(),
							},
						},
					},
				},
			},
			expectedRules: map[string]expectedRule{
				"rule-ext-auth": {
					permissions:         []string{},
					expectAnyPermission: true,
				},
			},
			expectedShadowRules: map[string]expectedRule{
				"rule-ext-auth": {
					principal:           "spiffe://example.com/ns/default/sa/caller",
					permissions:         []string{},
					expectAnyPermission: true,
				},
			},
			expectShadowStatPrefix: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := &Translator{agenticIdentityTrustDomain: testTrustDomain}
			rbac := tr.translateAccessPolicyToRBAC(tc.accessPolicy)

			verifyRBAC(t, rbac.GetRules(), tc.expectedRules)
			verifyRBAC(t, rbac.GetShadowRules(), tc.expectedShadowRules)

			if (rbac.GetShadowRulesStatPrefix() != "") != tc.expectShadowStatPrefix {
				t.Errorf("ShadowRulesStatPrefix: expected set=%v, got %q", tc.expectShadowStatPrefix, rbac.GetShadowRulesStatPrefix())
			}
		})
	}
}

func TestBuildAllowMCPSessionClosePolicy(t *testing.T) {
	policy := buildAllowMCPSessionClosePolicy()
	ids := policy.GetPrincipals()[0].GetAndIds().GetIds()
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
	if !policy.GetPrincipals()[0].GetAny() {
		t.Errorf("principal should be ANY")
	}
	matcher := policy.GetPermissions()[0].GetAndRules().GetRules()[0].GetSourcedMetadata().GetMetadataMatcher()
	if matcher.GetFilter() != constants.MCPProxyFilterName || matcher.GetPath()[0].GetKey() != "method" {
		t.Errorf("policy incorrectly configured")
	}
	orMethods := matcher.GetValue().GetOrMatch()
	if orMethods == nil || len(orMethods.GetValueMatchers()) != 3 {
		t.Errorf("expected 3 allowed methods")
	}
}

func TestBuildAllowHTTPGetPolicy(t *testing.T) {
	policy := buildAllowHTTPGetPolicy()
	if !policy.GetPrincipals()[0].GetAny() {
		t.Errorf("principal should be ANY")
	}
	if policy.GetPermissions()[0].GetHeader().GetName() != ":method" ||
		policy.GetPermissions()[0].GetHeader().GetStringMatch().GetExact() != "GET" {
		t.Errorf("policy incorrectly configured")
	}
}

func verifyRBAC(t *testing.T, rbacRules *rbacconfigv3.RBAC, expectedRules map[string]expectedRule) {
	t.Helper()
	if len(expectedRules) == 0 {
		if rbacRules != nil && len(rbacRules.GetPolicies()) > 0 {
			t.Errorf("did not expect any policies, but got %d", len(rbacRules.GetPolicies()))
		}
		return
	}

	if rbacRules == nil {
		t.Fatal("expected RBAC rules to be populated")
	}

	if len(rbacRules.GetPolicies()) != len(expectedRules) {
		t.Errorf("expected %d policies, got %d", len(expectedRules), len(rbacRules.GetPolicies()))
	}

	for ruleName, expected := range expectedRules {
		rbacPolicy, ok := rbacRules.GetPolicies()[ruleName]
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
		for _, p := range rbacPolicy.GetPrincipals() {
			auth := p.GetAuthenticated()
			if auth != nil && auth.GetPrincipalName().GetExact() == expected.principal {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("did not find expected principal %q", expected.principal)
		}
	} else if len(rbacPolicy.GetPrincipals()) > 0 {
		// If no principal expected, should match 'Any'
		foundAny := false
		for _, p := range rbacPolicy.GetPrincipals() {
			if p.GetAny() {
				foundAny = true
				break
			}
		}
		if !foundAny {
			t.Errorf("expected 'Any' principal but not found")
		}
	}

	// Verify CEL Condition
	if expected.hasCelCondition {
		if rbacPolicy.GetCondition() == nil {
			t.Errorf("expected CEL condition but found none")
		}
	} else if rbacPolicy.GetCondition() != nil {
		t.Errorf("did not expect CEL condition but found one")
	}

	// Verify Tools Permissions
	if len(rbacPolicy.GetPermissions()) == 0 {
		t.Errorf("expected permissions for tools, but found none")
		return
	}

	if expected.expectAnyPermission {
		if len(rbacPolicy.GetPermissions()) != 1 || !rbacPolicy.GetPermissions()[0].GetAny() {
			t.Errorf("expected 'Any' permission for omitted authorization")
		}
		return
	}

	if expected.isExternalAuth || expected.hasCelCondition {
		if len(rbacPolicy.GetPermissions()) != 1 {
			t.Errorf("expected 1 permission for external auth or CEL, got %d", len(rbacPolicy.GetPermissions()))
			return
		}
		methodRule := rbacPolicy.GetPermissions()[0].GetSourcedMetadata()
		if methodRule == nil || methodRule.GetMetadataMatcher().GetValue().GetStringMatch().GetExact() != constants.ToolsCallMethod {
			t.Errorf("expected tools/call method permission for external auth or CEL")
		}
		return
	}

	// The top level permission should be an AndRules
	andRules := rbacPolicy.GetPermissions()[0].GetAndRules()
	if andRules == nil || len(andRules.GetRules()) != 2 {
		t.Errorf("expected tools permission to have 2 ANDed rules (method and tools)")
		return
	}

	// Rule 1: method must be tools/call
	methodRule := andRules.GetRules()[0].GetSourcedMetadata()
	if methodRule == nil || methodRule.GetMetadataMatcher() == nil || methodRule.GetMetadataMatcher().GetFilter() != constants.MCPProxyFilterName {
		t.Errorf("first AND rule should be sourced metadata from %s", constants.MCPProxyFilterName)
		return
	}
	// Verify Path ["method"]
	if methodRule.GetMetadataMatcher().GetPath()[0].GetKey() != "method" {
		t.Errorf("tools/call matcher should have path ['method']")
	}
	// Verify Value "tools/call"
	if methodRule.GetMetadataMatcher().GetValue().GetStringMatch().GetExact() != constants.ToolsCallMethod {
		t.Errorf("tools/call matcher should match exact string %q", constants.ToolsCallMethod)
	}

	// Rule 2: tool names match
	toolsRule := andRules.GetRules()[1].GetSourcedMetadata()
	if toolsRule == nil || toolsRule.GetMetadataMatcher() == nil {
		t.Errorf("second AND rule should be tool name matchers")
		return
	}
	// Verify Path ["params", "name"]
	if toolsRule.GetMetadataMatcher().GetPath()[0].GetKey() != "params" || toolsRule.GetMetadataMatcher().GetPath()[1].GetKey() != "name" {
		t.Errorf("tools matcher should have path ['params', 'name']")
	}

	// Verify tool names exactly match
	if len(expected.permissions) == 1 {
		// Single tool uses StringMatch directly
		got := toolsRule.GetMetadataMatcher().GetValue().GetStringMatch().GetExact()
		if got != expected.permissions[0] {
			t.Errorf("tool name: expected %q, got %q", expected.permissions[0], got)
		}
	} else {
		// Multiple tools use OrMatch
		orMatch := toolsRule.GetMetadataMatcher().GetValue().GetOrMatch()
		if orMatch == nil {
			t.Errorf("expected OrMatch for multiple tools")
			return
		}
		if len(orMatch.GetValueMatchers()) != len(expected.permissions) {
			t.Errorf("expected %d tools in OrMatch, got %d", len(expected.permissions), len(orMatch.GetValueMatchers()))
			return
		}
		// Convert actual matchers to a map for easy lookup
		actualTools := make(map[string]bool)
		for _, v := range orMatch.GetValueMatchers() {
			actualTools[v.GetStringMatch().GetExact()] = true
		}
		for _, expectedTool := range expected.permissions {
			if !actualTools[expectedTool] {
				t.Errorf("expected tool %q not found in OrMatch", expectedTool)
			}
		}
	}
}
