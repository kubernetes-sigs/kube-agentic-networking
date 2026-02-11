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

	rbacconfigv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
)

const testTrustDomain = "cluster.local"

type expectedPrincipals []string

func TestTranslateAccessPolicyToRBAC(t *testing.T) {
	tests := []struct {
		name                string
		accessPolicy        *agenticv0alpha0.XAccessPolicy
		backend             *agenticv0alpha0.XBackend
		expectedRules       map[string]expectedPrincipals
		expectedShadowRules map[string]expectedPrincipals
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
			expectedRules: map[string]expectedPrincipals{
				"allow-all": {"spiffe://example.com/ns/default/sa/default"},
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
			expectedRules: map[string]expectedPrincipals{
				"rule-1": {"spiffe://example.com/ns/default/sa/foo"},
				"rule-2": {"spiffe://example.com/ns/default/sa/bar"},
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
			expectedRules: map[string]expectedPrincipals{
				"allow-sa": {convertSAtoSPIFFEID(testTrustDomain, "my-ns", "my-sa")},
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
			expectedRules: map[string]expectedPrincipals{
				"allow-tools-a-and-b": {"spiffe://example.com/ns/default/sa/default"},
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
			expectedShadowRules: map[string]expectedPrincipals{
				"ext-authz-rule": {"spiffe://example.com/ns/default/sa/default"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := &Translator{agenticIdentityTrustDomain: testTrustDomain}
			rbacConfig := tr.translatesAccessPolicyToRBAC(tc.accessPolicy)
			verifyRBACRulesContainPolicyNames(t, rbacConfig.GetRules(), tc.expectedRules)
			verifyRBACRulesContainPolicyNames(t, rbacConfig.GetShadowRules(), tc.expectedShadowRules)
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

func verifyRBACRulesContainPolicyNames(t *testing.T, rules *rbacconfigv3.RBAC, expectedRules map[string]expectedPrincipals) {
	policies := rules.GetPolicies()
	if len(policies) != len(expectedRules) {
		t.Errorf("expected %d policies, got %d", len(expectedRules), len(policies))
	}
	for key, expectedPrincipals := range expectedRules {
		if _, ok := policies[key]; !ok {
			t.Errorf("expected policy with key %q not found", key)
		}
		if expectedPrincipals != nil {
			verifyRBACPolicyPrincipals(t, policies[key], expectedPrincipals)
		}
	}

	// Optional: print keys found if failure
	if t.Failed() {
		found := make([]string, 0, len(policies))
		for k := range policies {
			found = append(found, k)
		}
		t.Logf("Found keys: %v", found)
	}
}

func verifyRBACPolicyPrincipals(t *testing.T, policy *rbacconfigv3.Policy, expectedPrincipals expectedPrincipals) {
	foundPrincipals := make(map[string]bool)
	for _, p := range policy.Principals {
		auth := p.GetAuthenticated()
		if auth != nil {
			foundPrincipals[auth.PrincipalName.GetExact()] = true
		}
	}

	for _, expected := range expectedPrincipals {
		if !foundPrincipals[expected] {
			t.Errorf("expected principal %q not found in policy", expected)
		}
	}
}
