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
	"k8s.io/client-go/tools/cache"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticlisters "sigs.k8s.io/kube-agentic-networking/k8s/client/listers/api/v0alpha0"
)

func TestTranslateAccessPolicyToRBAC(t *testing.T) {
	tests := []struct {
		name         string
		accessPolicy *agenticv0alpha0.XAccessPolicy
		backend      *agenticv0alpha0.XBackend
		expectedKeys []string
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
			expectedKeys: []string{"allow-all"},
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
			expectedKeys: []string{"rule-1", "rule-2"},
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
			backend:      &agenticv0alpha0.XBackend{},
			expectedKeys: []string{"allow-sa"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := &Translator{agenticIdentityTrustDomain: "cluster.local"}
			policies := tr.translateAccessPolicyToRBAC(tc.accessPolicy)
			if len(policies) != len(tc.expectedKeys) {
				t.Errorf("expected %d policies, got %d", len(tc.expectedKeys), len(policies))
			}

			for _, key := range tc.expectedKeys {
				verifyAccessRulePolicy(t, tc.accessPolicy, policies, key, tr.agenticIdentityTrustDomain)
			}

			// Optional: print keys found if failure
			if t.Failed() {
				found := make([]string, 0, len(policies))
				for k := range policies {
					found = append(found, k)
				}
				t.Logf("Found keys: %v", found)
			}
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

func verifyAccessRulePolicy(t *testing.T, policy *agenticv0alpha0.XAccessPolicy, rbacPolicies map[string]*rbacconfigv3.Policy, ruleName, trustDomain string) {
	rbacPolicy, ok := rbacPolicies[ruleName]
	if !ok {
		t.Errorf("expected policy with key %q not found", ruleName)
		return
	}

	var rule *agenticv0alpha0.AccessRule
	for i := range policy.Spec.Rules {
		if policy.Spec.Rules[i].Name == ruleName {
			rule = &policy.Spec.Rules[i]
			break
		}
	}
	if rule == nil {
		t.Errorf("rule %q not found in AccessPolicy", ruleName)
		return
	}

	expectedPrincipal := ""
	switch rule.Source.Type {
	case agenticv0alpha0.AuthorizationSourceTypeSPIFFE:
		if rule.Source.SPIFFE != nil {
			expectedPrincipal = string(*rule.Source.SPIFFE)
		}
	case agenticv0alpha0.AuthorizationSourceTypeServiceAccount:
		if rule.Source.ServiceAccount != nil {
			ns := rule.Source.ServiceAccount.Namespace
			if ns == "" {
				ns = policy.Namespace
			}
			// Convert K8s ServiceAccount to SPIFFE ID
			expectedPrincipal = convertSAtoSPIFFEID(trustDomain, ns, rule.Source.ServiceAccount.Name)
		}
	}

	if expectedPrincipal != "" {
		found := false
		for _, p := range rbacPolicy.Principals {
			auth := p.GetAuthenticated()
			if auth != nil && auth.PrincipalName.GetExact() == expectedPrincipal {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("rule %q: did not find expected principal %q", ruleName, expectedPrincipal)
		}
	}
}

// TestRbacConfigFromAccessPolicy_DeletionBehaviour tests that when no XAccessPolicy
// targets a backend (e.g. after the policy is deleted), the translator returns RBAC with
// no rules so that Envoy does not enforce RBAC (allow all). See Envoy RBAC docs: when
// rules are absent, no RBAC enforcement occurs.
func TestRbacConfigFromAccessPolicy_DeletionBehaviour(t *testing.T) {
	// Use a cache.Indexer to back the lister (simulates informer cache).
	// Empty indexer = no AccessPolicies = "after deletion" behaviour.
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	})
	lister := agenticlisters.NewXAccessPolicyLister(indexer)

	backend := &agenticv0alpha0.XBackend{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "my-backend",
		},
	}

	tr := &Translator{}
	rbacConfig, err := tr.rbacConfigFromAccessPolicy(lister, backend)
	if err != nil {
		t.Fatalf("rbacConfigFromAccessPolicy: %v", err)
	}

	if rbacConfig.GetRules() != nil {
		t.Errorf("expected no RBAC rules when no XAccessPolicy targets backend (deletion behaviour); rules present with %d policies", len(rbacConfig.GetRules().GetPolicies()))
	}
}

// TestRbacConfigFromAccessPolicy_PolicyExists_NoAllowAll tests that when an XAccessPolicy
// targets the backend, the config does not include the allow-all policy.
func TestRbacConfigFromAccessPolicy_PolicyExists_NoAllowAll(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	})

	policy := &agenticv0alpha0.XAccessPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "policy-1",
		},
		Spec: agenticv0alpha0.AccessPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: agenticv0alpha0.GroupName,
						Kind:  "XBackend",
						Name:  gatewayv1.ObjectName("my-backend"),
					},
				},
			},
			Rules: []agenticv0alpha0.AccessRule{
				{
					Name: "restrict-tools",
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
	}
	if err := indexer.Add(policy); err != nil {
		t.Fatalf("indexer.Add: %v", err)
	}

	lister := agenticlisters.NewXAccessPolicyLister(indexer)
	backend := &agenticv0alpha0.XBackend{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "my-backend",
		},
	}

	tr := &Translator{}
	rbacConfig, err := tr.rbacConfigFromAccessPolicy(lister, backend)
	if err != nil {
		t.Fatalf("rbacConfigFromAccessPolicy: %v", err)
	}

	policies := rbacConfig.GetRules().GetPolicies()
	if _, hasAllowAll := policies["allow-all"]; hasAllowAll {
		var keys []string
		for k := range policies {
			keys = append(keys, k)
		}
		t.Errorf("expected no allow-all policy when XAccessPolicy targets backend; policies: %v", keys)
	}
	if _, ok := policies["restrict-tools"]; !ok {
		var keys []string
		for k := range policies {
			keys = append(keys, k)
		}
		t.Errorf("expected policy-derived rule %q; policies: %v", "restrict-tools", keys)
	}
}
