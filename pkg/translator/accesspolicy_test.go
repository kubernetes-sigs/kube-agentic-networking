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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policies := translateAccessPolicyToRBAC(tc.accessPolicy, tc.backend)
			if len(policies) != len(tc.expectedKeys) {
				t.Errorf("expected %d policies, got %d", len(tc.expectedKeys), len(policies))
			}

			for _, key := range tc.expectedKeys {
				if _, ok := policies[key]; !ok {
					t.Errorf("expected policy with key %q not found", key)
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
		})
	}
}

// TestRbacConfigFromAccessPolicy_DeletionBehaviour tests that when no XAccessPolicy
// targets a backend (e.g. after the policy is deleted), the translator produces RBAC
// config with an allow-all policy so that all tool calls are allowed.
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

	rbacConfig, err := rbacConfigFromAccessPolicy(lister, backend)
	if err != nil {
		t.Fatalf("rbacConfigFromAccessPolicy: %v", err)
	}

	policies := rbacConfig.GetRules().GetPolicies()
	if _, hasAllowAll := policies["allow-all"]; !hasAllowAll {
		var keys []string
		for k := range policies {
			keys = append(keys, k)
		}
		t.Errorf("expected allow-all policy when no XAccessPolicy targets backend (deletion behaviour); policies: %v", keys)
	}
	for _, name := range []string{"allow-mcp-session-close", "allow-anyone-to-initialize-and-list-tools", "allow-http-get"} {
		if _, ok := policies[name]; !ok {
			t.Errorf("expected common policy %q", name)
		}
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

	rbacConfig, err := rbacConfigFromAccessPolicy(lister, backend)
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
