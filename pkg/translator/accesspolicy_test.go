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
	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
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
