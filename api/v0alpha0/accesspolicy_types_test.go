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

package v0alpha0

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestXAccessPolicyIsAccepted(t *testing.T) {
	tests := []struct {
		name     string
		status   AccessPolicyStatus
		expected bool
	}{
		{
			name:     "no ancestors (empty status)",
			status:   AccessPolicyStatus{},
			expected: false,
		},
		{
			name: "all ancestors accepted",
			status: AccessPolicyStatus{
				Ancestors: []gwapiv1.PolicyAncestorStatus{
					{
						Conditions: []metav1.Condition{
							{
								Type:   string(PolicyConditionAccepted),
								Status: metav1.ConditionTrue,
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "one ancestor rejected",
			status: AccessPolicyStatus{
				Ancestors: []gwapiv1.PolicyAncestorStatus{
					{
						Conditions: []metav1.Condition{
							{
								Type:   string(PolicyConditionAccepted),
								Status: metav1.ConditionTrue,
							},
						},
					},
					{
						Conditions: []metav1.Condition{
							{
								Type:   string(PolicyConditionAccepted),
								Status: metav1.ConditionFalse,
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "no accepted condition type present",
			status: AccessPolicyStatus{
				Ancestors: []gwapiv1.PolicyAncestorStatus{
					{
						Conditions: []metav1.Condition{
							{
								Type:   "SomeOtherCondition",
								Status: metav1.ConditionTrue,
							},
						},
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &XAccessPolicy{
				Status: tt.status,
			}
			if got := p.IsAccepted(); got != tt.expected {
				t.Errorf("XAccessPolicy.IsAccepted() = %v, want %v", got, tt.expected)
			}
		})
	}
}
