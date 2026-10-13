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

package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"

	"sigs.k8s.io/kube-agentic-networking/api/v1alpha1"
	localfeatures "sigs.k8s.io/kube-agentic-networking/conformance/utils/features"
)

var XAccessPolicyProgrammed = suite.ConformanceTest{
	ShortName:   "XAccessPolicyProgrammed",
	Description: "Verifies that an accepted XAccessPolicy reports Programmed after data plane configuration.",
	Features:    []features.FeatureName{localfeatures.SupportAccessPolicyGateway, features.SupportGateway},
	Manifests:   []string{"tests/xaccesspolicy-programmed.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		policyName := types.NamespacedName{Name: "xaccesspolicy-programmed", Namespace: "agentic-conformance-infra"}
		policy := &v1alpha1.XAccessPolicy{}

		err := wait.PollUntilContextCancel(ctx, 2*time.Second, true, func(ctx context.Context) (bool, error) {
			if err := s.Client.Get(ctx, policyName, policy); err != nil {
				t.Logf("Error getting XAccessPolicy: %v", err)
				return false, client.IgnoreNotFound(err)
			}

			for _, ancestor := range policy.Status.Ancestors {
				if ancestor.AncestorRef.Group == nil || string(*ancestor.AncestorRef.Group) != gatewayv1.GroupName ||
					ancestor.AncestorRef.Kind == nil || string(*ancestor.AncestorRef.Kind) != "Gateway" ||
					string(ancestor.AncestorRef.Name) != "conformance-primary" {
					continue
				}

				condition := meta.FindStatusCondition(ancestor.Conditions, string(v1alpha1.PolicyConditionProgrammed))
				if condition == nil {
					t.Log("Waiting for Programmed condition")
					return false, nil
				}
				t.Logf("XAccessPolicy %s Programmed condition: status=%s reason=%s", policyName.Name, condition.Status, condition.Reason)
				return condition.Status == metav1.ConditionTrue &&
					condition.Reason == string(v1alpha1.PolicyReasonProgrammed) &&
					condition.ObservedGeneration == policy.Generation, nil
			}

			return false, nil
		})
		require.NoError(t, err, "timed out waiting for XAccessPolicy to be programmed")
	},
}

func init() {
	ConformanceTests = append(ConformanceTests, XAccessPolicyProgrammed)
}
