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
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"

	"sigs.k8s.io/kube-agentic-networking/api/v1alpha1"
	localfeatures "sigs.k8s.io/kube-agentic-networking/conformance/utils/features"
	"sigs.k8s.io/kube-agentic-networking/pkg/helpers"
)

var XAccessPolicyExtAuthLimit = suite.ConformanceTest{
	ShortName:   "XAccessPolicyExtAuthLimit",
	Description: "Verifies that only one ExternalAuth policy is accepted per target, and subsequent ones are rejected.",
	Features:    []features.FeatureName{localfeatures.SupportAccessPolicyGateway},
	Manifests:   []string{"tests/xaccesspolicy-extauth-limit.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		policy1Name := types.NamespacedName{Name: "xaccesspolicy-extauth-limit-1", Namespace: "agentic-conformance-infra"}
		policy2Name := types.NamespacedName{Name: "xaccesspolicy-extauth-limit-2", Namespace: "agentic-conformance-infra"}

		// 1. Verify policy 1 (senior) is accepted
		t.Logf("Waiting for senior XAccessPolicy %s to be accepted", policy1Name)
		policy1 := &v1alpha1.XAccessPolicy{}
		err := wait.PollUntilContextCancel(ctx, 2*time.Second, true, func(ctx context.Context) (bool, error) {
			err := suite.Client.Get(ctx, policy1Name, policy1)
			if err != nil {
				t.Logf("Error getting XAccessPolicy 1: %v", err)
				return false, client.IgnoreNotFound(err)
			}
			return helpers.IsXAccessPolicyAccepted(policy1), nil
		})
		require.NoError(t, err, "timed out waiting for senior XAccessPolicy to be accepted")

		// 2. Verify policy 2 (junior) is rejected with LimitPerTargetExceeded
		t.Logf("Waiting for junior XAccessPolicy %s to be rejected with LimitPerTargetExceeded", policy2Name)
		policy2 := &v1alpha1.XAccessPolicy{}
		err = wait.PollUntilContextCancel(ctx, 2*time.Second, true, func(ctx context.Context) (bool, error) {
			err := suite.Client.Get(ctx, policy2Name, policy2)
			if err != nil {
				t.Logf("Error getting XAccessPolicy 2: %v", err)
				return false, client.IgnoreNotFound(err)
			}

			// We check if it has Accepted=False with reason LimitPerTargetExceeded
			rejected := hasCondition(policy2, string(v1alpha1.PolicyConditionAccepted), metav1.ConditionFalse, string(v1alpha1.PolicyLimitPerTargetExceeded))
			t.Logf("XAccessPolicy %s rejected status: %v", policy2Name.Name, rejected)
			return rejected, nil
		})
		require.NoError(t, err, "timed out waiting for junior XAccessPolicy to be rejected")
	},
}

func hasCondition(policy *v1alpha1.XAccessPolicy, condType string, status metav1.ConditionStatus, reason string) bool {
	for _, ancestor := range policy.Status.Ancestors {
		cond := meta.FindStatusCondition(ancestor.Conditions, condType)
		if cond != nil && cond.Status == status && cond.Reason == reason {
			return true
		}
	}
	return false
}

func init() {
	ConformanceTests = append(ConformanceTests, XAccessPolicyExtAuthLimit)
}
