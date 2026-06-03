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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"

	"sigs.k8s.io/kube-agentic-networking/api/v1alpha1"
	localfeatures "sigs.k8s.io/kube-agentic-networking/conformance/utils/features"
	"sigs.k8s.io/kube-agentic-networking/pkg/helpers"
)

var XAccessPolicyExtAuthAccepted = suite.ConformanceTest{
	ShortName:   "XAccessPolicyExtAuthAccepted",
	Description: "Verifies that a valid XAccessPolicy with ExternalAuth action targeting a Gateway is accepted by the controller.",
	Features:    []features.FeatureName{localfeatures.SupportAccessPolicyGateway},
	Manifests:   []string{"tests/xaccesspolicy-extauth-accepted.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		policy := &v1alpha1.XAccessPolicy{}
		policyName := types.NamespacedName{Name: "xaccesspolicy-extauth-accepted", Namespace: "agentic-conformance-infra"}

		t.Logf("Waiting for XAccessPolicy %s to be accepted", policyName)

		err := wait.PollUntilContextCancel(ctx, 2*time.Second, true, func(ctx context.Context) (bool, error) {
			err := suite.Client.Get(ctx, policyName, policy)
			if err != nil {
				t.Logf("Error getting XAccessPolicy: %v", err)
				return false, client.IgnoreNotFound(err)
			}

			accepted := helpers.IsXAccessPolicyAccepted(policy)
			t.Logf("XAccessPolicy %s Accepted condition: %v", policyName.Name, accepted)

			return accepted, nil
		})
		require.NoError(t, err, "timed out waiting for XAccessPolicy to be accepted")
	},
}

func init() {
	ConformanceTests = append(ConformanceTests, XAccessPolicyExtAuthAccepted)
}
