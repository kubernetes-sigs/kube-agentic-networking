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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"

	"sigs.k8s.io/kube-agentic-networking/api/v1alpha1"
	localfeatures "sigs.k8s.io/kube-agentic-networking/conformance/utils/features"
	"sigs.k8s.io/kube-agentic-networking/pkg/helpers"
)

var XAccessPolicyBaseProtocolSkip = suite.ConformanceTest{
	ShortName:   "XAccessPolicyBaseProtocolSkip",
	Description: "Verifies that base protocol methods (like initialize) are denied when SKIP_BASE_PROTOCOL_METHODS is set.",
	Features:    []features.FeatureName{localfeatures.SupportAccessPolicyGateway, features.SupportGateway},
	Manifests:   []string{"tests/xaccesspolicy-base-protocol-skip.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		namespace := "agentic-conformance-infra"
		policyName := types.NamespacedName{Name: "xaccesspolicy-base-protocol-skip", Namespace: namespace}

		// 1. Wait for policy to be accepted
		t.Logf("Waiting for XAccessPolicy %s to be accepted", policyName)
		policy := &v1alpha1.XAccessPolicy{}
		err := wait.PollUntilContextCancel(ctx, 2*time.Second, true, func(ctx context.Context) (bool, error) {
			getErr := s.Client.Get(ctx, policyName, policy)
			if getErr != nil {
				t.Logf("Error getting XAccessPolicy: %v", getErr)
				return false, client.IgnoreNotFound(getErr)
			}
			return helpers.IsXAccessPolicyAccepted(policy), nil
		})
		require.NoError(t, err, "timed out waiting for XAccessPolicy to be accepted")

		// 2. Get Gateway IP
		gatewayName := types.NamespacedName{Name: "conformance-primary", Namespace: namespace}
		gatewayIP, err := kubernetes.WaitForGatewayAddress(t, s.Client, s.TimeoutConfig, kubernetes.NewGatewayRef(gatewayName))
		require.NoError(t, err, "failed to get gateway IP")

		// 3. Find tester pod name
		testerPodName := getTesterPodName(t, namespace)

		// 4. Try to initialize MCP session (should fail with 403)
		t.Log("Verifying MCP initialization is denied")
		err = retry(15, 2*time.Second, func() error {
			out, execErr := execMCPCurl(t, gatewayIP, namespace, testerPodName)
			if execErr != nil {
				return execErr // kubectl error
			}
			if !strings.Contains(out, "403") {
				return fmt.Errorf("expected 403 Forbidden, got response: %s", out)
			}
			return nil
		})
		require.NoError(t, err, "expected initialization to be denied")
	},
}

func init() {
	ConformanceTests = append(ConformanceTests, XAccessPolicyBaseProtocolSkip)
}
