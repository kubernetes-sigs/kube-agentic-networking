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
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"

	"sigs.k8s.io/kube-agentic-networking/api/v1alpha1"
	localfeatures "sigs.k8s.io/kube-agentic-networking/conformance/utils/features"
	"sigs.k8s.io/kube-agentic-networking/pkg/helpers"
)

var XAccessPolicySPIFFEMatching = suite.ConformanceTest{
	ShortName:   "XAccessPolicySPIFFEMatching",
	Description: "Verifies access is allowed for matched SPIFFE ID and denied for others (default deny).",
	Features:    []features.FeatureName{localfeatures.SupportAccessPolicyGateway, features.SupportGateway},
	Manifests:   []string{"tests/xaccesspolicy-spiffe-matching.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		namespace := "agentic-conformance-infra"
		policyName := types.NamespacedName{Name: "xaccesspolicy-spiffe-matching", Namespace: namespace}
		testerPodName := getTesterPodName(t, namespace)

		// 1. Wait for policy to be accepted
		t.Logf("Waiting for XAccessPolicy %s to be accepted", policyName)
		policy := &v1alpha1.XAccessPolicy{}
		err := wait.PollUntilContextCancel(ctx, 2*time.Second, true, func(ctx context.Context) (bool, error) {
			err := s.Client.Get(ctx, policyName, policy)
			if err != nil {
				t.Logf("Error getting XAccessPolicy: %v", err)
				return false, client.IgnoreNotFound(err)
			}
			return helpers.IsXAccessPolicyAccepted(policy), nil
		})
		require.NoError(t, err, "timed out waiting for XAccessPolicy to be accepted")

		// 2. Get Gateway IP
		gatewayName := types.NamespacedName{Name: "conformance-primary", Namespace: namespace}
		gatewayIP, err := kubernetes.WaitForGatewayAddress(t, s.Client, s.TimeoutConfig, kubernetes.NewGatewayRef(gatewayName))
		require.NoError(t, err, "failed to get gateway IP")

		// 3. Initialize MCP session
		mcp := initializeMCP(t, gatewayIP, namespace, testerPodName)

		// 4. Call 'get-sum' (should succeed)
		t.Log("Verifying 'get-sum' is allowed")
		mcp.assertToolCall(t, "get-sum", `{"a":2,"b":3}`, mcpResponse{
			StatusCode: 200,
			Body: respBody{
				Result: &mcpResult{
					IsError: false,
					Content: []mcpContent{
						{
							Type: "text",
							Text: "The sum of 2 and 3 is 5.",
						},
					},
				},
			},
		})

		// 5. Call 'echo' (should be denied with 403 in JSON-RPC)
		t.Log("Verifying 'echo' is denied")
		err = mcp.checkToolCall(t, "echo", `{"message":"hello"}`, mcpResponse{
			StatusCode: 200,
			Body: respBody{
				Error: &mcpError{
					Code:    403,
					Message: "Access to this tool is forbidden.",
				},
			},
		})
		require.NoError(t, err, "expected tool call to be denied with 403 in JSON-RPC")
	},
}

func init() {
	ConformanceTests = append(ConformanceTests, XAccessPolicySPIFFEMatching)
}
