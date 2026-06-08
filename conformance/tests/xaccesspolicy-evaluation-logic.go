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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

var XAccessPolicyEvaluationLogic = suite.ConformanceTest{
	ShortName:   "XAccessPolicyEvaluationLogic",
	Description: "Verifies the interaction between ExternalAuth and Allow policies targeting the same Gateway.",
	Features:    []features.FeatureName{localfeatures.SupportAccessPolicyGateway, features.SupportGateway},
	Manifests:   []string{"tests/xaccesspolicy-evaluation-logic.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		namespace := "agentic-conformance-infra"
		extAuthPolicyName := types.NamespacedName{Name: "xaccesspolicy-eval-extauth", Namespace: namespace}
		allowPolicyName := types.NamespacedName{Name: "xaccesspolicy-eval-allow", Namespace: namespace}
		testerPodName := getTesterPodName(t, namespace)

		// 1. Wait for Authorino deployment to be available
		t.Log("Waiting for Authorino deployment to be available")
		err := wait.PollUntilContextCancel(ctx, 5*time.Second, true, func(ctx context.Context) (bool, error) {
			dep, getErr := s.Clientset.AppsV1().Deployments(namespace).Get(ctx, "authorino", metav1.GetOptions{})
			if getErr != nil {
				return false, client.IgnoreNotFound(getErr)
			}
			return dep.Status.AvailableReplicas > 0, nil
		})
		require.NoError(t, err, "timed out waiting for Authorino deployment")

		// 2. Wait for policies to be accepted
		t.Logf("Waiting for XAccessPolicy %s to be accepted", extAuthPolicyName)
		extAuthPolicy := &v1alpha1.XAccessPolicy{}
		err = wait.PollUntilContextCancel(ctx, 2*time.Second, true, func(ctx context.Context) (bool, error) {
			getErr := s.Client.Get(ctx, extAuthPolicyName, extAuthPolicy)
			if getErr != nil {
				t.Logf("Error getting ExternalAuth policy: %v", getErr)
				return false, client.IgnoreNotFound(getErr)
			}
			return helpers.IsXAccessPolicyAccepted(extAuthPolicy), nil
		})
		require.NoError(t, err, "timed out waiting for ExternalAuth XAccessPolicy to be accepted")

		t.Logf("Waiting for XAccessPolicy %s to be accepted", allowPolicyName)
		allowPolicy := &v1alpha1.XAccessPolicy{}
		err = wait.PollUntilContextCancel(ctx, 2*time.Second, true, func(ctx context.Context) (bool, error) {
			getErr := s.Client.Get(ctx, allowPolicyName, allowPolicy)
			if getErr != nil {
				t.Logf("Error getting Allow policy: %v", getErr)
				return false, client.IgnoreNotFound(getErr)
			}
			return helpers.IsXAccessPolicyAccepted(allowPolicy), nil
		})
		require.NoError(t, err, "timed out waiting for Allow XAccessPolicy to be accepted")

		// 3. Get Gateway IP
		gatewayName := types.NamespacedName{Name: "conformance-primary", Namespace: namespace}
		gatewayIP, err := kubernetes.WaitForGatewayAddress(t, s.Client, s.TimeoutConfig, kubernetes.NewGatewayRef(gatewayName))
		require.NoError(t, err, "failed to get gateway IP")

		// 4. Initialize MCP session
		mcp := initializeMCP(t, gatewayIP, namespace, testerPodName)

		// 5. Call 'get-sum' (should succeed)
		t.Log("Verifying 'get-sum' is allowed (both policies allow)")
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

		// 6. Call 'get-env' (should be denied with 403 in JSON-RPC)
		t.Log("Verifying 'get-env' is denied (denied by Allow policy)")
		mcp.assertToolCall(t, "get-env", `{}`, mcpResponse{
			StatusCode: 200,
			Body: respBody{
				Error: &mcpError{
					Code:    403,
					Message: "Access to this tool is forbidden.",
				},
			},
		})

		// 7. Call 'echo' (should be denied with 403 in JSON-RPC)
		t.Log("Verifying 'echo' is denied (denied by ExternalAuth policy)")
		mcp.assertToolCall(t, "echo", `{"message":"hello"}`, mcpResponse{
			StatusCode: 200,
			Body: respBody{
				Error: &mcpError{
					Code:    403,
					Message: "Access to this tool is forbidden.",
				},
			},
		})
	},
}

func init() {
	ConformanceTests = append(ConformanceTests, XAccessPolicyEvaluationLogic)
}
