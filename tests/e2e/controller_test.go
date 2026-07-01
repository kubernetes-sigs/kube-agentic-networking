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

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/agentidentity/localca"
)

const (
	agentCertPath = "/run/agent-identity-mtls/credential-bundle.pem"
	agentKeyPath  = "/run/agent-identity-mtls/credential-bundle.pem"
	agentCAPath   = "/run/agent-identity-mtls/cluster.local.trust-bundle.pem"

	testClientCertPath = "/tmp/mtls-client/tls.crt"
	testClientKeyPath  = "/tmp/mtls-client/tls.key"
	testClientCAPath   = "/tmp/mtls-client/ca.crt"

	defaultMCPPath = "/mcp"
)

// TestControllerE2E verifies the core functionality of the agentic networking controller including:
// - Resource reconciliation on CRUD operations for Gateway, HTTPRoute, XBackend, and XAccessPolicy.
// - Dynamic xDS configuration updates to Envoy proxies.
// - mTLS authentication verification between the client and the proxy.
// - Multi-level authorization enforcement at both Gateway and Backend scopes.
// - Correctness of the generated Envoy configuration for policy enforcement.
func TestControllerE2E(t *testing.T) {
	t.Parallel()

	namespace, gatewayIP, cleanup := deployCommonTestResources(t)
	defer cleanup()

	// Desploy the tester pod
	applyToNamespace(t, "testdata/tester-pod.yaml", namespace)
	runKubectl(t, "wait", "--for=condition=Ready", "pod/e2e-tester", "-n", namespace, "--timeout=5m")

	// Initialize MCP session
	mcp := initializeMCP(t, gatewayIP, types.NamespacedName{Namespace: namespace, Name: "e2e-tester"})

	t.Run("Case 1: No policy applied (all allowed)", func(t *testing.T) {
		mcp.assertToolCall(t, "get-sum", `{"a":2,"b":3}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
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
			},
		)

		mcp.assertToolCall(t, "echo", `{"message":"hello"}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Result: &mcpResult{
						IsError: false,
						Content: []mcpContent{
							{
								Type: "text",
								Text: "Echo: hello",
							},
						},
					},
				},
			})
	})

	t.Run("Case 2: Only backend policy (allows get-sum)", func(t *testing.T) {
		applyToNamespace(t, "testdata/backend-policy.yaml", namespace)
		mcp.assertToolCall(t, "get-sum", `{"a":2,"b":3}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
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
			},
		)

		mcp.assertToolCall(t, "echo", `{"message":"hello"}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Error: &mcpError{
						Code:    403,
						Message: "Access to this tool is forbidden.",
					},
				},
			},
		)
	})

	t.Run("Case 3: Only gateway policy (allows echo)", func(t *testing.T) {
		deleteFromNamespace(t, "testdata/backend-policy.yaml", namespace)
		applyToNamespace(t, "testdata/gateway-policy.yaml", namespace)
		mcp.assertToolCall(t, "get-sum", `{"a":2,"b":3}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Error: &mcpError{
						Code:    403,
						Message: "Access to this tool is forbidden.",
					},
				},
			},
		)

		mcp.assertToolCall(t, "echo", `{"message":"hello"}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Result: &mcpResult{
						IsError: false,
						Content: []mcpContent{
							{
								Type: "text",
								Text: "Echo: hello",
							},
						},
					},
				},
			})
	})

	t.Run("Case 4: Both policies (GW: echo, BE: get-sum)", func(t *testing.T) {
		applyToNamespace(t, "testdata/backend-policy.yaml", namespace)
		mcp.assertToolCall(t, "get-sum", `{"a":2,"b":3}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Error: &mcpError{
						Code:    403,
						Message: "Access to this tool is forbidden.",
					},
				},
			},
		)
		mcp.assertToolCall(t, "echo", `{"message":"hello"}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Error: &mcpError{
						Code:    403,
						Message: "Access to this tool is forbidden.",
					},
				},
			},
		)
	})

	t.Run("Case 5: Patch Gateway policy to allow get-sum", func(t *testing.T) {
		// Modifying Gateway Policy: Allowing 'get-sum' to align with Backend policy.
		patchGW := `[{"op": "replace", "path": "/spec/rules/0/authorization/mcp/methods", "value": [{"name": "tools/call", "params": ["get-sum"]}]}]`
		runKubectl(t, "patch", "xaccesspolicy", "e2e-gateway-level-policy", "-n", namespace, "--type=json", "-p", patchGW)

		mcp.assertToolCall(t, "get-sum", `{"a":2,"b":3}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
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
			},
		)
	})

	t.Run("Case 6: CEL policy (allows only get-sum)", func(t *testing.T) {
		// Clean up previous policies first to avoid interference
		runKubectl(t, "delete", "xaccesspolicy", "e2e-gateway-level-policy", "-n", namespace, "--ignore-not-found")
		deleteFromNamespace(t, "testdata/backend-policy.yaml", namespace)

		applyToNamespace(t, "testdata/cel-policy.yaml", namespace)

		mcp.assertToolCall(t, "get-sum", `{"a":2,"b":3}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
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
			},
		)

		mcp.assertToolCall(t, "echo", `{"message":"hello"}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Error: &mcpError{
						Code:    403,
						Message: "Access to this tool is forbidden.",
					},
				},
			},
		)
	})

	t.Run("Case 7: CEL policy - All failures (allows nothing)", func(t *testing.T) {
		deleteFromNamespace(t, "testdata/cel-policy.yaml", namespace)
		applyToNamespace(t, "testdata/cel-all-failures.yaml", namespace)

		mcp.assertToolCall(t, "get-sum", `{"a":2,"b":3}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Error: &mcpError{
						Code:    403,
						Message: "Access to this tool is forbidden.",
					},
				},
			},
		)

		mcp.assertToolCall(t, "echo", `{"message":"hello"}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Error: &mcpError{
						Code:    403,
						Message: "Access to this tool is forbidden.",
					},
				},
			},
		)
	})

	t.Run("Case 8: CEL policy - Mix of failure and success (allows get-sum)", func(t *testing.T) {
		deleteFromNamespace(t, "testdata/cel-all-failures.yaml", namespace)
		applyToNamespace(t, "testdata/cel-multi-rule.yaml", namespace)

		mcp.assertToolCall(t, "get-sum", `{"a":2,"b":3}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
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
			},
		)

		mcp.assertToolCall(t, "echo", `{"message":"hello"}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Error: &mcpError{
						Code:    403,
						Message: "Access to this tool is forbidden.",
					},
				},
			},
		)
	})

	// Case 9: CEL policy - Macros and functions
	t.Run("Case 9: CEL policy - Macros and functions (startsWith, contains, matches)", func(t *testing.T) {
		deleteFromNamespace(t, "testdata/cel-multi-rule.yaml", namespace)
		applyToNamespace(t, "testdata/cel-macros.yaml", namespace)

		// get-sum satisfies startsWith('/mc'), contains('2025'), and matches('^get-[a-z]+$')
		mcp.assertToolCall(t, "get-sum", `{"a":2,"b":3}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
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
			},
		)

		// echo fails the regex match for request.mcp.tool_name.matches('^get-[a-z]+$')
		mcp.assertToolCall(t, "echo", `{"message":"hello"}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Error: &mcpError{
						Code:    403,
						Message: "Access to this tool is forbidden.",
					},
				},
			},
		)
	})

	// --- Individual CEL Variable Tests via Dynamic Patching ---
	t.Run("Cases 10-15: CEL policy - Individual Native Variables", func(t *testing.T) {
		// Clean up previous policies
		deleteFromNamespace(t, "testdata/cel-macros.yaml", namespace)

		// Apply the base CEL policy
		applyToNamespace(t, "testdata/cel-policy.yaml", namespace)

		celCases := []struct {
			name           string
			validExpr      string
			failExpression string
		}{
			{"request.path", "request.path == '/mcp'", "request.path == '/wrong'"},
			{"request.url_path", "request.url_path == '/mcp'", "request.url_path == '/wrong'"},
			{"request.method", "request.method == 'POST'", "request.method == 'GET'"},
			{"request.host", "request.host.endsWith(':10001')", "request.host.endsWith(':9999')"},
			{"request.headers", "request.headers['mcp-protocol-version'] == '2025-11-25'", "request.headers['mcp-protocol-version'] == '1999-01-01'"},
			{"request.time", "request.time.getFullYear() >= 2025", "request.time.getFullYear() < 2000"},
		}

		for _, tc := range celCases {
			t.Logf("Testing CEL native variable: %s", tc.name)

			// 1. Success Path: Patch to valid expression
			validPatch := `[{"op": "replace", "path": "/spec/rules/0/authorization/cel/expression", "value": "` + tc.validExpr + `"}]`
			runKubectl(t, "patch", "xaccesspolicy", "e2e-cel-policy", "-n", namespace, "--type=json", "-p", validPatch)

			mcp.assertToolCall(t, "get-sum", `{"a":2,"b":3}`,
				mcpResponse{
					StatusCode: 200,
					Body: respBody{
						JSONRPC: "2.0",
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
				},
			)

			// 2. Failure Path: Patch to invalid expression
			failPatch := `[{"op": "replace", "path": "/spec/rules/0/authorization/cel/expression", "value": "` + tc.failExpression + `"}]`
			runKubectl(t, "patch", "xaccesspolicy", "e2e-cel-policy", "-n", namespace, "--type=json", "-p", failPatch)

			mcp.assertToolCall(t, "get-sum", `{"a":2,"b":3}`,
				mcpResponse{
					StatusCode: 200,
					Body: respBody{
						JSONRPC: "2.0",
						Error: &mcpError{
							Code:    403,
							Message: "Access to this tool is forbidden.",
						},
					},
				},
			)
		}
	})
}

// TestExternalAuthE2E verifies the ExternalAuth authorization feature including:
// - External authorization service deployment and integration
// - Combined Inline and ExternalAuth policies at the backend level
// - ExternalAuth policy at the gateway level
// - Multi-client authorization with different ServiceAccounts
func TestExternalAuthE2E(t *testing.T) {
	t.Parallel()

	namespace, gatewayIP, cleanup := deployCommonTestResources(t)
	defer cleanup()

	// Deploy the tester pods
	t.Log("Deploying tester pods...")
	applyToNamespace(t, "testdata/tester-pod.yaml", namespace)
	applyToNamespace(t, "testdata/tester-pod-2.yaml", namespace)
	runKubectl(t, "wait", "--for=condition=Ready", "pod/e2e-tester", "-n", namespace, "--timeout=5m")
	runKubectl(t, "wait", "--for=condition=Ready", "pod/e2e-tester-2", "-n", namespace, "--timeout=5m")

	// Deploy External Auth service
	t.Log("Deploying External Auth service...")
	runKubectl(t, "apply", "--server-side", "-f", "https://raw.githubusercontent.com/Kuadrant/authorino/refs/tags/v0.24.0/install/manifests.yaml")
	runKubectl(t, "wait", "--for=condition=established", "crd/authconfigs.authorino.kuadrant.io", "--timeout=1m")
	applyToNamespace(t, "testdata/ext-authz-service.yaml", namespace)
	runKubectl(t, "wait", "--for=condition=available", "deployment/authorino", "-n", namespace, "--timeout=2m")
	err := retry(20, 2*time.Second, func() error {
		out, err := runKubectlOutput(t, "get", "authconfig", "external-auth-config", "-n", namespace, "-o", "jsonpath={.status.summary.ready}")
		if err != nil {
			return err
		}
		if out != "true" {
			return fmt.Errorf("authconfig not ready yet: %s", out)
		}
		return nil
	})
	if err != nil {
		t.Logf("Warning: AuthConfig status check failed: %v (continuing anyway)", err)
	} else {
		t.Log("AuthConfig is ready")
	}

	// Initialize MCP sessions for both testers
	mcp1 := initializeMCP(t, gatewayIP, types.NamespacedName{Namespace: namespace, Name: "e2e-tester"})
	mcp2 := initializeMCP(t, gatewayIP, types.NamespacedName{Namespace: namespace, Name: "e2e-tester-2"})

	t.Run("Case 1: Combined backend policy - Inline (tester-1) + ExternalAuth (tester-2)", func(t *testing.T) {
		applyToNamespace(t, "testdata/backend-policy-extauth.yaml", namespace)

		// tester-1 with Inline: can call echo and get-sum
		t.Log("Testing tester-1 (Inline: echo, get-sum allowed)")
		mcp1.assertToolCall(t, "echo", `{"message":"hello"}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Result: &mcpResult{
						IsError: false,
						Content: []mcpContent{
							{
								Type: "text",
								Text: "Echo: hello",
							},
						},
					},
				},
			})

		mcp1.assertToolCall(t, "get-sum", `{"a":2,"b":3}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
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

		mcp1.assertToolCall(t, "get-env", `{}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Error: &mcpError{
						Code:    403,
						Message: "Access to this tool is forbidden.",
					},
				},
			})

		// tester-2 with ExternalAuth: can call get-sum and get-env (per AuthConfig)
		t.Log("Testing tester-2 (ExternalAuth: get-sum, get-env allowed per AuthConfig)")
		mcp2.assertToolCall(t, "get-sum", `{"a":5,"b":7}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Result: &mcpResult{
						IsError: false,
						Content: []mcpContent{
							{
								Type: "text",
								Text: "The sum of 5 and 7 is 12.",
							},
						},
					},
				},
			})

		mcp2.assertToolCall(t, "get-env", `{}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Result: &mcpResult{
						IsError: false,
					},
				},
			})

		mcp2.assertToolCall(t, "echo", `{"message":"world"}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Error: &mcpError{
						Code:    403,
						Message: "Access to this tool is forbidden.",
					},
				},
			})
	})

	t.Run("Case 2: Gateway-level ExternalAuth policy (all requests go through external auth)", func(t *testing.T) {
		deleteFromNamespace(t, "testdata/backend-policy-extauth.yaml", namespace)
		applyToNamespace(t, "testdata/gateway-policy-extauth.yaml", namespace)

		// Both testers should now be subject to the same ExternalAuth rules
		t.Log("Testing tester-1 with gateway-level ExternalAuth")
		mcp1.assertToolCall(t, "get-sum", `{"a":10,"b":20}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Result: &mcpResult{
						IsError: false,
						Content: []mcpContent{
							{
								Type: "text",
								Text: "The sum of 10 and 20 is 30.",
							},
						},
					},
				},
			})

		mcp1.assertToolCall(t, "get-env", `{}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Result: &mcpResult{
						IsError: false,
					},
				},
			})

		mcp1.assertToolCall(t, "echo", `{"message":"test"}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Error: &mcpError{
						Code:    403,
						Message: "Access to this tool is forbidden.",
					},
				},
			})

		t.Log("Testing tester-2 with gateway-level ExternalAuth")
		mcp2.assertToolCall(t, "get-sum", `{"a":3,"b":4}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Result: &mcpResult{
						IsError: false,
						Content: []mcpContent{
							{
								Type: "text",
								Text: "The sum of 3 and 4 is 7.",
							},
						},
					},
				},
			})

		mcp2.assertToolCall(t, "echo", `{"message":"gateway"}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Error: &mcpError{
						Code:    403,
						Message: "Access to this tool is forbidden.",
					},
				},
			})
	})
}

func createTestNamespace(t *testing.T, name string) (cleanup func()) {
	t.Log("Creating E2E test namespace")
	runKubectl(t, "delete", "namespace", name, "--ignore-not-found")
	runKubectl(t, "create", "namespace", name)

	return func() {
		if t.Failed() {
			t.Logf("Skipping resource cleanup due to test failure. Inspect resources in '%s' namespace.", name)
			return
		}
		t.Logf("🎉🎉 %s Passed!", t.Name())
		t.Log("Cleaning up E2E test resources...")
		runKubectl(t, "delete", "namespace", name, "--ignore-not-found")
	}
}

// deployCommonTestResources creates the test namespace and deploys the common necessary resources for the E2E
// tests including the MCP server, Gateway, HTTPRoute, and XBackend. It waits for the resources to be ready and
// returns the namespace, Gateway IP address, and a cleanup function to delete the created resources after the test.
func deployCommonTestResources(t *testing.T) (namespace, gatewayIP string, cleanup func()) {
	namespace = fmt.Sprintf("e2e-test-ns-%s", utilrand.String(5))
	cleanup = createTestNamespace(t, namespace)

	t.Log("Setting up E2E test resources...")

	// MCP server
	applyToNamespace(t, "testdata/mcpserver.yaml", namespace)
	runKubectl(t, "wait", "--for=condition=available", "deployment/mcp-everything", "-n", namespace, "--timeout=2m")

	// Gateway, HTTPRoute and XBackend resources
	applyToNamespace(t, "testdata/e2e-resources.yaml", namespace)

	var proxyPodName string
	err := retry(20, 5*time.Second, func() error {
		out, err := runKubectlOutput(t, "get", "pods", "-n", namespace, "-l", fmt.Sprintf("%s=e2e-gateway", constants.GatewayNameLabel), "-o", "jsonpath={.items[*].metadata.name}")
		if err != nil {
			return err
		}
		names := strings.Fields(strings.TrimSpace(out))
		if len(names) == 0 {
			return fmt.Errorf("envoy proxy pod not found")
		}
		proxyPodName = names[0]
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to find envoy proxy pod: %v", err)
	}
	runKubectl(t, "wait", "--for=condition=Ready", "pod/"+proxyPodName, "-n", namespace, "--timeout=5m")

	// Return the Gateway IP
	t.Log("Obtain Gateway Address from status")

	err = retry(50, 10*time.Second, func() error {
		out, e := runKubectlOutput(t, "get", "gateway", "e2e-gateway", "-n", namespace, "-o", "jsonpath={.status.addresses[*].value}")
		if e != nil {
			return e
		}
		values := strings.Fields(strings.TrimSpace(out))
		if len(values) == 0 {
			return fmt.Errorf("gateway status address not found")
		}
		gatewayIP = values[0]
		t.Logf("Found Gateway status address: %s", gatewayIP)
		return nil
	})
	if err != nil {
		t.Fatalf("Gateway status verification failed: %v", err)
	}
	return namespace, gatewayIP, cleanup
}

func runKubectl(t *testing.T, args ...string) {
	cmd := exec.CommandContext(context.Background(), "kubectl", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("kubectl %v failed: %v\nStderr: %s", args, err, stderr.String())
	}
}

// applyToNamespace reads a manifest file, replaces all occurrences of "e2e-test-ns"
// with the actual namespace, and applies it to the cluster.
func applyToNamespace(t *testing.T, manifestPath, namespace string) {
	applyManifestReplacing(t, manifestPath, namespace, "e2e-test-ns")
}

// applyManifestReplacing reads a manifest file, replaces placeholderNamespace with namespace, and applies it.
func applyManifestReplacing(t *testing.T, manifestPath, namespace, placeholderNamespace string) {
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read manifest %s: %v", manifestPath, err)
	}

	modifiedContent := strings.ReplaceAll(string(content), placeholderNamespace, namespace)

	cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(modifiedContent)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("kubectl apply failed for %s: %v\nStderr: %s", manifestPath, err, stderr.String())
	}
}

// deleteFromNamespace reads a manifest file, replaces all occurrences of "e2e-test-ns"
// with the actual namespace, and deletes it from the cluster.
func deleteFromNamespace(t *testing.T, manifestPath, namespace string) {
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read manifest %s: %v", manifestPath, err)
	}

	// Replace all occurrences of e2e-test-ns with the actual namespace
	modifiedContent := strings.ReplaceAll(string(content), "e2e-test-ns", namespace)

	cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "--ignore-not-found", "-f", "-")
	cmd.Stdin = strings.NewReader(modifiedContent)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("kubectl delete failed for %s: %v\nStderr: %s", manifestPath, err, stderr.String())
	}
}

func runKubectlOutput(t *testing.T, args ...string) (string, error) {
	cmd := exec.CommandContext(context.Background(), "kubectl", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("kubectl %v failed: %w\nStderr: %s", args, err, stderr.String())
	}
	if stderr.Len() > 0 {
		t.Logf("kubectl %v stderr: %s", args, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

func retry(attempts int, sleep time.Duration, f func() error) error {
	var lastErr error
	for i := 0; i < attempts; i++ {
		err := f()
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(sleep)
	}
	return fmt.Errorf("after %d attempts, last error: %w", attempts, lastErr)
}

// waitForGatewayProgrammed blocks until the Gateway status reflects the latest spec generation
// and the https-listener is programmed. TLS subtests must call this after patching Gateway TLS
// so Envoy receives the updated client-validation configuration before MCP initialization.
func waitForGatewayProgrammed(t *testing.T, namespace string) {
	t.Helper()
	err := retry(30, 2*time.Second, func() error {
		genOut, err := runKubectlOutput(t, "get", "gateway", "e2e-gateway", "-n", namespace, "-o", "jsonpath={.metadata.generation}")
		if err != nil {
			return err
		}
		generation := strings.TrimSpace(genOut)
		if generation == "" {
			return fmt.Errorf("gateway generation not found")
		}

		progOut, err := runKubectlOutput(t, "get", "gateway", "e2e-gateway", "-n", namespace,
			"-o", `jsonpath={.status.conditions[?(@.type=="Programmed")].status}{"\n"}{.status.conditions[?(@.type=="Programmed")].observedGeneration}`)
		if err != nil {
			return err
		}
		lines := strings.Split(strings.TrimSpace(progOut), "\n")
		if len(lines) < 2 || lines[0] != "True" {
			return fmt.Errorf("gateway Programmed status not True yet: %q", progOut)
		}
		if lines[1] != generation {
			return fmt.Errorf("gateway observedGeneration=%q, want %q", lines[1], generation)
		}

		listenerProgOut, err := runKubectlOutput(t, "get", "gateway", "e2e-gateway", "-n", namespace,
			"-o", `jsonpath={.status.listeners[?(@.name=="https-listener")].conditions[?(@.type=="Programmed")].status}`)
		if err != nil {
			return err
		}
		if strings.TrimSpace(listenerProgOut) != "True" {
			return fmt.Errorf("https-listener Programmed status not True yet: %q", listenerProgOut)
		}

		resolvedOut, err := runKubectlOutput(t, "get", "gateway", "e2e-gateway", "-n", namespace,
			"-o", `jsonpath={.status.listeners[?(@.name=="https-listener")].conditions[?(@.type=="ResolvedRefs")].status}`)
		if err != nil {
			return err
		}
		if strings.TrimSpace(resolvedOut) != "True" {
			return fmt.Errorf("https-listener ResolvedRefs status not True yet: %q", resolvedOut)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("Gateway did not become programmed in namespace %s: %v", namespace, err)
	}
}

// restartGatewayEnvoyProxy rolls the gateway's Envoy deployment so downstream TLS context
// changes (e.g. SPIFFE trust -> explicit CACertificateRefs) are picked up cleanly.
func restartGatewayEnvoyProxy(t *testing.T, namespace string) {
	t.Helper()
	label := fmt.Sprintf("%s=e2e-gateway", constants.GatewayNameLabel)
	runKubectl(t, "rollout", "restart", "deployment", "-n", namespace, "-l", label)
	runKubectl(t, "rollout", "status", "deployment", "-n", namespace, "-l", label, "--timeout=5m")
	err := retry(20, 5*time.Second, func() error {
		out, err := runKubectlOutput(t, "get", "pods", "-n", namespace, "-l", label,
			"-o", `jsonpath={.items[*].status.conditions[?(@.type=="Ready")].status}`)
		if err != nil {
			return err
		}
		for _, status := range strings.Fields(out) {
			if status != "True" {
				return fmt.Errorf("envoy proxy pod not ready: %q", out)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Envoy proxy did not become ready after restart in namespace %s: %v", namespace, err)
	}
}

type mcpTestSession struct {
	t         *testing.T
	gatewayIP string
	sessionID string
	mcpPath   string
	pod       types.NamespacedName
	certPath  string
	keyPath   string
	caPath    string
}

func mcpGatewayURL(gatewayIP, mcpPath string) string {
	if mcpPath == "" {
		mcpPath = defaultMCPPath
	}
	return fmt.Sprintf("https://%s:10001%s", gatewayIP, mcpPath)
}

func initializeMCP(t *testing.T, gatewayIP string, pod types.NamespacedName) *mcpTestSession {
	return initializeMCPWithCerts(t, gatewayIP, pod, defaultMCPPath, agentCertPath, agentKeyPath, agentCAPath)
}

func tryInitializeMCPWithCerts(t *testing.T, gatewayIP string, pod types.NamespacedName, mcpPath, certPath, keyPath, caPath string) (*mcpTestSession, error) {
	t.Helper()
	t.Logf("Initialize MCP session for pod %s at %s", pod, mcpPath)

	mcpSessionID := ""
	err := retry(10, 10*time.Second, func() error {
		out, err := execMCPCurl(t, gatewayIP, pod, mcpPath, certPath, keyPath, caPath)
		if err != nil {
			return err
		}

		lines := strings.Split(out, "\r\n")
		for _, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "mcp-session-id:") {
				mcpSessionID = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
				return nil
			}
		}

		return fmt.Errorf("failed to get mcp-session-id from headers")
	})
	if err != nil {
		return nil, err
	}
	t.Logf("Obtained MCP Session ID for %s: %s", pod, mcpSessionID)
	return newMCPTestSession(t, gatewayIP, mcpSessionID, mcpPath, pod, certPath, keyPath, caPath), nil
}

func initializeMCPWithCerts(t *testing.T, gatewayIP string, pod types.NamespacedName, mcpPath, certPath, keyPath, caPath string) *mcpTestSession {
	mcp, err := tryInitializeMCPWithCerts(t, gatewayIP, pod, mcpPath, certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("MCP Initialization failed for pod %s: %v", pod, err)
	}
	return mcp
}

// initializeMCPWithCertsOptional is like initializeMCPWithCerts but returns false instead of
// failing the test when initialization does not succeed (e.g. remote MCP unreachable in CI).
func initializeMCPWithCertsOptional(t *testing.T, gatewayIP string, pod types.NamespacedName, mcpPath, certPath, keyPath, caPath string) (*mcpTestSession, bool) {
	t.Helper()
	mcp, err := tryInitializeMCPWithCerts(t, gatewayIP, pod, mcpPath, certPath, keyPath, caPath)
	if err != nil {
		t.Logf("MCP initialization unavailable for pod %s at %s: %v", pod, mcpPath, err)
		return nil, false
	}
	return mcp, true
}

func newMCPTestSession(t *testing.T, gatewayIP, sessionID, mcpPath string, pod types.NamespacedName, certPath, keyPath, caPath string) *mcpTestSession {
	t.Helper()
	return &mcpTestSession{
		t:         t,
		gatewayIP: gatewayIP,
		sessionID: sessionID,
		mcpPath:   mcpPath,
		pod:       pod,
		certPath:  certPath,
		keyPath:   keyPath,
		caPath:    caPath,
	}
}

func execMCPCurl(t *testing.T, gatewayIP string, pod types.NamespacedName, mcpPath, certPath, keyPath, caPath string) (string, error) {
	return runKubectlOutput(t, "exec", pod.Name, "-n", pod.Namespace, "--",
		"curl", "-ks", "-i",
		"--cert", certPath,
		"--key", keyPath,
		"--cacert", caPath,
		"-H", "Content-Type: application/json",
		"-H", "Accept: application/json, text/event-stream",
		"-H", "mcp-protocol-version: 2025-11-25",
		"--data-raw", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl-client","version":"1.0.0"}}}`,
		mcpGatewayURL(gatewayIP, mcpPath))
}

type mcpResponse struct {
	StatusCode int      `json:"status"`
	Body       respBody `json:"body"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type respBody struct {
	JSONRPC string     `json:"jsonrpc"`
	ID      int        `json:"id"`
	Result  *mcpResult `json:"result,omitempty"`
	Error   *mcpError  `json:"error,omitempty"`
}

type mcpResult struct {
	IsError bool         `json:"isError"`
	Content []mcpContent `json:"content"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func (m *mcpTestSession) doMCPRequest(t *testing.T, method, paramsJSON string) (requestID int, httpCode int, resp respBody, rawBody string, err error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return 0, 0, respBody{}, "", fmt.Errorf("failed to generate random request ID: %w", err)
	}
	requestID = int(nBig.Int64())

	data := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"%s","params":%s}`, requestID, method, paramsJSON)

	if m.pod.Name == "" || m.pod.Namespace == "" {
		return 0, 0, respBody{}, "", fmt.Errorf("invalid pod reference in MCP session: %v", m.pod)
	}

	out, err := runKubectlOutput(t, "exec", m.pod.Name, "-n", m.pod.Namespace, "--",
		"curl", "-ks", "-w", "\n%{http_code}",
		"--cert", m.certPath,
		"--key", m.keyPath,
		"--cacert", m.caPath,
		"-H", "Content-Type: application/json",
		"-H", "Accept: application/json, text/event-stream",
		"-H", "mcp-protocol-version: 2025-11-25",
		"-H", fmt.Sprintf("mcp-session-id: %s", m.sessionID),
		"--data-raw", data,
		mcpGatewayURL(m.gatewayIP, m.mcpPath))
	if err != nil {
		return 0, 0, respBody{}, "", fmt.Errorf("failed MCP request %q: %w", method, err)
	}

	out = strings.TrimSpace(out)
	lines := strings.Split(out, "\n")
	if len(lines) == 0 {
		return 0, 0, respBody{}, "", fmt.Errorf("empty response from gateway")
	}

	codeStr := strings.TrimSpace(lines[len(lines)-1])
	httpCode, err = strconv.Atoi(codeStr)
	if err != nil {
		return 0, 0, respBody{}, "", fmt.Errorf("failed to parse HTTP status code from response: %q", codeStr)
	}

	rawBody = strings.TrimSpace(strings.Join(lines[:len(lines)-1], "\n"))
	resp, err = parseMCPResponse(rawBody)
	if err != nil {
		return 0, 0, respBody{}, "", err
	}

	return requestID, httpCode, resp, rawBody, nil
}

func (m *mcpTestSession) checkMCPAllowed(t *testing.T, method, paramsJSON string) error {
	_, _, resp, rawBody, err := m.doMCPRequest(t, method, paramsJSON)
	if err != nil {
		return err
	}
	if resp.Error != nil && resp.Error.Code == 403 {
		return fmt.Errorf("MCP method %q forbidden: %s", method, resp.Error.Message)
	}
	if resp.Result == nil && resp.Error == nil {
		return fmt.Errorf("MCP method %q returned no result or error\nbody: %s", method, rawBody)
	}
	return nil
}

func (m *mcpTestSession) checkToolCall(t *testing.T, toolName, toolArgs string, expected mcpResponse) error {
	paramsJSON := fmt.Sprintf(`{"name":"%s","arguments":%s}`, toolName, toolArgs)
	requestID, httpCode, resp, rawBody, err := m.doMCPRequest(t, "tools/call", paramsJSON)
	if err != nil {
		return err
	}
	expected.Body.ID = requestID

	if expected.StatusCode != 0 && httpCode != expected.StatusCode {
		return fmt.Errorf("unexpected HTTP status code: got %d, want %d", httpCode, expected.StatusCode)
	}

	return assertMCPResponse(resp, expected, rawBody)
}

func parseMCPResponse(body string) (respBody, error) {
	var resp respBody
	idx := strings.Index(body, "{")
	if idx == -1 {
		return resp, fmt.Errorf("failed to find JSON payload in response\nbody: %s", body)
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(body[idx:])), &resp); err != nil {
		return resp, fmt.Errorf("failed to parse JSON response: %w\nbody: %s", err, body)
	}
	return resp, nil
}

func assertMCPResponse(resp respBody, expected mcpResponse, body string) error {
	if expected.Body.JSONRPC != "" && resp.JSONRPC != expected.Body.JSONRPC {
		return fmt.Errorf("jsonrpc mismatch: got %q, want %q\nJSON payload: %s", resp.JSONRPC, expected.Body.JSONRPC, body)
	}

	if resp.ID != expected.Body.ID {
		return fmt.Errorf("id mismatch: got %d, want %d\nbody: %s", resp.ID, expected.Body.ID, body)
	}

	if expected.Body.Error != nil {
		if resp.Error == nil {
			return fmt.Errorf("expected error but got nil\nbody: %s", body)
		}
		if resp.Error.Code != expected.Body.Error.Code {
			return fmt.Errorf("error code mismatch: got %d, want %d\nbody: %s", resp.Error.Code, expected.Body.Error.Code, body)
		}
		if expected.Body.Error.Message != "" && resp.Error.Message != expected.Body.Error.Message {
			return fmt.Errorf("error message mismatch: got %q, want %q\nbody: %s", resp.Error.Message, expected.Body.Error.Message, body)
		}
	} else {
		if resp.Result == nil || len(resp.Result.Content) == 0 {
			return fmt.Errorf("response contains no result\nbody: %s", body)
		}
		isError := resp.Result.IsError
		message := resp.Result.Content[0].Text
		tp := resp.Result.Content[0].Type
		expectedIsError := expected.Body.Result.IsError
		if expectedIsError != isError {
			return fmt.Errorf("isError mismatch: got %v, want %v\nbody: %s", isError, expectedIsError, body)
		}
		if expectedContent := expected.Body.Result.Content; len(expectedContent) > 0 {
			expectedMessage := expectedContent[0].Text
			expectedType := expectedContent[0].Type
			if expectedMessage != "" && message != expectedMessage {
				return fmt.Errorf("message mismatch: expected %q to be in %q\nbody: %s", expectedMessage, message, body)
			}
			if expectedType != "" && tp != expectedType {
				return fmt.Errorf("type mismatch: got %q, want %q\nbody: %s", tp, expectedType, body)
			}
		}
	}
	return nil
}

func (m *mcpTestSession) assertToolCall(t *testing.T, toolName, toolArgs string, expected mcpResponse) {
	// Retry 10 times with 2 second interval. This to allow xds update to propagate.
	err := retry(10, 2*time.Second, func() error {
		return m.checkToolCall(t, toolName, toolArgs, expected)
	})
	if err != nil {
		t.Fatalf("Tool call %q failed after retries: %v", toolName, err)
	}
	t.Logf("Tool call %q from pod %s: got expected response.", toolName, m.pod)
}

func (m *mcpTestSession) assertToolCallForbidden(t *testing.T, toolName, toolArgs string) {
	m.assertToolCall(t, toolName, toolArgs, mcpResponse{
		StatusCode: 200,
		Body: respBody{
			JSONRPC: "2.0",
			Error: &mcpError{
				Code:    403,
				Message: "Access to this tool is forbidden.",
			},
		},
	})
}

func (m *mcpTestSession) assertMCPRequestAllowed(t *testing.T, method, paramsJSON string) {
	t.Helper()
	err := retry(10, 2*time.Second, func() error {
		return m.checkMCPAllowed(t, method, paramsJSON)
	})
	if err != nil {
		t.Fatalf("MCP request %q expected to be allowed: %v", method, err)
	}
	t.Logf("MCP request %q from pod %s: allowed as expected.", method, m.pod)
}

func (m *mcpTestSession) assertToolCallAllowed(t *testing.T, toolName, toolArgs string) {
	t.Helper()
	paramsJSON := fmt.Sprintf(`{"name":"%s","arguments":%s}`, toolName, toolArgs)
	err := retry(10, 2*time.Second, func() error {
		return m.checkMCPAllowed(t, "tools/call", paramsJSON)
	})
	if err != nil {
		t.Fatalf("Tool call %q expected to be allowed: %v", toolName, err)
	}
	t.Logf("Tool call %q from pod %s: allowed as expected.", toolName, m.pod)
}

func TestGatewayTLS(t *testing.T) {
	t.Parallel()

	namespace, gatewayIP, cleanup := deployCommonTestResources(t)
	defer cleanup()

	kc := getClientset(t)
	podName := "e2e-tester-no-certs"

	var ca1, ca2 *localca.CA
	var clientCert1, clientKey1 []byte
	var clientCert2, clientKey2 []byte
	var clientCertDefault, clientKeyDefault []byte
	var serverCert, serverKey []byte
	var caCertPEM1 []byte

	t.Run("SetupCertificates", func(t *testing.T) {
		var err error
		ca1, err = generateCA("test-ca-1")
		if err != nil {
			t.Fatalf("failed to generate CA 1: %v", err)
		}

		ca2, err = generateCA("test-ca-2")
		if err != nil {
			t.Fatalf("failed to generate CA 2: %v", err)
		}

		serverCert, serverKey, err = generateServerCert(ca1, []string{"agentic-net-gateway"})
		if err != nil {
			t.Fatalf("failed to generate server cert: %v", err)
		}

		clientCert1, clientKey1, err = generateClientCert(ca1, fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/e2e-tester-sa", namespace))
		if err != nil {
			t.Fatalf("failed to generate client cert 1: %v", err)
		}

		clientCert2, clientKey2, err = generateClientCert(ca2, fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/e2e-tester-sa", namespace))
		if err != nil {
			t.Fatalf("failed to generate client cert 2: %v", err)
		}

		// Read default CA from secret
		defaultCA, err := getAgenticIdentityDefaultCA(kc)
		if err != nil {
			t.Fatalf("failed to get default CA: %v", err)
		}

		clientCertDefault, clientKeyDefault, err = generateClientCert(defaultCA, fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/e2e-tester-sa", namespace))
		if err != nil {
			t.Fatalf("failed to generate client cert for default CA: %v", err)
		}

		// Create secrets for Gateway
		err = createTLSSecret(kc, namespace, "gateway-server-cert", serverCert, serverKey)
		if err != nil {
			t.Fatalf("failed to create server secret: %v", err)
		}

		caCertPEM1 = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca1.RootCertificate.Raw})
		err = createCACertConfigMap(kc, namespace, "gateway-client-ca", caCertPEM1)
		if err != nil {
			t.Fatalf("failed to create CA configmap: %v", err)
		}
	})

	t.Run("DeployTesterPod", func(t *testing.T) {
		applyToNamespace(t, "testdata/tester-pod-no-certs.yaml", namespace)
		runKubectl(t, "wait", "--for=condition=Ready", "pod/e2e-tester-no-certs", "-n", namespace, "--timeout=5m")

		// Prepare workspace in pod
		runKubectl(t, "exec", podName, "-n", namespace, "--", "mkdir", "-p", "/tmp/mtls-client")
	})

	t.Run("TrustedCA_NoGatewayCA", func(t *testing.T) {
		// Test case 1: client cert signed by trusted CA without gateway CA configuration (should succeed)
		applyToNamespace(t, "testdata/gateway-no-ca.yaml", namespace)
		applyToNamespace(t, "testdata/gateway-policy.yaml", namespace)
		waitForGatewayProgrammed(t, namespace)

		// Write files to pod
		writePodFile(t, namespace, podName, testClientCertPath, clientCertDefault)
		writePodFile(t, namespace, podName, testClientKeyPath, clientKeyDefault)
		writePodFile(t, namespace, podName, testClientCAPath, caCertPEM1)

		mcp := initializeMCPWithCerts(t, gatewayIP, types.NamespacedName{Namespace: namespace, Name: podName}, defaultMCPPath,
			testClientCertPath, testClientKeyPath, testClientCAPath)

		mcp.assertToolCall(t, "echo", `{"message":"hello"}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Result: &mcpResult{
						IsError: false,
						Content: []mcpContent{
							{
								Type: "text",
								Text: "Echo: hello",
							},
						},
					},
				},
			},
		)
		mcp.assertToolCall(t, "get-sum", `{"a":2,"b":3}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Error: &mcpError{
						Code:    403,
						Message: "Access to this tool is forbidden.",
					},
				},
			},
		)
	})

	t.Run("TrustedCA_WithGatewayCA", func(t *testing.T) {
		// Test case 2: Client cert signed by trusted CA with gateway CA configuration (should succeed)
		applyToNamespace(t, "testdata/gateway-tls.yaml", namespace)
		applyToNamespace(t, "testdata/gateway-policy.yaml", namespace)
		waitForGatewayProgrammed(t, namespace)
		restartGatewayEnvoyProxy(t, namespace)
		waitForGatewayProgrammed(t, namespace)

		caRefOut, err := runKubectlOutput(t, "get", "gateway", "e2e-gateway", "-n", namespace,
			"-o", "jsonpath={.spec.tls.frontend.default.validation.caCertificateRefs[0].name}")
		if err != nil {
			t.Fatalf("failed to read gateway CA reference: %v", err)
		}
		if strings.TrimSpace(caRefOut) != "gateway-client-ca" {
			t.Fatalf("gateway frontend CA reference not applied (got %q, want gateway-client-ca)", caRefOut)
		}

		// Override certs in the pod to match the gateway-configured client CA.
		writePodFile(t, namespace, podName, testClientCertPath, appendPEMs(clientCert1, caCertPEM1))
		writePodFile(t, namespace, podName, testClientKeyPath, clientKey1)
		writePodFile(t, namespace, podName, testClientCAPath, caCertPEM1)

		mcp := initializeMCPWithCerts(t, gatewayIP, types.NamespacedName{Namespace: namespace, Name: podName}, defaultMCPPath,
			testClientCertPath, testClientKeyPath, testClientCAPath)

		mcp.assertToolCall(t, "echo", `{"message":"hello"}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Result: &mcpResult{
						IsError: false,
						Content: []mcpContent{
							{
								Type: "text",
								Text: "Echo: hello",
							},
						},
					},
				},
			},
		)

		mcp.assertToolCall(t, "get-sum", `{"a":2,"b":3}`,
			mcpResponse{
				StatusCode: 200,
				Body: respBody{
					JSONRPC: "2.0",
					Error: &mcpError{
						Code:    403,
						Message: "Access to this tool is forbidden.",
					},
				},
			},
		)
	})

	t.Run("UntrustedCA_ShouldFail", func(t *testing.T) {
		// Test case 3: Client cert signed by different CA (should fail)
		t.Log("Testing with client cert signed by different CA (should fail)")

		// Override client certs with invalid ones
		writePodFile(t, namespace, podName, testClientCertPath, clientCert2)
		writePodFile(t, namespace, podName, testClientKeyPath, clientKey2)

		err := retry(5, 5*time.Second, func() error {
			stdout, e := execMCPCurl(t, gatewayIP, types.NamespacedName{Namespace: namespace, Name: podName}, defaultMCPPath,
				testClientCertPath, testClientKeyPath, testClientCAPath)
			if e == nil {
				return fmt.Errorf("expected curl to fail but it succeeded with output: %s", stdout)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("mTLS negative test failed: %v", err)
		}
	})
}

func getClientset(t *testing.T) kubernetes.Interface {
	kubeConfigDefault := ""
	if home := homedir.HomeDir(); home != "" {
		kubeConfigDefault = filepath.Join(home, ".kube", "config")
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = kubeConfigDefault
	}

	kconfig, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("while reading kubeconfig: %v", err)
	}

	kc, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		t.Fatalf("while creating Kubernetes client: %v", err)
	}
	return kc
}

func writePodFile(t *testing.T, namespace, podName, filePath string, content []byte) {
	// #nosec G204
	cmd := exec.CommandContext(context.Background(), "kubectl", "exec", "-i", podName, "-n", namespace, "--", "sh", "-c", "cat > "+filePath)
	cmd.Stdin = bytes.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to write file %s to pod %s: %v\nStderr: %s", filePath, podName, err, stderr.String())
	}
}

func appendPEMs(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}
