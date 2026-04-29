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

	xdsUpdateWaitTime = 5 * time.Second
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

	// Case 1: No policy
	t.Log("--------------------------------------------------------------------------------")
	t.Log("Case 1: No policy applied (all allowed)")
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

	// Case 2: Only backend policy
	t.Log("--------------------------------------------------------------------------------")
	t.Log("Case 2: Only backend policy (allows get-sum)")
	applyToNamespace(t, "testdata/backend-policy.yaml", namespace)
	// Wait for xDS propagation
	time.Sleep(xdsUpdateWaitTime)
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

	// Case 3: Only gateway policy
	t.Log("--------------------------------------------------------------------------------")
	t.Log("Case 3: Only gateway policy (allows echo)")
	deleteFromNamespace(t, "testdata/backend-policy.yaml", namespace)
	applyToNamespace(t, "testdata/gateway-policy.yaml", namespace)
	// Wait for xDS propagation
	time.Sleep(xdsUpdateWaitTime)
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

	// Case 4: Both policies applied
	t.Log("--------------------------------------------------------------------------------")
	t.Log("Case 4: Both policies (GW: echo, BE: get-sum)")
	applyToNamespace(t, "testdata/backend-policy.yaml", namespace)
	// Wait for xDS propagation
	time.Sleep(xdsUpdateWaitTime)
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

	// Case 5: Patch Gateway policy to allow get-sum
	t.Log("--------------------------------------------------------------------------------")
	t.Log("Case 5: Patch Gateway policy to allow get-sum")
	// Modifying Gateway Policy: Allowing 'get-sum' to align with Backend policy.
	patchGW := `[{"op": "replace", "path": "/spec/rules/0/authorization/tools", "value": ["get-sum"]}]`
	runKubectl(t, "patch", "xaccesspolicy", "e2e-gateway-level-policy", "-n", namespace, "--type=json", "-p", patchGW)

	// Wait for xDS propagation
	time.Sleep(xdsUpdateWaitTime)
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
	// Case 6: CEL policy (allows only get-sum)
	t.Log("--------------------------------------------------------------------------------")
	t.Log("Case 6: CEL policy (allows only get-sum)")
	// Clean up previous policies first to avoid interference
	runKubectl(t, "delete", "xaccesspolicy", "e2e-gateway-level-policy", "-n", namespace, "--ignore-not-found")
	deleteFromNamespace(t, "testdata/backend-policy.yaml", namespace)

	applyToNamespace(t, "testdata/cel-policy.yaml", namespace)
	// Wait for xDS propagation
	time.Sleep(xdsUpdateWaitTime)

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
	// Case 7: CEL policy - All failures (allows nothing)
	t.Log("--------------------------------------------------------------------------------")
	t.Log("Case 7: CEL policy - All failures (allows nothing)")
	deleteFromNamespace(t, "testdata/cel-policy.yaml", namespace)
	applyToNamespace(t, "testdata/cel-all-failures.yaml", namespace)
	// Wait for xDS propagation
	time.Sleep(xdsUpdateWaitTime)

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

	// Case 8: CEL policy - Mix of failure and success (allows get-sum)
	t.Log("--------------------------------------------------------------------------------")
	t.Log("Case 8: CEL policy - Mix of failure and success (allows get-sum)")
	deleteFromNamespace(t, "testdata/cel-all-failures.yaml", namespace)
	applyToNamespace(t, "testdata/cel-multi-rule.yaml", namespace)
	// Wait for xDS propagation
	time.Sleep(xdsUpdateWaitTime)

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
	t.Log("--------------------------------------------------------------------------------")
}

// TestExternalAuthE2E verifies the ExternalAuth authorization feature including:
// - External authorization service deployment and integration
// - Combined InlineTools and ExternalAuth policies at the backend level
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

	// Case 1: Combined backend policy (InlineTools for tester-1, ExternalAuth for tester-2)
	t.Log("--------------------------------------------------------------------------------")
	t.Log("Case 1: Combined backend policy - InlineTools (tester-1) + ExternalAuth (tester-2)")
	applyToNamespace(t, "testdata/backend-policy-extauth.yaml", namespace)
	time.Sleep(xdsUpdateWaitTime)

	// tester-1 with InlineTools: can call echo and get-sum
	t.Log("Testing tester-1 (InlineTools: echo, get-sum allowed)")
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

	// Case 2: Gateway-level ExternalAuth policy (applies to all requests)
	t.Log("--------------------------------------------------------------------------------")
	t.Log("Case 2: Gateway-level ExternalAuth policy (all requests go through external auth)")
	deleteFromNamespace(t, "testdata/backend-policy-extauth.yaml", namespace)
	applyToNamespace(t, "testdata/gateway-policy-extauth.yaml", namespace)
	time.Sleep(xdsUpdateWaitTime)

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

	t.Log("--------------------------------------------------------------------------------")
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
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read manifest %s: %v", manifestPath, err)
	}

	// Replace all occurrences of e2e-test-ns with the actual namespace
	modifiedContent := strings.ReplaceAll(string(content), "e2e-test-ns", namespace)

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
	for i := 0; i < attempts; i++ {
		if err := f(); err == nil {
			return nil
		}
		time.Sleep(sleep)
	}
	return fmt.Errorf("after %d attempts", attempts)
}

type mcpTestSession struct {
	t         *testing.T
	gatewayIP string
	sessionID string
	pod       types.NamespacedName
	certPath  string
	keyPath   string
	caPath    string
}

func initializeMCP(t *testing.T, gatewayIP string, pod types.NamespacedName) *mcpTestSession {
	return initializeMCPWithCerts(t, gatewayIP, pod, agentCertPath, agentKeyPath, agentCAPath)
}

func initializeMCPWithCerts(t *testing.T, gatewayIP string, pod types.NamespacedName, certPath, keyPath, caPath string) *mcpTestSession {
	t.Logf("Initialize MCP session for pod %s", pod)
	time.Sleep(xdsUpdateWaitTime)

	mcpSessionID := ""
	err := retry(5, 10*time.Second, func() error {
		out, err := execMCPCurl(t, gatewayIP, pod, certPath, keyPath, caPath)
		if err != nil {
			return err
		}

		// Extract mcp-session-id from headers
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
		t.Fatalf("MCP Initialization failed for pod %s: %v", pod, err)
	}
	t.Logf("Obtained MCP Session ID for %s: %s", pod, mcpSessionID)

	return &mcpTestSession{
		t:         t,
		gatewayIP: gatewayIP,
		sessionID: mcpSessionID,
		pod:       pod,
		certPath:  certPath,
		keyPath:   keyPath,
		caPath:    caPath,
	}
}

func execMCPCurl(t *testing.T, gatewayIP string, pod types.NamespacedName, certPath, keyPath, caPath string) (string, error) {
	return runKubectlOutput(t, "exec", pod.Name, "-n", pod.Namespace, "--",
		"curl", "-ks", "-i",
		"--cert", certPath,
		"--key", keyPath,
		"--cacert", caPath,
		"-H", "Content-Type: application/json",
		"-H", "Accept: application/json, text/event-stream",
		"-H", "mcp-protocol-version: 2025-11-25",
		"--data-raw", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl-client","version":"1.0.0"}}}`,
		fmt.Sprintf("https://%s:10001/mcp", gatewayIP))
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

func (m *mcpTestSession) assertToolCall(t *testing.T, toolName, toolArgs string, expected mcpResponse) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		t.Fatalf("failed to generate random request ID: %v", err)
	}
	requestID := int(nBig.Int64())
	expected.Body.ID = requestID

	data := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"%s","arguments":%s}}`, requestID, toolName, toolArgs)

	if m.pod.Name == "" || m.pod.Namespace == "" {
		t.Fatalf("invalid pod reference in MCP session: %v", m.pod)
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
		fmt.Sprintf("https://%s:10001/mcp", m.gatewayIP))
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}

	out = strings.TrimSpace(out)
	lines := strings.Split(out, "\n")
	if len(lines) == 0 {
		t.Fatalf("empty response from gateway")
	}

	// Check HTTP status code
	codeStr := strings.TrimSpace(lines[len(lines)-1])
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		t.Fatalf("failed to parse HTTP status code from response: %q", codeStr)
	}
	if expected.StatusCode != 0 && code != expected.StatusCode {
		t.Fatalf("unexpected HTTP status code: got %d, want %d\n", code, expected.StatusCode)
	}
	// An example mcp response body: {"id":1,"jsonrpc":"2.0","result":{"content":[{"text":"Access to this tool is forbidden (403).","type":"text"}],"isError":true}}
	// Check HTTP body
	body := strings.TrimSpace(strings.Join(lines[:len(lines)-1], "\n"))
	var resp respBody
	idx := strings.Index(body, "{")
	if idx == -1 {
		t.Fatalf("failed to find JSON payload in response\nbody: %s", body)
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(body[idx:])), &resp); err != nil {
		t.Fatalf("failed to parse JSON response: %v\nbody: %s", err, body)
	}

	if expected.Body.JSONRPC != "" && resp.JSONRPC != expected.Body.JSONRPC {
		t.Fatalf("jsonrpc mismatch: got %q, want %q\nJSON payload: %s", resp.JSONRPC, expected.Body.JSONRPC, body)
	}

	if resp.ID != expected.Body.ID {
		t.Fatalf("id mismatch: got %d, want %d\nbody: %s", resp.ID, expected.Body.ID, body)
	}

	if expected.Body.Error != nil {
		if resp.Error == nil {
			t.Fatalf("expected error but got nil\nbody: %s", body)
		}
		if resp.Error.Code != expected.Body.Error.Code {
			t.Fatalf("error code mismatch: got %d, want %d\nbody: %s", resp.Error.Code, expected.Body.Error.Code, body)
		}
		if expected.Body.Error.Message != "" && resp.Error.Message != expected.Body.Error.Message {
			t.Fatalf("error message mismatch: got %q, want %q\nbody: %s", resp.Error.Message, expected.Body.Error.Message, body)
		}
	} else {
		if resp.Result == nil || len(resp.Result.Content) == 0 {
			t.Fatalf("response contains no result\nbody: %s", body)
		}
		isError := resp.Result.IsError
		message := resp.Result.Content[0].Text
		tp := resp.Result.Content[0].Type
		expectedIsError := expected.Body.Result.IsError
		if expectedIsError != isError {
			t.Fatalf("isError mismatch: got %v, want %v\nbody: %s", isError, expectedIsError, body)
		}
		if expectedContent := expected.Body.Result.Content; len(expectedContent) > 0 {
			expectedMessage := expectedContent[0].Text
			expectedType := expectedContent[0].Type
			if expectedMessage != "" && message != expectedMessage {
				t.Fatalf("message mismatch: expected %q to be in %q\nbody: %s", expectedMessage, message, body)
			}
			if expectedType != "" && tp != expectedType {
				t.Fatalf("type mismatch: got %q, want %q\nbody: %s", tp, expectedType, body)
			}
		}
	}
	t.Logf("Tool call %q from pod %s: got expected response.", toolName, m.pod)
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

		// Wait for xDS propagation
		time.Sleep(xdsUpdateWaitTime)

		// Prepare workspace in pod
		runKubectl(t, "exec", podName, "-n", namespace, "--", "mkdir", "-p", "/tmp/mtls-client")
	})

	t.Run("TrustedCA_NoGatewayCA", func(t *testing.T) {
		// Test case 1: client cert signed by trusted CA without gateway CA configuration (should succeed)
		applyToNamespace(t, "testdata/gateway-no-ca.yaml", namespace)
		applyToNamespace(t, "testdata/gateway-policy.yaml", namespace)

		// Write files to pod
		writePodFile(t, namespace, podName, testClientCertPath, clientCertDefault)
		writePodFile(t, namespace, podName, testClientKeyPath, clientKeyDefault)
		writePodFile(t, namespace, podName, testClientCAPath, caCertPEM1)

		mcp := initializeMCPWithCerts(t, gatewayIP, types.NamespacedName{Namespace: namespace, Name: podName},
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

		// Override certs in the pod
		writePodFile(t, namespace, podName, testClientCertPath, clientCert1)
		writePodFile(t, namespace, podName, testClientKeyPath, clientKey1)

		mcp := initializeMCPWithCerts(t, gatewayIP, types.NamespacedName{Namespace: namespace, Name: podName},
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
			stdout, e := execMCPCurl(t, gatewayIP, types.NamespacedName{Namespace: namespace, Name: podName},
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
