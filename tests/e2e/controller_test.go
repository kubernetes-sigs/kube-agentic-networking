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
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

const (
	agentCertPath = "/run/agent-identity-mtls/credential-bundle.pem"
	agentKeyPath  = "/run/agent-identity-mtls/credential-bundle.pem"
	agentCAPath   = "/run/agent-identity-mtls/cluster.local.trust-bundle.pem"
)

// TestControllerE2E verifies the core functionality of the agentic networking controller including:
// - Resource reconciliation on CRUD operations for Gateway, HTTPRoute, XBackend, and XAccessPolicy.
// - Dynamic xDS configuration updates to Envoy proxies.
// - mTLS authentication verification between the client and the proxy.
// - Multi-level authorization enforcement at both Gateway and Backend scopes.
// - Correctness of the generated Envoy configuration for policy enforcement.
func TestControllerE2E(t *testing.T) {
	// 1. Creating E2E test namespace
	t.Log("Creating E2E test namespace")
	runKubectl(t, "delete", "namespace", "e2e-test-ns", "--ignore-not-found")
	runKubectl(t, "create", "namespace", "e2e-test-ns")

	defer func() {
		if t.Failed() {
			t.Log("Skipping resource cleanup due to test failure. Inspect resources in 'e2e-test-ns' namespace.")
			return
		}
		t.Log("🎉🎉 E2E Test Passed!")
		t.Log("Cleaning up E2E test resources...")
		runKubectl(t, "delete", "namespace", "e2e-test-ns", "--ignore-not-found")
		runKubectl(t, "delete", "gatewayclass", "kube-agentic-networking", "--ignore-not-found")
	}()

	// 2. Setting up E2E test resources
	t.Log("Setting up E2E test resources...")
	// a. MCP server
	runKubectl(t, "apply", "-f", "testdata/mcpserver.yaml")
	runKubectl(t, "wait", "--for=condition=available", "deployment/mcp-everything", "-n", "e2e-test-ns", "--timeout=2m")

	// b. Gateway, HTTPRoute and XBackend resources
	runKubectl(t, "apply", "-f", "testdata/e2e-resources.yaml")

	var proxyPodName string
	err := retry(20, 5*time.Second, func() error {
		out := runKubectlOutput(t, "get", "pods", "-n", "e2e-test-ns", "-l", fmt.Sprintf("%s=e2e-gateway", constants.GatewayNameLabel), "-o", "jsonpath={.items[*].metadata.name}")
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
	runKubectl(t, "wait", "--for=condition=Ready", "pod/"+proxyPodName, "-n", "e2e-test-ns", "--timeout=5m")

	// c. Tester pod
	runKubectl(t, "apply", "-f", "testdata/tester-pod.yaml")
	runKubectl(t, "wait", "--for=condition=Ready", "pod/e2e-tester", "-n", "e2e-test-ns", "--timeout=5m")

	// 3. Obtain Gateway Address from status
	t.Log("Obtain Gateway Address from status")
	var gatewayIP string
	err = retry(20, 2*time.Second, func() error {
		out := runKubectlOutput(t, "get", "gateway", "e2e-gateway", "-n", "e2e-test-ns", "-o", "jsonpath={.status.addresses[*].value}")
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

	// 4. Initialize MCP session
	mcp := initializeMCP(t, gatewayIP)

	// 5. Case 1: No policy
	t.Log("--------------------------------------------------------------------------------")
	t.Log("Case 1: No policy applied (all allowed)")
	mcp.assertToolCall("get-sum", `{"a":2,"b":3}`, 200)
	mcp.assertToolCall("echo", `{"message":"hello"}`, 200)

	// 6. Case 2: Only backend policy
	t.Log("--------------------------------------------------------------------------------")
	t.Log("Case 2: Only backend policy (allows get-sum)")
	runKubectl(t, "apply", "-f", "testdata/backend-policy.yaml")
	// Wait for xDS propagation
	time.Sleep(5 * time.Second)
	mcp.assertToolCall("get-sum", `{"a":2,"b":3}`, 200)
	mcp.assertToolCall("echo", `{"message":"hello"}`, 403)

	// 7. Case 3: Only gateway policy
	t.Log("--------------------------------------------------------------------------------")
	t.Log("Case 3: Only gateway policy (allows echo)")
	runKubectl(t, "delete", "-f", "testdata/backend-policy.yaml", "--ignore-not-found")
	runKubectl(t, "apply", "-f", "testdata/gateway-policy.yaml")
	// Wait for xDS propagation
	time.Sleep(5 * time.Second)
	mcp.assertToolCall("get-sum", `{"a":2,"b":3}`, 403)
	mcp.assertToolCall("echo", `{"message":"hello"}`, 200)

	// 8. Case 4: Both policies applied
	t.Log("--------------------------------------------------------------------------------")
	t.Log("Case 4: Both policies (GW: echo, BE: get-sum)")
	runKubectl(t, "apply", "-f", "testdata/backend-policy.yaml")
	// Wait for xDS propagation
	time.Sleep(5 * time.Second)
	mcp.assertToolCall("get-sum", `{"a":2,"b":3}`, 403)
	mcp.assertToolCall("echo", `{"message":"hello"}`, 403)

	// 9. Case 5: Patch Gateway policy to allow get-sum
	t.Log("--------------------------------------------------------------------------------")
	t.Log("Case 5: Patch Gateway policy to allow get-sum")
	// Modifying Gateway Policy: Allowing 'get-sum' to align with Backend policy.
	patchGW := `[{"op": "replace", "path": "/spec/rules/0/authorization/tools", "value": ["get-sum"]}]`
	runKubectl(t, "patch", "xaccesspolicy", "e2e-gateway-level-policy", "-n", "e2e-test-ns", "--type=json", "-p", patchGW)

	// Wait for xDS propagation
	time.Sleep(5 * time.Second)
	mcp.assertToolCall("get-sum", `{"a":2,"b":3}`, 200)
	t.Log("--------------------------------------------------------------------------------")
}

func runKubectl(t *testing.T, args ...string) {
	cmd := exec.Command("kubectl", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("kubectl %v failed: %v\nStderr: %s", args, err, stderr.String())
	}
}

func runKubectlOutput(t *testing.T, args ...string) string {
	cmd := exec.Command("kubectl", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Logf("kubectl %v failed: %v\nStderr: %s", args, err, stderr.String())
		return ""
	}
	if stderr.Len() > 0 {
		t.Logf("kubectl %v stderr: %s", args, stderr.String())
	}
	return strings.TrimSpace(stdout.String())
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
}

func initializeMCP(t *testing.T, gatewayIP string) *mcpTestSession {
	t.Log("Initialize MCP session")
	time.Sleep(5 * time.Second)

	mcpSessionID := ""
	err := retry(5, 10*time.Second, func() error {
		out := runKubectlOutput(t, "exec", "e2e-tester", "-n", "e2e-test-ns", "--",
			"curl", "-ks", "-i",
			"--cert", agentCertPath,
			"--key", agentKeyPath,
			"--cacert", agentCAPath,
			"-H", "Content-Type: application/json",
			"-H", "Accept: application/json, text/event-stream",
			"-H", "mcp-protocol-version: 2025-11-25",
			"--data-raw", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl-client","version":"1.0.0"}}}`,
			fmt.Sprintf("https://%s:10001/mcp", gatewayIP))

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
		t.Fatalf("MCP Initialization failed: %v", err)
	}
	t.Logf("Obtained MCP Session ID: %s", mcpSessionID)

	return &mcpTestSession{t: t, gatewayIP: gatewayIP, sessionID: mcpSessionID}
}

func (m *mcpTestSession) assertToolCall(toolName, toolArgs string, expectedStatus int) {
	data := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"%s","arguments":%s}}`, toolName, toolArgs)

	out := runKubectlOutput(m.t, "exec", "e2e-tester", "-n", "e2e-test-ns", "--",
		"curl", "-ks", "-o", "/dev/null", "-w", "%{http_code}",
		"--cert", agentCertPath,
		"--key", agentKeyPath,
		"--cacert", agentCAPath,
		"-H", "Content-Type: application/json",
		"-H", "Accept: application/json, text/event-stream",
		"-H", "mcp-protocol-version: 2025-11-25",
		"-H", fmt.Sprintf("mcp-session-id: %s", m.sessionID),
		"--data-raw", data,
		fmt.Sprintf("https://%s:10001/mcp", m.gatewayIP))

	gotStatus, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		m.t.Fatalf("Failed to parse HTTP status code from curl output %q: %v", out, err)
	}

	if gotStatus != expectedStatus {
		m.t.Errorf("Tool call %s: expected status %d, got %d", toolName, expectedStatus, gotStatus)
	} else {
		m.t.Logf("Tool call %s: got expected status %d", toolName, gotStatus)
	}
}
