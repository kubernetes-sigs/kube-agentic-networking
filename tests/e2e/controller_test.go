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

func TestControllerE2E(t *testing.T) {
	// 1. Initial Setup
	t.Log("Setting up E2E test resources...")
	runKubectl(t, "apply", "-f", "testdata/e2e-resources.yaml")
	runKubectl(t, "apply", "-f", "testdata/tester-pod.yaml")
	runKubectl(t, "apply", "-f", "testdata/mcpserver.yaml")

	defer func() {
		if t.Failed() {
			t.Log("Skipping resource cleanup due to test failure. Inspect resources in 'e2e-test-ns' namespace.")
			return
		}
		t.Log("Cleaning up E2E test resources...")
		runKubectl(t, "delete", "-f", "testdata/e2e-resources.yaml", "--ignore-not-found")
		runKubectl(t, "delete", "-f", "testdata/tester-pod.yaml", "--ignore-not-found")
		runKubectl(t, "delete", "-f", "testdata/mcpserver.yaml", "--ignore-not-found")
	}()

	// 2. Wait for Readiness
	t.Log("Waiting for resources to be ready...")
	runKubectl(t, "wait", "--for=condition=Ready", "pod/e2e-tester", "-n", "e2e-test-ns", "--timeout=2m")
	runKubectl(t, "wait", "--for=condition=available", "deployment/mcp-everything", "-n", "e2e-test-ns", "--timeout=2m")
	// Wait for Gateway to be programmed and proxy to be up
	var proxyPodName string
	err := retry(20, 5*time.Second, func() error {
		// Find the pod using the standard gateway-name label
		out := runKubectlOutput(t, "get", "pods", "-n", "e2e-test-ns", "-l", fmt.Sprintf("%s=e2e-gateway", constants.GatewayNameLabel), "-o", "jsonpath={.items[0].metadata.name}")
		if out == "" {
			return fmt.Errorf("envoy proxy pod not found")
		}
		proxyPodName = out
		return nil
	})

	if err != nil {
		t.Fatalf("Failed to find envoy proxy pod: %v", err)
	}
	runKubectl(t, "wait", "--for=condition=Ready", "pod/"+proxyPodName, "-n", "e2e-test-ns", "--timeout=2m")

	// 3. Obtain Gateway Address from status
	t.Log("Verifying Gateway status address and capturing IP...")
	var gatewayIP string
	err = retry(20, 2*time.Second, func() error {
		out := runKubectlOutput(t, "get", "gateway", "e2e-gateway", "-n", "e2e-test-ns", "-o", "jsonpath={.status.addresses[0].value}")
		if out == "" {
			return fmt.Errorf("gateway status address not found")
		}
		gatewayIP = out
		t.Logf("Found Gateway status address: %s", gatewayIP)
		return nil
	})
	if err != nil {
		t.Fatalf("Gateway status verification failed: %v", err)
	}

	// 4. Initialize MCP session
	t.Log("Initializing MCP session...")
	time.Sleep(10 * time.Second)

	mcpSessionID := ""
	err = retry(5, 10*time.Second, func() error {
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

	// 5. Test Phase 1: get-sum allowed, echo denied
	t.Log("Verifying initial policy (get-sum: OK, echo: DENY)...")

	// get-sum should be 200
	assertToolCall(t, mcpSessionID, gatewayIP, "get-sum", `{"a":2,"b":3}`, 200)
	// echo should be 403
	assertToolCall(t, mcpSessionID, gatewayIP, "echo", `{"message":"hello"}`, 403)

	// 6. Update Policy
	t.Log("Updating XAccessPolicy (swap permissions)...")
	runKubectl(t, "apply", "-f", "testdata/policy-update.yaml")

	// Give some time for xDS propagation
	t.Log("Waiting for xDS propagation...")
	time.Sleep(10 * time.Second)

	// 7. Test Phase 2: get-sum denied, echo allowed
	t.Log("Verifying updated policy (get-sum: DENY, echo: OK)...")

	// get-sum should now be 403
	assertToolCall(t, mcpSessionID, gatewayIP, "get-sum", `{"a":2,"b":3}`, 403)
	// echo should now be 200
	assertToolCall(t, mcpSessionID, gatewayIP, "echo", `{"message":"hello"}`, 200)

	t.Log("E2E Test Passed!")
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

func assertToolCall(t *testing.T, sessionID, gatewayAddr, toolName, toolArgs string, expectedStatus int) {
	data := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"%s","arguments":%s}}`, toolName, toolArgs)

	out := runKubectlOutput(t, "exec", "e2e-tester", "-n", "e2e-test-ns", "--",
		"curl", "-ks", "-o", "/dev/null", "-w", "%{http_code}",
		"--cert", agentCertPath,
		"--key", agentKeyPath,
		"--cacert", agentCAPath,
		"-H", "Content-Type: application/json",
		"-H", "Accept: application/json, text/event-stream",
		"-H", "mcp-protocol-version: 2025-11-25",
		"-H", fmt.Sprintf("mcp-session-id: %s", sessionID),
		"--data-raw", data,
		fmt.Sprintf("https://%s:10001/mcp", gatewayAddr))

	gotStatus, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("Failed to parse HTTP status code from curl output %q: %v", out, err)
	}

	if gotStatus != expectedStatus {
		t.Errorf("Tool call %s: expected status %d, got %d", toolName, expectedStatus, gotStatus)
	} else {
		t.Logf("Tool call %s: got expected status %d", toolName, gotStatus)
	}
}
