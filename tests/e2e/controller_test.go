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
	"encoding/json"
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

type mcpResponse struct {
	StatusCode int      `json:"status"`
	Body       respBody `json:"body"`
}

type respBody struct {
	JSONRPC string     `json:"jsonrpc"`
	ID      int        `json:"id"`
	Result  *mcpResult `json:"result,omitempty"`
}

type mcpResult struct {
	IsError bool         `json:"isError"`
	Content []mcpContent `json:"content"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

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
	runKubectl(t, "wait", "--for=condition=Ready", "pod/e2e-tester", "-n", "e2e-test-ns", "--timeout=5m")
	runKubectl(t, "wait", "--for=condition=available", "deployment/mcp-everything", "-n", "e2e-test-ns", "--timeout=2m")
	// Wait for Gateway to be programmed and proxy to be up.
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

	// 3. Obtain Gateway Address from status
	t.Log("Verifying Gateway status address and capturing IP...")
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

	// get-sum should be successful.
	assertToolCall(t, "1", mcpSessionID, gatewayIP, "get-sum", `{"a":2,"b":3}`,
		mcpResponse{
			StatusCode: 200,
			Body: respBody{
				JSONRPC: "2.0",
				ID:      1,
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

	// echo should be unsuccessful.
	assertToolCall(t, "2", mcpSessionID, gatewayIP, "echo", `{"message":"hello"}`,
		mcpResponse{
			StatusCode: 200,
			Body: respBody{
				JSONRPC: "2.0",
				ID:      2,
				Result: &mcpResult{
					IsError: true,
					Content: []mcpContent{
						{
							Type: "text",
							Text: "Access to this tool is forbidden (403).",
						},
					},
				},
			},
		},
	)

	// 6. Update Policy
	t.Log("Updating XAccessPolicy (swap permissions)...")
	runKubectl(t, "apply", "-f", "testdata/policy-update.yaml")

	// Give some time for xDS propagation
	t.Log("Waiting for xDS propagation...")
	time.Sleep(10 * time.Second)

	// 7. Test Phase 2: get-sum denied, echo allowed
	t.Log("Verifying updated policy (get-sum: DENY, echo: OK)...")

	// get-sum should now be unsuccessful.
	assertToolCall(t, "3", mcpSessionID, gatewayIP, "get-sum", `{"a":2,"b":3}`,
		mcpResponse{
			StatusCode: 200,
			Body: respBody{
				JSONRPC: "2.0",
				ID:      3,
				Result: &mcpResult{
					IsError: true,
					Content: []mcpContent{
						{
							Type: "text",
							Text: "Access to this tool is forbidden (403).",
						},
					},
				},
			},
		},
	)

	// echo should now be successful.
	assertToolCall(t, "4", mcpSessionID, gatewayIP, "echo", `{"message":"hello"}`,
		mcpResponse{
			StatusCode: 200,
			Body: respBody{
				JSONRPC: "2.0",
				ID:      4,
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

	t.Log("E2E Test Passed!")
}

func runKubectl(t *testing.T, args ...string) {
	cmd := exec.CommandContext(context.Background(), "kubectl", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("kubectl %v failed: %v\nStderr: %s", args, err, stderr.String())
	}
}

func runKubectlOutput(t *testing.T, args ...string) string {
	cmd := exec.CommandContext(context.Background(), "kubectl", args...)
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

func assertToolCall(t *testing.T, requestID, sessionID, gatewayAddr, toolName, toolArgs string, expected mcpResponse) {
	data := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"%s","arguments":%s}}`, requestID, toolName, toolArgs)

	out := runKubectlOutput(t, "exec", "e2e-tester", "-n", "e2e-test-ns", "--",
		"curl", "-ks", "-w", "\n%{http_code}",
		"--cert", agentCertPath,
		"--key", agentKeyPath,
		"--cacert", agentCAPath,
		"-H", "Content-Type: application/json",
		"-H", "Accept: application/json, text/event-stream",
		"-H", "mcp-protocol-version: 2025-11-25",
		"-H", fmt.Sprintf("mcp-session-id: %s", sessionID),
		"--data-raw", data,
		fmt.Sprintf("https://%s:10001/mcp", gatewayAddr))

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

	if requestID != "" && strconv.Itoa(resp.ID) != requestID {
		t.Fatalf("id mismatch: got %q, want %q\nbody: %s", strconv.Itoa(resp.ID), requestID, body)
	}

	if resp.Result == nil || len(resp.Result.Content) == 0 {
		t.Fatalf("response contains no result\nbody: %s", body)
	}
	isError := resp.Result.IsError
	message := resp.Result.Content[0].Text
	tp := resp.Result.Content[0].Type
	expectedIsError := expected.Body.Result.IsError
	expectedMessage := expected.Body.Result.Content[0].Text
	expectedType := expected.Body.Result.Content[0].Type
	if expectedIsError != isError {
		t.Fatalf("isError mismatch: got %v, want %v\nbody: %s", isError, expectedIsError, body)
	}
	if expectedMessage != "" && message != expectedMessage {
		t.Fatalf("message mismatch: expected %q to be in %q\nbody: %s", expectedMessage, message, body)
	}
	if expectedType != "" && tp != expectedType {
		t.Fatalf("type mismatch: got %q, want %q\nbody: %s", tp, expectedType, body)
	}
}
