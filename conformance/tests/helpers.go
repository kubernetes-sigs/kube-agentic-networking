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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	agentCertPath = "/run/agent-identity-mtls/credential-bundle.pem"
	agentKeyPath  = "/run/agent-identity-mtls/credential-bundle.pem"
	agentCAPath   = "/run/agent-identity-mtls/cluster.local.trust-bundle.pem"
)

type mcpTestSession struct {
	t         *testing.T
	gatewayIP string
	sessionID string
	podName   string
	namespace string
}

func initializeMCP(t *testing.T, gatewayIP, namespace, podName string) *mcpTestSession {
	t.Helper()
	t.Logf("Initialize MCP session for pod %s/%s", namespace, podName)

	host, _, err := net.SplitHostPort(gatewayIP)
	if err != nil {
		host = gatewayIP
	}

	mcpSessionID := ""
	err = retry(15, 5*time.Second, func() error {
		out, err := execMCPCurl(t, host, namespace, podName)
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
	require.NoError(t, err, "MCP Initialization failed")
	t.Logf("Obtained MCP Session ID: %s", mcpSessionID)

	return &mcpTestSession{
		t:         t,
		gatewayIP: host,
		sessionID: mcpSessionID,
		podName:   podName,
		namespace: namespace,
	}
}

func execMCPCurl(t *testing.T, gatewayIP, namespace, podName string) (string, error) {
	host, _, err := net.SplitHostPort(gatewayIP)
	if err != nil {
		host = gatewayIP
	}
	return runKubectlOutput(t, "exec", podName, "-n", namespace, "--",
		"curl", "-ks", "-i",
		"--cert", agentCertPath,
		"--key", agentKeyPath,
		"--cacert", agentCAPath,
		"-H", "Content-Type: application/json",
		"-H", "Accept: application/json, text/event-stream",
		"-H", "mcp-protocol-version: 2025-11-25",
		"--data-raw", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl-client","version":"1.0.0"}}}`,
		fmt.Sprintf("https://%s:443/mcp", host))
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

func (m *mcpTestSession) checkToolCall(t *testing.T, toolName, toolArgs string, expected mcpResponse) error {
	nBig, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return fmt.Errorf("failed to generate random request ID: %w", err)
	}
	requestID := int(nBig.Int64())
	expected.Body.ID = requestID

	data := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"%s","arguments":%s}}`, requestID, toolName, toolArgs)

	out, err := runKubectlOutput(t, "exec", m.podName, "-n", m.namespace, "--",
		"curl", "-ks", "-w", "\n%{http_code}",
		"--cert", agentCertPath,
		"--key", agentKeyPath,
		"--cacert", agentCAPath,
		"-H", "Content-Type: application/json",
		"-H", "Accept: application/json, text/event-stream",
		"-H", "mcp-protocol-version: 2025-11-25",
		"-H", fmt.Sprintf("mcp-session-id: %s", m.sessionID),
		"--data-raw", data,
		fmt.Sprintf("https://%s:443/mcp", m.gatewayIP))
	if err != nil {
		return fmt.Errorf("failed to call tool: %w", err)
	}

	out = strings.TrimSpace(out)
	lines := strings.Split(out, "\n")
	if len(lines) == 0 {
		return fmt.Errorf("empty response from gateway")
	}

	// Check HTTP status code
	codeStr := strings.TrimSpace(lines[len(lines)-1])
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		return fmt.Errorf("failed to parse HTTP status code from response: %q", codeStr)
	}
	if expected.StatusCode != 0 && code != expected.StatusCode {
		return fmt.Errorf("unexpected HTTP status code: got %d, want %d", code, expected.StatusCode)
	}

	body := strings.TrimSpace(strings.Join(lines[:len(lines)-1], "\n"))
	resp, err := parseMCPResponse(body)
	if err != nil {
		return err
	}

	return assertMCPResponse(resp, expected, body)
}

func (m *mcpTestSession) assertToolCall(t *testing.T, toolName, toolArgs string, expected mcpResponse) {
	// Retry to allow xds update to propagate.
	err := retry(15, 2*time.Second, func() error {
		return m.checkToolCall(t, toolName, toolArgs, expected)
	})
	require.NoError(t, err, "Tool call failed after retries")
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

func runKubectlOutput(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "kubectl", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("kubectl %v failed: %w\nStderr: %s", args, err, stderr.String())
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

// checkSessionClose sends a DELETE request to close the session and returns HTTP status code.
func (m *mcpTestSession) checkSessionClose(t *testing.T) (int, error) {
	out, err := runKubectlOutput(t, "exec", m.podName, "-n", m.namespace, "--",
		"curl", "-ks", "-o", "/dev/null", "-w", "%{http_code}",
		"--cert", agentCertPath,
		"--key", agentKeyPath,
		"--cacert", agentCAPath,
		"-X", "DELETE",
		"-H", fmt.Sprintf("mcp-session-id: %s", m.sessionID),
		fmt.Sprintf("https://%s:443/mcp", m.gatewayIP))
	if err != nil {
		return 0, fmt.Errorf("failed to close session: %w", err)
	}
	code, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, fmt.Errorf("failed to parse status code: %w", err)
	}
	return code, nil
}

// checkToolsList sends a tools/list request and returns HTTP status code.
func (m *mcpTestSession) checkToolsList(t *testing.T) (int, error) {
	out, err := runKubectlOutput(t, "exec", m.podName, "-n", m.namespace, "--",
		"curl", "-ks", "-o", "/dev/null", "-w", "%{http_code}",
		"--cert", agentCertPath,
		"--key", agentKeyPath,
		"--cacert", agentCAPath,
		"-H", "Content-Type: application/json",
		"-H", "Accept: application/json, text/event-stream",
		"-H", "mcp-protocol-version: 2025-11-25",
		"-H", fmt.Sprintf("mcp-session-id: %s", m.sessionID),
		"--data-raw", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		fmt.Sprintf("https://%s:443/mcp", m.gatewayIP))
	if err != nil {
		return 0, fmt.Errorf("failed to list tools: %w", err)
	}
	code, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, fmt.Errorf("failed to parse status code: %w", err)
	}
	return code, nil
}

type genericRespBody struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

// checkMCPMethod sends an MCP request and verifies the response.
func (m *mcpTestSession) checkMCPMethod(t *testing.T, method string, paramsJSON string, expectedError *mcpError) error {
	t.Helper()
	data := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"%s"}`, method)
	if paramsJSON != "" {
		data = fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"%s","params":%s}`, method, paramsJSON)
	}

	out, err := runKubectlOutput(t, "exec", m.podName, "-n", m.namespace, "--",
		"curl", "-ks", "-w", "\n%{http_code}",
		"--cert", agentCertPath,
		"--key", agentKeyPath,
		"--cacert", agentCAPath,
		"-H", "Content-Type: application/json",
		"-H", "Accept: application/json, text/event-stream",
		"-H", "mcp-protocol-version: 2025-11-25",
		"-H", fmt.Sprintf("mcp-session-id: %s", m.sessionID),
		"--data-raw", data,
		fmt.Sprintf("https://%s:443/mcp", m.gatewayIP))
	if err != nil {
		return fmt.Errorf("failed to call MCP method %s: %w", method, err)
	}

	out = strings.TrimSpace(out)
	lines := strings.Split(out, "\n")
	if len(lines) == 0 {
		return fmt.Errorf("empty response from gateway")
	}

	codeStr := strings.TrimSpace(lines[len(lines)-1])
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		return fmt.Errorf("failed to parse HTTP status code from response: %q", codeStr)
	}
	if code != 200 {
		return fmt.Errorf("unexpected HTTP status code: got %d, want 200", code)
	}

	body := strings.TrimSpace(strings.Join(lines[:len(lines)-1], "\n"))
	idx := strings.Index(body, "{")
	if idx == -1 {
		return fmt.Errorf("failed to find JSON payload in response\nbody: %s", body)
	}

	var resp genericRespBody
	if err := json.Unmarshal([]byte(strings.TrimSpace(body[idx:])), &resp); err != nil {
		return fmt.Errorf("failed to parse JSON response: %w\nbody: %s", err, body)
	}

	if expectedError != nil {
		if resp.Error == nil {
			return fmt.Errorf("expected error in response but got nil\nbody: %s", body)
		}
		if resp.Error.Code != expectedError.Code {
			return fmt.Errorf("error code mismatch: got %d, want %d\nbody: %s", resp.Error.Code, expectedError.Code, body)
		}
		if expectedError.Message != "" && resp.Error.Message != expectedError.Message {
			return fmt.Errorf("error message mismatch: got %q, want %q\nbody: %s", resp.Error.Message, expectedError.Message, body)
		}
	} else {
		if resp.Error != nil {
			// Check if it is Envoy RBAC error
			if resp.Error.Code == 403 && resp.Error.Message == "Access to this tool is forbidden." {
				return fmt.Errorf("expected allowed but was denied by Envoy\nbody: %s", body)
			}
			// Other errors are assumed to be backend errors, which means it was allowed by Envoy.
			t.Logf("Accepting backend error as proof of allowed: %v", resp.Error)
		}
	}

	return nil
}

func (m *mcpTestSession) assertMCPMethod(t *testing.T, method string, paramsJSON string, expectedError *mcpError) {
	t.Helper()
	err := retry(15, 2*time.Second, func() error {
		return m.checkMCPMethod(t, method, paramsJSON, expectedError)
	})
	require.NoError(t, err, "MCP method call failed after retries")
}

// getTesterPodName finds the pod name of the tester deployment.
func getTesterPodName(t *testing.T, namespace string) string {
	t.Helper()
	var podName string
	err := retry(30, 2*time.Second, func() error {
		out, err := runKubectlOutput(t, "get", "pods", "-n", namespace, "-l", "app=conformance-tester", "-o", "jsonpath={.items[0].metadata.name}")
		if err != nil {
			return err
		}
		name := strings.TrimSpace(out)
		if name == "" {
			return fmt.Errorf("conformance-tester pod not found")
		}
		podName = name
		return nil
	})
	require.NoError(t, err, "failed to find conformance-tester pod")
	return podName
}
