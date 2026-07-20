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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	utilrand "k8s.io/apimachinery/pkg/util/rand"

	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

const (
	quickstartNSPlaceholder = "quickstart-ns"
	quickstartGatewayName   = "agentic-net-gateway"
	quickstartLocalMCPPath  = "/local/mcp"
	quickstartRemoteMCPPath = "/remote/mcp"
)

// TestQuickstartE2E validates the quickstart policy manifests end-to-end: Gateway,
// HTTPRoutes, XBackends, XAccessPolicies, MCP server, and tool authorization behavior
// matching site-src/guides/quickstart/policy/e2e.yaml.
func TestQuickstartE2E(t *testing.T) {
	t.Parallel()

	namespace, gatewayIP, cleanup := deployQuickstartTestResources(t)
	defer cleanup()

	runKubectl(t, "create", "sa", "adk-agent-sa", "-n", namespace)
	applyQuickstartTesterPod(t, namespace)
	runKubectl(t, "wait", "--for=condition=Ready", "pod/quickstart-tester", "-n", namespace, "--timeout=5m")

	pod := types.NamespacedName{Namespace: namespace, Name: "quickstart-tester"}

	t.Run("local MCP backend", func(t *testing.T) {
		mcp := initializeMCPWithCerts(t, gatewayIP, pod, quickstartLocalMCPPath, agentCertPath, agentKeyPath, agentCAPath)

		t.Run("initialize allowed", func(t *testing.T) {
			mcp.assertMCPRequestAllowed(t, "initialize",
				`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"e2e-client","version":"1.0.0"}}`)
		})

		t.Run("tools/list allowed", func(t *testing.T) {
			mcp.assertMCPRequestAllowed(t, "tools/list", `{}`)
		})

		t.Run("get-sum allowed", func(t *testing.T) {
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
				})
		})

		t.Run("get-tiny-image allowed", func(t *testing.T) {
			mcp.assertToolCallAllowed(t, "get-tiny-image", `{}`)
		})

		t.Run("echo denied", func(t *testing.T) {
			mcp.assertToolCallForbidden(t, "echo", `{"message":"hello"}`)
		})
	})

	t.Run("remote MCP backend", func(t *testing.T) {
		if os.Getenv("SKIP_REMOTE_MCP") == "true" {
			t.Skip("SKIP_REMOTE_MCP is set")
		}

		mcp, ok := initializeMCPWithCertsOptional(t, gatewayIP, pod, quickstartRemoteMCPPath, agentCertPath, agentKeyPath, agentCAPath)
		if !ok {
			t.Skip("remote MCP backend unavailable (mcp.deepwiki.com may be unreachable from this environment; set SKIP_REMOTE_MCP=true to skip explicitly)")
		}

		t.Run("read_wiki_structure allowed", func(t *testing.T) {
			mcp.assertToolCallAllowed(t, "read_wiki_structure",
				`{"repoName":"kubernetes-sigs/kube-agentic-networking"}`)
		})

		t.Run("read_wiki_content denied", func(t *testing.T) {
			mcp.assertToolCallForbidden(t, "read_wiki_content",
				`{"repoName":"kubernetes-sigs/kube-agentic-networking"}`)
		})
	})
}

func deployQuickstartTestResources(t *testing.T) (namespace, gatewayIP string, cleanup func()) {
	namespace = fmt.Sprintf("quickstart-e2e-ns-%s", utilrand.String(5))
	cleanup = createTestNamespace(t, namespace)

	t.Log("Setting up quickstart E2E resources from site-src/guides/quickstart manifests...")

	applyManifestReplacing(t, quickstartManifest(t, "mcpserver/deployment.yaml"), namespace, quickstartNSPlaceholder)
	runKubectl(t, "wait", "--for=condition=available", "deployment/mcp-everything", "-n", namespace, "--timeout=2m")

	applyManifestReplacing(t, quickstartManifest(t, "policy/e2e.yaml"), namespace, quickstartNSPlaceholder)

	var proxyPodName string
	err := retry(20, 5*time.Second, func() error {
		out, err := runKubectlOutput(t, "get", "pods", "-n", namespace,
			"-l", fmt.Sprintf("%s=%s", constants.GatewayNameLabel, quickstartGatewayName),
			"-o", "jsonpath={.items[*].metadata.name}")
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

	err = retry(50, 10*time.Second, func() error {
		out, e := runKubectlOutput(t, "get", "gateway", quickstartGatewayName, "-n", namespace,
			"-o", "jsonpath={.status.addresses[*].value}")
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

// applyQuickstartTesterPod deploys the standard e2e tester pod with adk-agent-sa, matching quickstart policy.
func applyQuickstartTesterPod(t *testing.T, namespace string) {
	t.Helper()
	content, err := os.ReadFile("testdata/tester-pod.yaml")
	if err != nil {
		t.Fatalf("failed to read tester pod manifest: %v", err)
	}
	modified := strings.ReplaceAll(string(content), "e2e-test-ns", namespace)
	modified = strings.ReplaceAll(modified, "e2e-tester-sa", "adk-agent-sa")
	modified = strings.ReplaceAll(modified, "e2e-tester", "quickstart-tester")

	cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(modified)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("kubectl apply failed for quickstart tester pod: %v\nStderr: %s", err, stderr.String())
	}
}

func quickstartManifest(t *testing.T, relPath string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to determine test file path")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	path := filepath.Join(root, "site-src", "guides", "quickstart", relPath)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("quickstart manifest not found at %s: %v", path, err)
	}
	return path
}
