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

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
)

func serviceBackend(namespace, name, service string, port int32, path string) agenticv0alpha0.XBackend {
	return agenticv0alpha0.XBackend{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       agenticv0alpha0.BackendSpec{MCP: agenticv0alpha0.MCPBackend{ServiceName: &service, Port: port, Path: path}},
	}
}

// fakePodForwarder stands in for the SPDY port-forward. Every forward points
// at a server already listening on localPort, and the calls are recorded.
type fakePodForwarder struct {
	localPort uint16
	fail      func(pod string) error // optional: fails the forward for some pods
	block     bool                   // wait for ctx instead of forwarding

	calls []forwardCall
	stops int
}

type forwardCall struct {
	namespace, pod string
	podPort        int32
	hasDeadline    bool
}

func (f *fakePodForwarder) forward(ctx context.Context, namespace, pod string, podPort int32) (uint16, func(), error) {
	_, hasDeadline := ctx.Deadline()
	f.calls = append(f.calls, forwardCall{namespace, pod, podPort, hasDeadline})
	if f.block {
		<-ctx.Done()
		return 0, nil, ctx.Err()
	}
	if f.fail != nil {
		if err := f.fail(pod); err != nil {
			return 0, nil, err
		}
	}
	return f.localPort, func() { f.stops++ }, nil
}

func (f *fakePodForwarder) prober(kube kubernetes.Interface, timeout time.Duration) *backendProber {
	return &backendProber{kube: kube, forwardPod: f.forward, timeout: timeout}
}

// listenPort returns the port of a test server's URL.
func listenPort(t *testing.T, serverURL string) uint16 {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return uint16(port)
}

func TestProbeBackend_MissingAddressing(t *testing.T) {
	backend := agenticv0alpha0.XBackend{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "broken"},
		Spec:       agenticv0alpha0.BackendSpec{MCP: agenticv0alpha0.MCPBackend{Port: 8080}},
	}

	result := (&backendProber{timeout: time.Second}).probeBackend(context.Background(), backend)
	if result.err == nil {
		t.Fatal("expected an error for a backend with neither serviceName nor hostname set")
	}
}

func TestProbeBackend_HostnameIsReachedDirectlyOverHTTPS(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.NotFoundHandler())
	ts.Config.ErrorLog = log.New(io.Discard, "", 0) // the probe rejects the certificate; skip the server's log line
	ts.StartTLS()
	t.Cleanup(ts.Close)
	host, port, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	portNum, _ := strconv.ParseInt(port, 10, 32)

	backend := agenticv0alpha0.XBackend{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "remote"},
		Spec:       agenticv0alpha0.BackendSpec{MCP: agenticv0alpha0.MCPBackend{Hostname: &host, Port: int32(portNum)}},
	}
	forwarder := &fakePodForwarder{}

	result := forwarder.prober(fake.NewClientset(), 5*time.Second).probeBackend(context.Background(), backend)

	if len(forwarder.calls) != 0 {
		t.Errorf("a hostname backend started a port-forward: %v", forwarder.calls)
	}
	// The test server's certificate isn't trusted, so the probe fails, but
	// only after attempting TLS against the backend's own address and default path.
	want := fmt.Sprintf("https://%s:%s/mcp", host, port)
	if result.err == nil || !strings.Contains(result.err.Error(), want) {
		t.Fatalf("probe error = %v, want it to mention %s", result.err, want)
	}
	if !strings.Contains(result.err.Error(), "certificate") {
		t.Errorf("probe error = %v, want a TLS certificate error proving HTTPS was used", result.err)
	}
}

func TestProbeBackend_ServiceNameIsProbedThroughForward(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantPath string
	}{
		{name: "explicit path is preserved", path: "/custom/mcp", wantPath: "/custom/mcp"},
		{name: "empty path gets the default", path: "", wantPath: "/mcp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "v0.0.0"}, nil)
			addNoopTool(t, srv, "add", "adds two numbers")
			handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)

			var mu sync.Mutex
			var requests []string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				requests = append(requests, r.Host+r.URL.Path)
				mu.Unlock()
				handler.ServeHTTP(w, r)
			}))
			t.Cleanup(ts.Close)

			kube := fake.NewClientset(
				testService("team-a", "mcp-svc", corev1.ServicePort{Port: 3001, TargetPort: intstr.FromInt32(8080)}),
				testPod("team-a", "mcp-pod", "mcp-svc", true),
			)
			forwarder := &fakePodForwarder{localPort: listenPort(t, ts.URL)}

			result := forwarder.prober(kube, 5*time.Second).probeBackend(context.Background(),
				serviceBackend("team-a", "local", "mcp-svc", 3001, tt.path))
			if result.err != nil {
				t.Fatalf("unexpected error: %v", result.err)
			}
			if len(result.tools) != 1 || result.tools[0].Name != "add" {
				t.Fatalf("got tools %v, want [add]", result.tools)
			}

			// The forward targets the pod and its resolved target port, not the Service port.
			wantCall := forwardCall{namespace: "team-a", pod: "mcp-pod", podPort: 8080, hasDeadline: true}
			if len(forwarder.calls) != 1 || forwarder.calls[0] != wantCall {
				t.Errorf("forward calls = %+v, want [%+v]", forwarder.calls, wantCall)
			}
			if forwarder.stops != 1 {
				t.Errorf("forward stopped %d times, want 1", forwarder.stops)
			}

			// The probe goes to the local end of the forward, on the original path.
			wantRequest := fmt.Sprintf("127.0.0.1:%d%s", forwarder.localPort, tt.wantPath)
			mu.Lock()
			defer mu.Unlock()
			if len(requests) == 0 {
				t.Fatal("the forwarded server received no requests")
			}
			for _, got := range requests {
				if got != wantRequest {
					t.Errorf("request to %q, want %q", got, wantRequest)
				}
			}
		})
	}
}

func TestProbeBackend_ForwardIsStoppedWhenProbeFails(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close() // nothing listens here anymore, so the probe is refused

	kube := fake.NewClientset(
		testService("default", "mcp-svc", corev1.ServicePort{Port: 80}),
		testPod("default", "mcp-pod", "mcp-svc", true),
	)
	forwarder := &fakePodForwarder{localPort: listenPort(t, closedURL)}

	result := forwarder.prober(kube, 2*time.Second).probeBackend(context.Background(),
		serviceBackend("default", "local", "mcp-svc", 80, ""))
	if result.err == nil {
		t.Fatal("expected the probe to fail")
	}
	if forwarder.stops != 1 {
		t.Errorf("forward stopped %d times after a failed probe, want 1", forwarder.stops)
	}
}

func TestProbeBackend_ServiceFailuresAreAdvisory(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "v0.0.0"}, nil)
	addNoopTool(t, srv, "add", "adds two numbers")

	kube := fake.NewClientset(
		testService("default", "unready-svc", corev1.ServicePort{Port: 80}),
		testPod("default", "unready-pod", "unready-svc", false),
		testService("default", "broken-svc", corev1.ServicePort{Port: 80}),
		testPod("default", "broken-pod", "broken-svc", true),
		testService("default", "good-svc", corev1.ServicePort{Port: 80}),
		testPod("default", "good-pod", "good-svc", true),
	)
	forwarder := &fakePodForwarder{
		localPort: listenPort(t, newMCPTestServer(t, srv)),
		fail: func(pod string) error {
			if pod == "broken-pod" {
				return errors.New("port-forward refused")
			}
			return nil
		},
	}
	prober := forwarder.prober(kube, 5*time.Second)

	tests := []struct {
		service string
		wantErr string
	}{
		{service: "missing-svc", wantErr: "getting service default/missing-svc"},
		{service: "unready-svc", wantErr: "no Ready pod found"},
		{service: "broken-svc", wantErr: "port-forward refused"},
		{service: "good-svc"}, // still works after the failures above
	}
	for _, tt := range tests {
		result := prober.probeBackend(context.Background(), serviceBackend("default", tt.service, tt.service, 80, ""))
		if tt.wantErr == "" {
			if result.err != nil || len(result.tools) != 1 {
				t.Errorf("%s: got (%v, %v), want the tools to be listed", tt.service, result.tools, result.err)
			}
			continue
		}
		if result.err == nil || !strings.Contains(result.err.Error(), tt.wantErr) {
			t.Errorf("%s: error = %v, want it to contain %q", tt.service, result.err, tt.wantErr)
		}
	}

	// Only the two pods that got as far as a forward attempt were forwarded to,
	// and only the one that succeeded has anything to stop.
	if len(forwarder.calls) != 2 || forwarder.stops != 1 {
		t.Errorf("forward calls = %+v, stops = %d, want 2 calls and 1 stop", forwarder.calls, forwarder.stops)
	}
}

func TestProbeBackend_TimeoutAndCancellationCoverTheForward(t *testing.T) {
	kube := fake.NewClientset(
		testService("default", "mcp-svc", corev1.ServicePort{Port: 80}),
		testPod("default", "mcp-pod", "mcp-svc", true),
	)
	backend := serviceBackend("default", "local", "mcp-svc", 80, "")

	t.Run("timeout", func(t *testing.T) {
		forwarder := &fakePodForwarder{block: true}
		result := forwarder.prober(kube, 50*time.Millisecond).probeBackend(context.Background(), backend)
		if !errors.Is(result.err, context.DeadlineExceeded) {
			t.Fatalf("probe error = %v, want %v", result.err, context.DeadlineExceeded)
		}
	})

	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		forwarder := &fakePodForwarder{block: true}
		result := forwarder.prober(kube, time.Minute).probeBackend(ctx, backend)
		if !errors.Is(result.err, context.Canceled) {
			t.Fatalf("probe error = %v, want %v", result.err, context.Canceled)
		}
	})
}

// A whole probe of a serviceName backend, with only the API server faked: the
// Service and pod lookups, the SPDY upgrade and the bytes on the forwarded
// stream are all the real code.
func TestProbeBackend_ServiceNameThroughSPDYPortForward(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "v0.0.0"}, nil)
	addNoopTool(t, srv, "add", "adds two numbers")
	mcpURL := newMCPTestServer(t, srv)
	api, _ := newFakeAPIServer(t, strings.TrimPrefix(mcpURL, "http://"))

	config := &rest.Config{Host: api.URL}
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	prober := &backendProber{
		kube: fake.NewClientset(
			testService("team-a", "mcp-svc", corev1.ServicePort{Port: 3001, TargetPort: intstr.FromString("http")}),
			testPod("team-a", "mcp-pod", "mcp-svc", true, corev1.ContainerPort{Name: "http", ContainerPort: 8080}),
		),
		forwardPod: newPodForwarder(config, kube.CoreV1().RESTClient()),
		timeout:    20 * time.Second,
	}

	result := prober.probeBackend(context.Background(), serviceBackend("team-a", "local", "mcp-svc", 3001, "/"))
	if result.err != nil {
		t.Fatalf("unexpected error: %v", result.err)
	}
	if len(result.tools) != 1 || result.tools[0].Name != "add" {
		t.Fatalf("got tools %v, want [add]", result.tools)
	}
}

// newMCPTestServer starts an in-process MCP server over the real streamable
// HTTP handler and returns its endpoint URL.
func newMCPTestServer(t *testing.T, srv *mcp.Server) string {
	t.Helper()
	ts := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil))
	t.Cleanup(ts.Close)
	return ts.URL
}

func addNoopTool(t *testing.T, srv *mcp.Server, name, description string) {
	t.Helper()
	srv.AddTool(&mcp.Tool{
		Name:        name,
		Description: description,
		InputSchema: map[string]any{"type": "object"},
	}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{}, nil
	})
}

func TestProbeEndpoint_ToolsCapabilityNotAdvertised(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "v0.0.0"}, nil)
	endpoint := newMCPTestServer(t, srv)

	result := probeEndpoint(context.Background(), endpoint, 5*time.Second)
	if result.err != nil {
		t.Fatalf("unexpected error: %v", result.err)
	}
	if result.toolsAdvertised {
		t.Fatal("expected tools capability to not be advertised")
	}
	if len(result.tools) != 0 {
		t.Fatalf("got %d tools, want 0", len(result.tools))
	}
}

func TestProbeEndpoint_ToolsCapabilityAdvertisedEmpty(t *testing.T) {
	// Force the tools capability on with no tools registered, rather than
	// registering and removing a tool, per the SDK's explicit capability
	// override mechanism.
	srv := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "v0.0.0"}, &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}},
	})
	endpoint := newMCPTestServer(t, srv)

	result := probeEndpoint(context.Background(), endpoint, 5*time.Second)
	if result.err != nil {
		t.Fatalf("unexpected error: %v", result.err)
	}
	if !result.toolsAdvertised {
		t.Fatal("expected tools capability to be advertised")
	}
	if len(result.tools) != 0 {
		t.Fatalf("got %d tools, want 0 (advertised but empty)", len(result.tools))
	}
}

func TestProbeEndpoint_Pagination(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "v0.0.0"}, &mcp.ServerOptions{PageSize: 1})
	// Registered out of alphabetical order to prove the result is sorted,
	// not just returned in registration/page order.
	addNoopTool(t, srv, "subtract", "subtracts two numbers")
	addNoopTool(t, srv, "multiply", "multiplies two numbers")
	addNoopTool(t, srv, "add", "adds two numbers")

	endpoint := newMCPTestServer(t, srv)

	result := probeEndpoint(context.Background(), endpoint, 5*time.Second)
	if result.err != nil {
		t.Fatalf("unexpected error: %v", result.err)
	}

	var got []string
	for _, tool := range result.tools {
		got = append(got, tool.Name)
	}
	want := []string{"add", "multiply", "subtract"}
	if !slices.Equal(got, want) {
		t.Fatalf("got tools %v, want %v (pagination should follow every page, sorted by name)", got, want)
	}
}

func TestProbeEndpoint_Timeout(t *testing.T) {
	// release, not r.Context(), gates the handler: the streamable client
	// doesn't reliably tear down its side of the connection when its own
	// context expires against a peer that never responds, so waiting on
	// r.Context().Done() here can leave the handler (and ts.Close) hanging
	// well past probeEndpoint's own return.
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	t.Cleanup(func() {
		close(release)
		ts.Close()
	})

	start := time.Now()
	result := probeEndpoint(context.Background(), ts.URL, 75*time.Millisecond)
	elapsed := time.Since(start)

	if result.err == nil {
		t.Fatal("expected a timeout error")
	}
	// The SDK's best-effort cleanup after a canceled connect can itself take
	// a few seconds against a peer that never responds at all (observed up to
	// ~5s), so this bound is deliberately generous: it only needs to prove
	// probeEndpoint doesn't hang indefinitely, not that it returns near the
	// configured timeout.
	if elapsed > 10*time.Second {
		t.Fatalf("probeEndpoint took %s to return after a 75ms timeout, want it to return promptly", elapsed)
	}
}

func TestProbeEndpoint_FailureDoesNotAffectLaterProbe(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close() // nothing listens here anymore, so this endpoint now refuses connections

	srv := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "v0.0.0"}, nil)
	addNoopTool(t, srv, "add", "adds two numbers")
	liveURL := newMCPTestServer(t, srv)

	failed := probeEndpoint(context.Background(), closedURL, 2*time.Second)
	if failed.err == nil {
		t.Fatal("expected an error probing a closed endpoint")
	}

	ok := probeEndpoint(context.Background(), liveURL, 5*time.Second)
	if ok.err != nil {
		t.Fatalf("probing a healthy endpoint after a prior failure returned an error: %v", ok.err)
	}
	if len(ok.tools) != 1 || ok.tools[0].Name != "add" {
		t.Fatalf("got tools %v, want [add]", ok.tools)
	}
}

func TestPrintProbeResult(t *testing.T) {
	tests := []struct {
		name   string
		result probeResult
		want   string
	}{
		{
			name:   "capability not advertised",
			result: probeResult{toolsAdvertised: false},
			want:   "  tools capability not advertised\n",
		},
		{
			name:   "capability advertised but empty",
			result: probeResult{toolsAdvertised: true},
			want:   "  tools capability advertised, no tools\n",
		},
		{
			name: "tools listed",
			result: probeResult{
				toolsAdvertised: true,
				tools: []*mcp.Tool{
					{Name: "add", Description: "adds two numbers"},
					{Name: "subtract", Description: "subtracts two numbers"},
				},
			},
			want: "  add - adds two numbers\n  subtract - subtracts two numbers\n",
		},
		{
			name:   "probe error",
			result: probeResult{err: errors.New("connection refused")},
			want:   "  error: connection refused\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printProbeResult(&buf, tt.result)
			if got := buf.String(); got != tt.want {
				t.Errorf("printProbeResult() = %q, want %q", got, tt.want)
			}
		})
	}
}
