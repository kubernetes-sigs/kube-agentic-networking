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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apimachinery/pkg/util/httpstream/spdy"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
)

const testSelectorKey = "app"

// testService returns a Service in ns that selects pods labeled app=name.
func testService(ns, name string, ports ...corev1.ServicePort) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{testSelectorKey: name},
			Ports:    ports,
		},
	}
}

// testPod returns a pod that belongs to the Service named app.
func testPod(ns, name, app string, ready bool, ports ...corev1.ContainerPort) *corev1.Pod {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: map[string]string{testSelectorKey: app}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "mcp", Ports: ports}}},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: status}},
		},
	}
}

func TestResolveServiceTarget(t *testing.T) {
	const ns, svcName = "default", "mcp-svc"

	httpPort := corev1.ContainerPort{Name: "http", ContainerPort: 9000}

	terminating := testPod(ns, "terminating", svcName, true)
	terminating.DeletionTimestamp = &metav1.Time{Time: time.Now()}
	noConditions := testPod(ns, "no-conditions", svcName, true)
	noConditions.Status.Conditions = nil
	otherApp := testPod(ns, "other-app", "something-else", true)
	otherNamespace := testPod("elsewhere", "other-namespace", svcName, true)

	udpFirst := []corev1.ServicePort{
		{Port: 53, Protocol: corev1.ProtocolUDP, TargetPort: intstr.FromInt32(5300)},
		{Port: 53, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(5353)},
	}
	noSelector := testService(ns, svcName, corev1.ServicePort{Port: 80})
	noSelector.Spec.Selector = nil

	tests := []struct {
		name        string
		objects     []runtime.Object
		port        int32
		wantPod     string
		wantPodPort int32
		wantErr     string
	}{
		{
			name:        "numeric targetPort",
			objects:     []runtime.Object{testService(ns, svcName, corev1.ServicePort{Port: 80, TargetPort: intstr.FromInt32(8080)}), testPod(ns, "pod-a", svcName, true)},
			port:        80,
			wantPod:     "pod-a",
			wantPodPort: 8080,
		},
		{
			name:        "unset targetPort defaults to the service port",
			objects:     []runtime.Object{testService(ns, svcName, corev1.ServicePort{Port: 3001}), testPod(ns, "pod-a", svcName, true)},
			port:        3001,
			wantPod:     "pod-a",
			wantPodPort: 3001,
		},
		{
			name:        "named targetPort is looked up on the selected pod",
			objects:     []runtime.Object{testService(ns, svcName, corev1.ServicePort{Port: 80, TargetPort: intstr.FromString("http")}), testPod(ns, "pod-a", svcName, true, httpPort)},
			port:        80,
			wantPod:     "pod-a",
			wantPodPort: 9000,
		},
		{
			name:    "named targetPort missing from the pod is an error",
			objects: []runtime.Object{testService(ns, svcName, corev1.ServicePort{Port: 80, TargetPort: intstr.FromString("metrics")}), testPod(ns, "pod-a", svcName, true, httpPort)},
			port:    80,
			wantErr: `targetPort "metrics" is not a named TCP port`,
		},
		{
			name: "the ServicePort matching the backend port is used",
			objects: []runtime.Object{
				testService(ns, svcName,
					corev1.ServicePort{Name: "http", Port: 80, TargetPort: intstr.FromInt32(8080)},
					corev1.ServicePort{Name: "https", Port: 443, TargetPort: intstr.FromInt32(8443)}),
				testPod(ns, "pod-a", svcName, true),
			},
			port:        443,
			wantPod:     "pod-a",
			wantPodPort: 8443,
		},
		{
			name:    "backend port that is not on the Service is an error",
			objects: []runtime.Object{testService(ns, svcName, corev1.ServicePort{Port: 80}), testPod(ns, "pod-a", svcName, true)},
			port:    9999,
			wantErr: "has no TCP port 9999",
		},
		{
			name:        "a non-TCP port with the same number is skipped",
			objects:     []runtime.Object{testService(ns, svcName, udpFirst...), testPod(ns, "pod-a", svcName, true)},
			port:        53,
			wantPod:     "pod-a",
			wantPodPort: 5353,
		},
		{
			name: "only Ready pods of the Service are eligible",
			objects: []runtime.Object{
				testService(ns, svcName, corev1.ServicePort{Port: 80}),
				testPod(ns, "not-ready", svcName, false),
				noConditions, terminating, otherApp, otherNamespace,
				testPod(ns, "ready", svcName, true),
			},
			port:        80,
			wantPod:     "ready",
			wantPodPort: 80,
		},
		{
			name: "the lowest-named Ready pod is chosen",
			objects: []runtime.Object{
				testService(ns, svcName, corev1.ServicePort{Port: 80}),
				testPod(ns, "pod-b", svcName, true),
				testPod(ns, "pod-a", svcName, true),
			},
			port:        80,
			wantPod:     "pod-a",
			wantPodPort: 80,
		},
		{
			name: "no Ready pod is an error",
			objects: []runtime.Object{
				testService(ns, svcName, corev1.ServicePort{Port: 80}),
				testPod(ns, "not-ready", svcName, false), noConditions, terminating, otherApp, otherNamespace,
			},
			port:    80,
			wantErr: "no Ready pod found for service default/mcp-svc",
		},
		{
			name:    "Service without a selector is an error",
			objects: []runtime.Object{noSelector, testPod(ns, "pod-a", svcName, true)},
			port:    80,
			wantErr: "has no selector",
		},
		{
			name:    "missing Service is an error",
			port:    80,
			wantErr: "getting service default/mcp-svc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kube := fake.NewClientset(tt.objects...)

			pod, podPort, err := resolveServiceTarget(context.Background(), kube, ns, svcName, tt.port)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("resolveServiceTarget() error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveServiceTarget() unexpected error: %v", err)
			}
			if pod != tt.wantPod || podPort != tt.wantPodPort {
				t.Errorf("resolveServiceTarget() = (%q, %d), want (%q, %d)", pod, podPort, tt.wantPod, tt.wantPodPort)
			}
		})
	}
}

// fakeConn is the pod side of a forward that never carries any traffic.
type fakeConn struct {
	closeCh chan bool
	once    sync.Once
}

func newFakeConn() *fakeConn { return &fakeConn{closeCh: make(chan bool)} }

func (c *fakeConn) CreateStream(http.Header) (httpstream.Stream, error) {
	return nil, errors.New("unexpected stream")
}
func (c *fakeConn) Close() error                       { c.once.Do(func() { close(c.closeCh) }); return nil }
func (c *fakeConn) CloseChan() <-chan bool             { return c.closeCh }
func (c *fakeConn) SetIdleTimeout(time.Duration)       {}
func (c *fakeConn) RemoveStreams(...httpstream.Stream) {}

func (c *fakeConn) isClosed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

type dialerFunc func(protocols ...string) (httpstream.Connection, string, error)

func (f dialerFunc) Dial(protocols ...string) (httpstream.Connection, string, error) {
	return f(protocols...)
}

// portInUse reports whether something listens on the given local port.
func portInUse(t *testing.T, port uint16) bool {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return true
	}
	l.Close()
	return false
}

func TestStartForward_StopReleasesEverything(t *testing.T) {
	conn := newFakeConn()
	dialer := dialerFunc(func(...string) (httpstream.Connection, string, error) {
		return conn, portforward.PortForwardProtocolV1Name, nil
	})

	port, stop, err := startForward(context.Background(), dialer, 8080)
	if err != nil {
		t.Fatalf("startForward() unexpected error: %v", err)
	}
	if port == 0 {
		t.Fatal("startForward() returned port 0, want the ephemeral port it bound")
	}
	if !portInUse(t, port) {
		t.Fatalf("nothing is listening on 127.0.0.1:%d after startForward() returned", port)
	}

	stop()
	if !conn.isClosed() {
		t.Error("stop() returned without closing the connection to the pod")
	}
	if portInUse(t, port) {
		t.Errorf("127.0.0.1:%d is still in use after stop()", port)
	}

	stop() // must be safe to call again
}

func TestStartForward_DialFailure(t *testing.T) {
	dialErr := errors.New("boom")
	dialer := dialerFunc(func(...string) (httpstream.Connection, string, error) {
		return nil, "", dialErr
	})

	_, stop, err := startForward(context.Background(), dialer, 8080)
	if !strings.Contains(fmt.Sprint(err), dialErr.Error()) {
		t.Fatalf("startForward() error = %v, want it to contain %q", err, dialErr)
	}
	if stop != nil {
		t.Error("startForward() returned a stop function alongside an error")
	}
}

func TestStartForward_ContextEndsWhileDialing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	// Like spdyDialer, give up once ctx ends.
	dialer := dialerFunc(func(...string) (httpstream.Connection, string, error) {
		<-ctx.Done()
		return nil, "", ctx.Err()
	})

	_, _, err := startForward(ctx, dialer, 8080)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("startForward() error = %v, want %v", err, context.DeadlineExceeded)
	}
}

// pipeToTarget copies between a forwarded data stream and a TCP connection to target.
func pipeToTarget(ctx context.Context, stream httpstream.Stream, replySent <-chan struct{}, target string) {
	<-replySent
	backend, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
	if err != nil {
		stream.Reset()
		return
	}
	defer backend.Close()
	go func() {
		io.Copy(backend, stream)
		backend.Close()
	}()
	io.Copy(stream, backend)
	stream.Close()
}

// newFakeAPIServer stands in for the API server's pod portforward endpoint. It
// speaks SPDY and pipes every forwarded connection to target. The request line
// and the pod port of each data stream are reported on the returned channel.
func newFakeAPIServer(t *testing.T, target string) (*httptest.Server, <-chan string) {
	t.Helper()
	seen := make(chan string, 64)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Method + " " + r.URL.Path
		if _, err := httpstream.Handshake(r, w, []string{portforward.PortForwardProtocolV1Name}); err != nil {
			return
		}
		//nolint:contextcheck // UpgradeResponse doesn't take a context
		conn := spdy.NewResponseUpgrader().UpgradeResponse(w, r, func(stream httpstream.Stream, replySent <-chan struct{}) error {
			if stream.Headers().Get(corev1.StreamType) == corev1.StreamTypeError {
				// Nothing to report, but the reply has to go out first.
				go func() {
					<-replySent
					stream.Close()
				}()
				return nil
			}
			seen <- "port " + stream.Headers().Get(corev1.PortHeader)

			go pipeToTarget(r.Context(), stream, replySent, target)
			return nil
		})
		if conn == nil {
			return
		}
		defer conn.Close()
		<-conn.CloseChan()
	}))
	t.Cleanup(ts.Close)
	return ts, seen
}

func TestNewPodForwarder_SPDY(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "v0.0.0"}, nil)
	addNoopTool(t, srv, "add", "adds two numbers")
	mcpURL := newMCPTestServer(t, srv)
	api, seen := newFakeAPIServer(t, strings.TrimPrefix(mcpURL, "http://"))

	config := &rest.Config{Host: api.URL}
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	forward := newPodForwarder(config, kube.CoreV1().RESTClient())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	port, stop, err := forward(ctx, "team-a", "mcp-pod", 8080)
	if err != nil {
		t.Fatalf("forward() unexpected error: %v", err)
	}
	defer stop()

	result := probeEndpoint(ctx, fmt.Sprintf("http://127.0.0.1:%d/", port), 10*time.Second)
	if result.err != nil {
		t.Fatalf("probing through the forward: %v", result.err)
	}
	if len(result.tools) != 1 || result.tools[0].Name != "add" {
		t.Fatalf("got tools %v through the forward, want [add]", result.tools)
	}

	stop()
	if portInUse(t, port) {
		t.Errorf("127.0.0.1:%d is still in use after stop()", port)
	}

	var got []string
	for len(seen) > 0 {
		got = append(got, <-seen)
	}
	if len(got) == 0 || got[0] != "POST /api/v1/namespaces/team-a/pods/mcp-pod/portforward" {
		t.Errorf("first API request = %v, want POST to the pod's portforward subresource", got)
	}
	for _, s := range got[1:] {
		if s != "port 8080" {
			t.Errorf("data stream request %q, want the pod port 8080", s)
		}
	}
}

func TestNewPodForwarder_StalledAPIServer(t *testing.T) {
	// The server takes the upgrade request and never answers it, like an API
	// server waiting on an unreachable kubelet.
	received := make(chan struct{}, 1)
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		received <- struct{}{}
		<-release
	}))
	t.Cleanup(func() {
		close(release)
		ts.Close()
	})

	config := &rest.Config{Host: ts.URL}
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	forward := newPodForwarder(config, kube.CoreV1().RESTClient())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		_, _, err := forward(ctx, "team-a", "mcp-pod", 8080)
		errCh <- err
	}()

	select {
	case <-received:
	case <-time.After(10 * time.Second):
		t.Fatal("the API server never received the upgrade request")
	}
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("forward() error = %v, want %v", err, context.Canceled)
		}
		if !strings.Contains(err.Error(), "pod team-a/mcp-pod port 8080") {
			t.Errorf("forward() error = %q, want it to name the pod and port", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("forward() did not return after its context was canceled")
	}
}
