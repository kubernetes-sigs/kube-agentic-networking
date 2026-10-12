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
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/google/subcommands"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/klog/v2"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned"
	"sigs.k8s.io/kube-agentic-networking/version"
)

// defaultMCPPath matches MCPBackend's +kubebuilder:default. XBackend objects
// built without going through the API server (older resources, test fixtures)
// may still have an empty Path, so we apply the same default here.
const defaultMCPPath = "/mcp"

type ListToolsCommand struct {
	kubeConfig string
	namespace  string
	timeout    time.Duration
}

var _ subcommands.Command = (*ListToolsCommand)(nil)

func (*ListToolsCommand) Name() string { return "list-tools" }

func (*ListToolsCommand) Synopsis() string {
	return "List the tools exposed by each MCP backend (XBackend)"
}

func (*ListToolsCommand) Usage() string {
	return `list-tools:
	List XBackend resources and probe each one's MCP endpoint for the tools it exposes.
	A probe failure for one backend is reported and does not stop the others from
	being processed.

	serviceName backends are reached through a port-forward via the API server, which
	needs get on services, list on pods and create on pods/portforward. hostname
	backends are reached directly over HTTPS.
`
}

func (c *ListToolsCommand) SetFlags(f *flag.FlagSet) {
	kubeConfigDefault := ""
	if home := homedir.HomeDir(); home != "" {
		kubeConfigDefault = filepath.Join(home, ".kube", "config")
	}

	f.StringVar(&c.kubeConfig, "kubeconfig", kubeConfigDefault, "absolute path to the kubeconfig file")
	f.StringVar(&c.namespace, "namespace", "", "only list backends in this namespace (default: all namespaces)")
	f.DurationVar(&c.timeout, "timeout", 10*time.Second, "per-backend MCP probe timeout")
}

func (c *ListToolsCommand) Execute(ctx context.Context, _ *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := c.do(ctx); err != nil {
		klog.ErrorS(err, "Error while executing")
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *ListToolsCommand) do(ctx context.Context) error {
	kconfig, err := clientcmd.BuildConfigFromFlags("", c.kubeConfig)
	if err != nil {
		return fmt.Errorf("while reading kubeconfig: %w", err)
	}

	agenticClient, err := versioned.NewForConfig(kconfig)
	if err != nil {
		return fmt.Errorf("while creating Kubernetes client: %w", err)
	}

	kubeClient, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		return fmt.Errorf("while creating core Kubernetes client: %w", err)
	}

	backendList, err := agenticClient.AgenticV0alpha0().XBackends(c.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("while listing XBackends: %w", err)
	}

	backends := backendList.Items
	sort.Slice(backends, func(i, j int) bool {
		if backends[i].Namespace != backends[j].Namespace {
			return backends[i].Namespace < backends[j].Namespace
		}
		return backends[i].Name < backends[j].Name
	})

	prober := &backendProber{
		kube:       kubeClient,
		forwardPod: newPodForwarder(kconfig, kubeClient.CoreV1().RESTClient()),
		timeout:    c.timeout,
	}

	for i, backend := range backends {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("%s/%s\n", backend.Namespace, backend.Name)
		printProbeResult(os.Stdout, prober.probeBackend(ctx, backend))
	}

	return nil
}

// probeResult is the outcome of probing a single backend's MCP endpoint.
type probeResult struct {
	toolsAdvertised bool
	tools           []*mcp.Tool
	err             error
}

// backendProber probes XBackends. The tool normally runs outside the cluster,
// where cluster DNS doesn't resolve, so serviceName backends are reached
// through a port-forward to one of the Service's pods.
type backendProber struct {
	kube       kubernetes.Interface
	forwardPod podForwardFunc
	timeout    time.Duration
}

// probeBackend connects to a backend's MCP endpoint and lists its tools.
// Any failure is returned in probeResult.err rather than as a Go error: a
// failed probe is advisory and must never stop the caller from moving on to
// the next backend.
func (p *backendProber) probeBackend(ctx context.Context, backend agenticv0alpha0.XBackend) probeResult {
	mcpBackend := backend.Spec.MCP
	path := mcpBackend.Path
	if path == "" {
		path = defaultMCPPath
	}

	switch {
	case mcpBackend.ServiceName != nil:
		return p.probeService(ctx, backend.Namespace, *mcpBackend.ServiceName, mcpBackend.Port, path)
	case mcpBackend.Hostname != nil:
		return probeEndpoint(ctx, fmt.Sprintf("https://%s:%d%s", *mcpBackend.Hostname, mcpBackend.Port, path), p.timeout)
	default:
		return probeResult{err: fmt.Errorf("backend has neither serviceName nor hostname set")}
	}
}

// probeService probes a Service through a port-forward to one of its Ready
// pods. The backend's timeout covers the lookups, the forward and the probe
// together, and the forward is stopped however the probe ends.
func (p *backendProber) probeService(ctx context.Context, namespace, service string, port int32, path string) probeResult {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	pod, podPort, err := resolveServiceTarget(ctx, p.kube, namespace, service, port)
	if err != nil {
		return probeResult{err: err}
	}
	localPort, stop, err := p.forwardPod(ctx, namespace, pod, podPort)
	if err != nil {
		return probeResult{err: err}
	}
	defer stop()

	// probeEndpoint applies the timeout again, but ctx's deadline is the
	// earlier of the two, so the shared budget still holds.
	return probeEndpoint(ctx, fmt.Sprintf("http://127.0.0.1:%d%s", localPort, path), p.timeout)
}

// probeEndpoint connects to an MCP endpoint and lists its tools.
func probeEndpoint(ctx context.Context, endpoint string, timeout time.Duration) probeResult {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "agentic-net-tool", Version: version.BundleVersion}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint}, nil)
	if err != nil {
		return probeResult{err: fmt.Errorf("connecting to %s: %w", endpoint, err)}
	}
	defer cs.Close()

	initResult := cs.InitializeResult()
	if initResult == nil {
		return probeResult{err: fmt.Errorf("connecting to %s: no initialize result", endpoint)}
	}
	if initResult.Capabilities == nil || initResult.Capabilities.Tools == nil {
		return probeResult{toolsAdvertised: false}
	}

	var tools []*mcp.Tool
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			return probeResult{toolsAdvertised: true, err: fmt.Errorf("listing tools from %s: %w", endpoint, err)}
		}
		tools = append(tools, tool)
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })

	return probeResult{toolsAdvertised: true, tools: tools}
}

func printProbeResult(w io.Writer, result probeResult) {
	switch {
	case result.err != nil:
		fmt.Fprintf(w, "  error: %v\n", result.err)
	case !result.toolsAdvertised:
		fmt.Fprintln(w, "  tools capability not advertised")
	case len(result.tools) == 0:
		fmt.Fprintln(w, "  tools capability advertised, no tools")
	default:
		for _, tool := range result.tools {
			fmt.Fprintf(w, "  %s - %s\n", tool.Name, tool.Description)
		}
	}
}
