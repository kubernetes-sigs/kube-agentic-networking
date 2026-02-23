Date: 9th February 2026<br/>
Authors: gkhom<br/>
Status: draft<br/>

# TelemetryPolicy
A Kubernetes API for Gateway/Mesh Observability

## Summary
This proposal introduces the `TelemetryPolicy`, a direct policy attachment designed to configure observability signals (metrics, logs, traces) 
for Gateway API resources (via `Gateway` attachment) and Service Mesh resources (via `namespace` attachment).

This K8s API standardizes how users enable and configure telemetry across different data plane implementations, replacing vendor-specific CRDs 
with a unified, portable spec.

# Context
## The Fragmentation of Observability
In the current Kubernetes landscape, the “Who, What, Where, and How Long” of network traffic is answered differently depending on the underlying 
proxy technology. While the Gateway API specification has unified how traffic is routed via `HTTPRoute` and `Gateway`, it has deferred the standardization 
of how that traffic is observed.
This deferral has led to "Observability Lock-in". Platform Engineering teams are forced to learn and manage distinct APIs for each environment. 
A standardized `TelemetryPolicy` is necessary to decouple the intent of observability from the implementation. Without such standardization it is 
difficult for platform owners to: 

1. Enforce consistent auditing standards across different infrastructure providers.
2. Support emerging workloads like AI Agents, which require specialized metrics (e.g., token usage, model latency) and detailed audit logs for tool-use verification.
3. Manage “Mesh” and “Gateway” observability with a single unified API.

## The Emergence of Agentic Networking

The most pressing driver for this proposal is the shift in traffic patterns introduced by agentic workloads. We are moving from a deterministic Service-to-Service 
paradigm to a non-deterministic Agent-to-Tool and Agent-to-Agent paradigm.

In an Agentic Mesh:
* **Entities are Autonomous**: An AI Agent (Pod) decides entirely on its own to call a Tool (Service).
* **Cost is Volatile**: Usage is measured in tokens, not just requests. A single HTTP 200 OK could cost $0.01 or $10.00 depending on the prompt and model used.
* **Context is King**: Debugging requires knowing the semantic context: Which Model? Which Prompt? Which tool?

Existing telemetry policies are unaware of the emerging Generative AI semantic conventions. They see an opaque TCP stream or HTTP POST. Without a standardized API to 
configure the extraction and export of these attributes, the “Agentic Mesh” will remain a black box, increasing governance and cost control challenges.

## Design Objectives

To address these challenges, the `TelemetryPolicy` proposal targets four core objectives:

1. **Standardization**: A single API for Gateway and Mesh to configure Access Logging, Metrics generation, and Tracing propagation.
2. **GEP-713 Compliance**: Support `targetRef` attachment to `Gateway` and `Namespace`. The latter covers Mesh use-cases.
3. **Agentic Support**: Enable the capture of OpenTelemetry GenAI Semantic Conventions and support the requirements of PR #33.
4. **Protocol Agnostic**: Support OpenTelemetry as the primary data model while allowing vendor-specific extensions.

## The TelemetryPolicy Specification

We propose the `TelemetryPolicy` as a direct policy attachment in the `gateway.networking.k8s.io` API group. See [GEP-713](https://gateway-api.sigs.k8s.io/geps/gep-713/#classes-of-policies) for more information on Direct attachment.

### Resource Structure

The following is an example that demonstrates the structure of the `TelemetryPolicy`.

```yaml
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TelemetryPolicy
metadata:
  name: standard-telemetry
  namespace: prod-ns
spec:
  # GEP-713 Attachment
  targetRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: my-gateway
  
  # 1. Tracing Configuration
  tracing:
    provider:
      type: OTLP # or implementation-specific
      endpoint: "otel-collector.monitoring.svc:4317"
    samplingRate: 
      percent: 5
    parentBasedSampling:
      enabled: true
      samplingRate:
        percent: 50
    context:
      - W3C
      - B3
    customAttributes:
      - attributeName: "env"
        literalValue: "production"

  # 2. Metrics Configuration
  metrics:
    enabled: true
    provider:
      type: Prometheus
    overrides:
      - name: "request_count"
        type: Counter
        dimensions: # Custom labels/dimensions
          - key: "model_id"
            fromHeader: "x-model-id" # Crucial for Agentic workloads

  # 3. Access Logging
  accessLogs:
    enable: true
    format: JSON
    matches: # Conditional logging
      - path: "/api/v1/sensitive"
    fields: # Configure specific fields to include
      - "start_time"
      - "response_code"
      - "x-token-usage"
```

### Policy Attachment

Following [GEP-713](https://gateway-api.sigs.k8s.io/geps/gep-713/), the `TelemetryPolicy` supports the following attachments:

1. **Gateway (Instance Scope)**: Configures the telemetry for a specific `Gateway`.
2. **Namespace (Mesh Scope)**: Configures the telemetry for all mesh proxies (sidecar proxy / node proxy / etc.) in that namespace.

#### Alternatives Considered

##### GatewayClass

Targeting `GatewayClass` would set the default telemetry configurations for all Gateways of a specific class. While this would provide a powerful mechanism, the challenge is that `GatewayClass` is a cluster-scoped entity whereas `TelemetryPolicy` is namespace-scoped. Allowing a namespace-scoped resource to influence the behavior of an entire cluster introduces significant operational and security risks. We would also need to define the semantics in the presence of multiple `TelemetryPolicy` resources that target the same `GatewayClass`. This is out of scope for this proposal.

##### Route

Future iterations could support attachment directly to routes (e.g., `HTTPRoute`). This will allow specific telemetry configuration for critical paths or specific API endpoints. To maintain API simplicity in the initial proposal, this is deferred to a future proposal.

##### Workload

We evaluated the ability to target specific workloads directly using pod label selectors. This would allow for precise application of telemetry settings to specific groups of pods (e.g., forcing debug logging on a specific deployment). However, we are prioritizing namespace-level attachment for mesh use-cases to align with existing Gateway API patterns.

##### Service

Attachment to a `Service` is deferred because a `Service` resource primarily defines the "exposure" or inbound side of a workload. It is not intuitive for a policy attached to an inbound definition to configure telemetry for both inbound and outbound traffic. Additionally, since multiple Services can select the same Pod, resolving precedence or merging strategies when different `TelemetryPolicy` resources target those different Services introduces significant complexity.

### Detailed Resource Description

The following are the Go structs modeling the proposed specification:

```Go
// TelemetryPolicy defines a direct policy attachment to configure observability
// signals for Gateway API resources and Service Mesh resources.
type TelemetryPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec TelemetryPolicySpec `json:"spec"`
}

type TelemetryPolicySpec struct {
	// Identifies the target resource (Gateway or Namespace) to which this policy attaches.
	TargetRef TargetRef `json:"targetRef"`

	// Configuration for distributed tracing options.
	Tracing *TracingConfig `json:"tracing,omitempty"`

	// Configuration for metric generation and exports.
	Metrics *MetricsConfig `json:"metrics,omitempty"`

	// Configuration for access log generation.
	AccessLogs *AccessLogsConfig `json:"accessLogs,omitempty"`
}

type TargetRef struct {
	Group string `json:"group"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
}

// --- Tracing Types ---

type TracingConfig struct {
	// Specifies the tracing backend. Includes type (e.g., "OTLP") and endpoint.
	Provider *TracingProvider `json:"provider,omitempty"`

	// The base sampling probability for traces.
	SamplingRate *Fraction `json:"samplingRate,omitempty"`

	// Configures whether to respect the sampling decision of the parent span.
	ParentBasedSampling *ParentBasedSampling `json:"parentBasedSampling,omitempty"`

	// Specifies the context propagation formats to use (e.g., W3C, B3, Jaeger).
	Context []string `json:"context,omitempty"`

	// Allows appending custom tags/attributes to spans.
	CustomAttributes []CustomAttribute `json:"customAttributes,omitempty"`
}

type TracingProvider struct {
	Type     string `json:"type"`
	Endpoint string `json:"endpoint,omitempty"`
}

type Fraction struct {
	Percent int32 `json:"percent,omitempty"`
}

type ParentBasedSampling struct {
	Enabled      bool      `json:"enabled"`
	SamplingRate *Fraction `json:"samplingRate,omitempty"`
}

type CustomAttribute struct {
	AttributeName string `json:"attributeName"`
	LiteralValue  string `json:"literalValue"`
}

// --- Metrics Types ---

type MetricsConfig struct {
	// Global switch to enable or disable metric generation.
	Enabled bool `json:"enabled"`

	// Specifies the metrics backend (e.g., Prometheus).
	Provider *MetricsProvider `json:"provider,omitempty"`

	// List of configurations to customize specific metric families.
	Overrides []MetricOverride `json:"overrides,omitempty"`
}

type MetricsProvider struct {
	Type string `json:"type"`
}

type MetricOverride struct {
	Name       string      `json:"name"`
	Type       string      `json:"type,omitempty"`
	// Defines custom dimensions (labels). Can extract values from headers.
	Dimensions []Dimension `json:"dimensions,omitempty"`
}

type Dimension struct {
	Key        string `json:"key"`
	FromHeader string `json:"fromHeader,omitempty"`
}

// --- Access Logs Types ---

type AccessLogsConfig struct {
	// Global switch to enable or disable access logging.
	Enabled bool `json:"enabled"`

	// The format of the logs (e.g., JSON, Text).
	Format string `json:"format,omitempty"`

	// Conditions for logging, allowing filtering to specific paths or events.
	Matches []MatchCondition `json:"matches,omitempty"`

	// A list of specific fields or headers to include in the logs.
	Fields []string `json:"fields,omitempty"`
}

type MatchCondition struct {
	Path string `json:"path,omitempty"`
}
```

### Alignment with Requirements

#### Agentic Telemetry

* **Token Counting**: The `metrics.overrides` and `accessLogs.fields` sections allow extracting the values from headers (e.g., `x-usage-input-tokens`, `x-usage-output-tokens`) or request/response bodies (if supported by the data plane) into telemetry.
* **Tool Use Auditing**: By attaching a `TelemetryPolicy` to a `Gateway` serving LLM traffic, operators can enforce 100% access logging for specific routes (e.g., `/tool/execute`) to create an immutable audit trail of agent actions.
* **Latency Tracking**: Latency histograms can be configured to track "Time to First Token" (TTFT) if exposed by the backend protocol.

#### Tracing

* **Sampling**: Supports probabilistic and parent-based sampling.
* **Propagation**: Explicitly configures propagation formats (W3C TraceContext defaults, option B3, Jaeger, etc.)
* **Customization**: Allows appending custom tags/attributes to spans.

#### Metrics

* **Granularity**: Users can enable/disable specific metric families.
* **Dimensions**: The API supports "overrides" (similar to [OpenTelemetry Views](https://opentelemetry.io/docs/specs/otel/metrics/sdk/#view)) where users can add or remove dimensions (labels/attributes) to reduce cardinality or increase visibility.

#### Logging

* **Flexible Formatting**: Supports both JSON and text formats for compatibility with standard log aggregation stacks.
* **Smart Filtering**: Reduces noise and cost via CEL-based filtering, allowing logs to be generated only for specific events (e.g., 5xx errors, high latency, or critical paths).
* **Custom Attributes**: Enables the extraction of specific headers and proxy metadata into log entries.
* **Sinks**: Defaults to standard container logging (stdout) with extensibility for OTLP or external ports.

## Comparison with Prior Art

|                | **Istio** | **Envoy Gateway** | **Kong** | **Kuadrant** | **GKE / Inference Gateway** | **TelemetryPolicy**<br />(this proposal) |
| --- | --- | --- | --- | --- | --- | --- |
| Primary API    | [Telemetry CRD](https://istio.io/latest/docs/reference/config/telemetry/) | | | | | |
| Policy Model   | | | | | | |
| Metrics & Logs | | | | | | |
| Portability    | | | | | | |
| AI/LLM Support | | | | | | |
