# OpenTelemetry Instrumentation for ADK Agent

This document describes the OpenTelemetry (OTEL) instrumentation added to the ADK agent for distributed tracing.

## Overview

The ADK agent has been instrumented with OpenTelemetry to provide observability through distributed tracing. This allows you to:

- Track requests through the agent and its dependencies
- Monitor MCP toolset initialization and usage
- Debug performance issues
- Understand the flow of agent operations

## Architecture

The instrumentation follows a similar pattern to the [weather_service example](https://github.com/kagenti/agent-examples/tree/main/a2a/weather_service):

1. **OTEL Collector**: Receives traces from the agent via OTLP protocol
2. **Agent Instrumentation**: Automatically traces FastAPI endpoints and custom spans for agent operations
3. **Export Options**: Traces can be exported to various backends (Jaeger, Zipkin, etc.)

## Components

### 1. Dependencies (`requirements.txt`)

Added OpenTelemetry packages:
- `opentelemetry-api` - Core OTEL API
- `opentelemetry-sdk` - OTEL SDK implementation
- `opentelemetry-exporter-otlp` - OTLP exporter for sending traces
- `opentelemetry-instrumentation-fastapi` - Automatic FastAPI instrumentation
- `opentelemetry-instrumentation-logging` - Log correlation with traces

### 2. Instrumentation Module (`otel_instrumentation.py`)

Provides:
- `setup_otel_tracing()` - Initializes OTEL with OTLP exporter
- `instrument_fastapi()` - Instruments FastAPI app for automatic tracing
- `get_tracer()` - Returns a tracer for custom spans

### 3. Main Application (`main.py`)

- Sets up OTEL tracing before creating the FastAPI app
- Instruments the FastAPI app for automatic endpoint tracing
- Configures service name and resource attributes

### 4. Agent Module (`mcp_agent/agent.py`)

- Adds custom spans for MCP toolset initialization using **GenAI semantic conventions**
- Tracks local and remote MCP connections
- Records errors and exceptions in spans
- Sets span attributes following OpenTelemetry GenAI standards
- **Propagates trace context (traceparent) to MCP tools via headers**

### 5. GenAI Spans Module (`mcp_agent/genai_spans.py`)

Helper module for creating spans that follow OpenTelemetry GenAI semantic conventions:
- `gen_ai.agent.chat` - Agent chat operations
- `gen_ai.tool.call` - Tool/MCP initialization and calls
- Attributes: `gen_ai.agent.id`, `gen_ai.tool.name`, `gen_ai.operation.name`, etc.

Based on the [0033-Observability proposal](https://github.com/kubernetes-sigs/kube-agentic-networking/blob/main/docs/proposals/0033-Observability.md) and [OpenTelemetry GenAI conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/).

#### Trace Context Propagation

The agent uses OpenTelemetry's `TraceContextTextMapPropagator` to inject trace context into HTTP headers when calling MCP tools:

```python
propagator = TraceContextTextMapPropagator()

def get_trace_headers():
    """Get headers with trace context for propagating traces."""
    headers = {}
    propagator.inject(headers)  # Injects traceparent and tracestate
    return headers
```

When initializing MCP toolsets, the trace headers are merged with authentication headers:

```python
trace_headers = get_trace_headers()
headers = {
    "x-k8s-sa-token": sa_token,
    **trace_headers,  # Includes traceparent header
}
```

This ensures that:
1. Each request to MCP tools includes a `traceparent` header
2. The downstream service can extract the trace context and continue the trace
3. All operations form a single distributed trace across services

### 5. Deployment Configuration (`deployment.yaml`)

Environment variables:
- `OTEL_EXPORTER_OTLP_ENDPOINT` - OTEL collector endpoint (default: `http://otel-collector:4317`)
- `OTEL_SERVICE_NAME` - Service name for traces (default: `adk-agent`)
- `NAMESPACE` - Kubernetes namespace (from pod metadata)
- `HOSTNAME` - Pod name (from pod metadata)

## Deployment

### 1. Deploy the OTEL Collector

```bash
kubectl apply -f quickstart/adk-agent/otel-collector.yaml
```

This creates:
- ConfigMap with OTEL collector configuration
- Deployment running the OTEL collector
- Service exposing the collector endpoints

### 2. Deploy the ADK Agent

The agent deployment already includes the necessary environment variables:

```bash
kubectl apply -f quickstart/adk-agent/deployment.yaml
```

### 3. Verify Traces

Check the OTEL collector logs to see traces:

```bash
kubectl logs -n team1 -l app=otel-collector -f
```

## Trace Examples

### Automatic FastAPI Traces

All FastAPI endpoints are automatically traced:
- HTTP method and path
- Status code
- Request duration
- Error details (if any)

### GenAI Semantic Convention Spans

The agent creates spans following OpenTelemetry GenAI semantic conventions:

**MCP Initialization Spans** (`gen_ai.tool.call`):
- `local_mcp_init` - Local MCP toolset initialization
- `remote_mcp_init` - Remote MCP toolset initialization

Each span includes:
- `gen_ai.tool.name` - Tool/MCP identifier
- `gen_ai.operation.name` - Operation type ("execute_tool")
- `mcp.type` - Type of MCP (local/remote)
- `mcp.url` - MCP endpoint URL
- `error.type` - Error classification (if initialization fails)
- Status (OK/ERROR)
- Exception details (if initialization fails)

These spans follow the [0033-Observability proposal](https://github.com/kubernetes-sigs/kube-agentic-networking/blob/main/docs/proposals/0033-Observability.md) and [OpenTelemetry GenAI conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/).

## Configuration

### Change OTEL Collector Endpoint

Edit the `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable in `deployment.yaml`:

```yaml
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: "http://your-collector:4317"
```

### Export to Jaeger

Uncomment the Jaeger exporter in `otel-collector.yaml`:

```yaml
exporters:
  otlp/jaeger:
    endpoint: jaeger-collector:4317
    tls:
      insecure: true

service:
  pipelines:
    traces:
      exporters: [logging, otlp/jaeger]
```

### Export to Prometheus

Uncomment the Prometheus exporter in `otel-collector.yaml`:

```yaml
exporters:
  prometheus:
    endpoint: "0.0.0.0:8889"

service:
  pipelines:
    metrics:
      exporters: [logging, prometheus]
```

## Adding Custom Spans

To add custom tracing to your code:

```python
from opentelemetry import trace

tracer = trace.get_tracer(__name__)

with tracer.start_as_current_span("my_operation") as span:
    span.set_attribute("custom.attribute", "value")
    try:
        # Your code here
        result = do_something()
        span.set_status(Status(StatusCode.OK))
    except Exception as e:
        span.set_status(Status(StatusCode.ERROR, str(e)))
        span.record_exception(e)
        raise
```

## Troubleshooting

### No traces appearing

1. Check OTEL collector is running:
   ```bash
   kubectl get pods -n team1 -l app=otel-collector
   ```

2. Check agent can reach collector:
   ```bash
   kubectl logs -n team1 -l app=adk-agent
   ```

3. Verify environment variables are set:
   ```bash
   kubectl describe pod -n team1 -l app=adk-agent
   ```

### Traces not exported

Check the OTEL collector configuration and ensure exporters are properly configured in the ConfigMap.

## References

- [OpenTelemetry Python Documentation](https://opentelemetry.io/docs/instrumentation/python/)
- [OTEL Collector Documentation](https://opentelemetry.io/docs/collector/)
- [Weather Service Example](https://github.com/kagenti/agent-examples/tree/main/a2a/weather_service)