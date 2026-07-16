Date: 19th December 2025<br/>
Authors: david-martin, evaline-ju<br/>
Status: Provisional<br/>

# Observability in Agentic Networking

This proposal defines tracing schemas for agentic systems, specifically the structure of traces emitted at runtime. It focuses on proxy-like workloads in Kubernetes environments, including sidecars and gateways. APIs for configuring observability (e.g., Kubernetes CRDs) will be addressed in subsequent proposals.

## OpenTelemetry Semantic Conventions

Follow these OpenTelemetry semantic conventions:

- [GenAI Agent spans](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/) for agent runtime spans
- [GenAI LLM spans](https://opentelemetry.io/docs/specs/semconv/gen-ai/llm-spans/) for LLM provider spans
- [Model Context Protocol (MCP)](https://opentelemetry.io/docs/specs/semconv/gen-ai/mcp/) for tool/MCP server spans
- [Security rule attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/security-rule/) for policy enforcement and guardrails
- [Error attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/error/) for error handling

### Alternate Conventions and Interoperability

The agentic observability ecosystem includes earlier conventions like [OpenInference](https://github.com/Arize-ai/openinference) (used by [Phoenix](https://phoenix.arize.com/) from Arize) that predate the official OpenTelemetry GenAI conventions, as well as OpenTelemetry-compatible extensions like [OpenLLMetry](https://github.com/traceloop/openllmetry) (used by [Traceloop](https://www.traceloop.com/)/[Langfuse](https://langfuse.com/)).

For alternate conventions, use [span processors](https://opentelemetry.io/docs/specs/otel/trace/sdk/#span-processor) or the OpenTelemetry Collector's [transform processor](https://opentelemetry.io/docs/collector/configuration/#processors) with [OTTL](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/transformprocessor) to remap attributes to the GenAI semantic conventions. For non-OpenTelemetry sources, a custom SDK-level bridge is needed to convert to OpenTelemetry spans first.

## Context Propagation

Use [W3C Trace Context](https://www.w3.org/TR/trace-context/) for distributed tracing and [W3C Baggage](https://www.w3.org/TR/baggage/) to propagate:

- `user.id`: Identifier for the user who delegated authority (obfuscated if needed)
- `agent.id`: Identifier for the agent executing operations

W3C Baggage is used instead of `tracestate` because these are application-level identifiers needed for runtime decisions (authorization, rate limiting), not tracing vendor metadata.

## Proposed Extensions

Where OpenTelemetry does not define attributes for permission enforcement outcomes, we propose:

| Attribute | Values | Description |
|-----------|--------|-------------|
| `event.action` | `allow`, `deny` | Action taken due to the policy check |
| `event.outcome` | `success`, `failure`, `unknown` | Outcome of the check itself |
| `security_rule.implicit` | `true` | Present and `true` when the span represents built-in fallback behavior rather than a user-defined rule. Absent on spans produced by explicit rules. |

These can be considered for inclusion in an existing or new OpenTelemetry semantic convention registry.

### Per-Rule Evaluation Spans

For authorization and guardrail checks, implementations should emit a single `mcp.authorization.rule` or `mcp.guardrail.rule` child span identifying the rule that determined the outcome. Each span records:
- `security_rule.name` — the rule identifier
- `event.action` — the action taken (`allow`/`deny`)

This span represents decisive attribution — which rule caused the outcome — rather than a full evaluation log. Implementations may additionally emit spans for rules that were evaluated but did not contribute to the decision, which can be useful for audit purposes; in that case `security_rule.match` should be set to `true`/`false` to indicate whether each rule matched.

For authorization, if no explicit allow rule matches, implementations should emit an `mcp.authorization.rule` span with `security_rule.name: default-deny`, `security_rule.implicit: true`, and `event.action: deny` to make the implicit default-deny behavior visible in traces, rather than leaving the denial attributed only to the parent span. The `security_rule.implicit: true` attribute distinguishes this span from any user-defined rule that might share the same name.

## Retries

Agentic retries often involve changed parameters (different tool arguments, altered prompts, or alternate tools). Use a common trace ID to link retry attempts. Reference prompts by hash to avoid full logging.

## Examples

These examples illustrate how the conventions apply. Span attributes shown are not comprehensive; see the linked OpenTelemetry specifications for complete attribute definitions.

### Access policy enforcement

This shows a trace example of a permission rule checked prior to tool access through a gateway.

```
trace_id: f5a9d214e6b8c7a9d1e2f3a4b5c6d7e8

Claude AI Agent
      │
      │ LLM call
      │
      ▼
Span: gen_ai.agent.chat                         [span_id: 3d4e5f6a]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 342ms ━━━━━━━━━━━━
├─ trace_id: f5a9d214e6b8c7a9d1e2f3a4b5c6d7e8
├─ span.kind: INTERNAL
│
├─ gen_ai.agent.id: claude-agent-prod-001
├─ gen_ai.agent.name: claude-sonnet-4.5
├─ gen_ai.operation.name: chat
├─ gen_ai.system: anthropic
├─ gen_ai.request.model: claude-sonnet-4-5-20250929
│
├─ gen_ai.usage.input_tokens: 1247
├─ gen_ai.usage.output_tokens: 89
│
└─ status: OK
    │
    │
    └─► Span: gen_ai.tool.call                  [span_id: 4e5f6a7b]
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 12ms ━━━━━━━━━━━━━
        ├─ trace_id: f5a9d214e6b8c7a9d1e2f3a4b5c6d7e8  ← Same trace_id
        ├─ span.kind: INTERNAL
        ├─ parent_span_id: 3d4e5f6a
        │
        ├─ gen_ai.tool.name: delete_customer_data
        └─ status: OK
      │
      │ POST /mcp
      │ Headers:
      │   traceparent: 00-f5a9d214e6b8c7a9d1e2f3a4b5c6d7e8-4e5f6a7b-01
      │   Authorization: Bearer eyJhbGc...
      │   ...
      │ Body (JSON-RPC):
      │ {
      │   "jsonrpc": "2.0",
      │   "method": "tools/call",
      │   "params": {
      │     "name": "delete_customer_data",
      │     "arguments": { "customer_id": "12345" }
      │   },
      │   "id": 1
      │ }
      ▼

Span: mcp.gateway.request                       [span_id: 5e6f7a8b]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 17ms ━━━━━━━━━━━━
├─ trace_id: f5a9d214e6b8c7a9d1e2f3a4b5c6d7e8 ← Same trace_id
├─ span.kind: SERVER
├─ parent_span_id: 4e5f6a7b
├─ http.response.status_code: 403
│
├─ gen_ai.operation.name: execute_tool
├─ gen_ai.tool.name: delete_customer_data
│
├─ mcp.method.name: tools/call
├─ mcp.session.id: sess_agent_2p7k4m
│
├─ error.type: PermissionDeniedError
└─ status: ERROR
    │
    │
    ├─► Span: mcp.authorization                 [span_id: 7a8b9c1d]
    │   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 15ms ━━━━━━━━━━━━
    │   ├─ trace_id: f5a9d214e6b8c7a9d1e2f3a4b5c6d7e8  ← Same trace_id
    │   ├─ span.kind: INTERNAL
    │   ├─ parent_span_id: 5e6f7a8b
    │   │
    │   ├─ security_rule.ruleset.name: crm_data_access_policy
    │   ├─ event.action: deny
    │   ├─ event.outcome: success
    │   │
    │   ├─ error.type: PermissionDeniedError
    │   ├─ error.message: "User role 'support_agent' lacks privileges for customer_data.delete"
    │   ├─ status: ERROR
    │   │
    │   └─► Span: mcp.authorization.rule         [span_id: 2e3f4a5b]
    │       ├─ security_rule.name: default-deny
    │       ├─ security_rule.implicit: true
    │       ├─ event.action: deny
    │       └─ event.outcome: success
    │
    │
    └─► Span: mcp.audit.log                     [span_id: 8b9c1d2e]
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2ms ━━━━━━━━━━━
        ├─ trace_id: f5a9d214e6b8c7a9d1e2f3a4b5c6d7e8  ← Same trace_id
        ├─ span.kind: INTERNAL
        ├─ parent_span_id: 5e6f7a8b
        ├─ audit.event.type: authorization_failure
        ├─ audit.event.category: security
        ├─ audit.event.outcome: failure
        ├─ ...
        └─ status: OK

      │
      ▼
   ⛔ Error: 403 - Forbidden
   🔒 Permission denied: insufficient privileges for customer_data.delete
```

### Guardrailing

This shows a trace example of a guardrail blocking a request at a gateway.

```
trace_id: c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8

Claude AI Agent
      │
      │ LLM call
      │
      ▼
Span: gen_ai.agent.chat                         [span_id: 3d4e5f6a]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 342ms ━━━━━━━━━━━━
├─ trace_id: c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8
├─ span.kind: INTERNAL
│
├─ gen_ai.agent.id: claude-agent-prod-001
├─ gen_ai.agent.name: claude-sonnet-4.5
├─ gen_ai.operation.name: chat
├─ gen_ai.system: anthropic
├─ gen_ai.request.model: claude-sonnet-4-5-20250929
│
├─ gen_ai.usage.input_tokens: 427
├─ gen_ai.usage.output_tokens: 89
│
└─ status: OK
    │
    │
    └─► Span: gen_ai.tool.call                  [span_id: 4e5f6a7b]
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 12ms ━━━━━━━━━━━━━
        ├─ trace_id: c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8  ← Same trace_id
        ├─ span.kind: INTERNAL
        ├─ parent_span_id: 3d4e5f6a
        │
        ├─ gen_ai.tool.name: send_email
        └─ status: OK
      │
      │ POST /mcp
      │ Headers:
      │   traceparent: 00-c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8-4e5f6a7b-01
      │   ...
      │ Body (JSON-RPC):
      │ {
      │   "jsonrpc": "2.0",
      │   "method": "tools/call",
      │   "params": {
      │     "name": "send_email",
      │     "arguments": {
      │       "to": "bob@example.com",
      │       "body": "SSN: 123-45-6789, CC: 4532-1234-5678-9010"
      │     }
      │   },
      │   "id": 2
      │ }
      ▼

Span: mcp.gateway.request                       [span_id: 5e6f7a8b]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 30ms ━━━━━━━━━━━━
├─ trace_id: c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8 ← Same trace_id
├─ span.kind: SERVER
├─ parent_span_id: 4e5f6a7b
├─ http.response.status_code: 400
│
├─ gen_ai.operation.name: execute_tool
├─ gen_ai.tool.name: send_email
│
├─ mcp.method.name: tools/call
├─ mcp.session.id: sess_agent_5k9m2n
│
├─ error.type: GuardrailViolationError
└─ status: ERROR
    │
    ├─► Span: mcp.guardrail.evaluate            [span_id: 7a8b9c1d]
    │   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 25ms ━━━━━━━━━━━━
    │   ├─ trace_id: c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8  ← Same trace_id
    │   ├─ span.kind: INTERNAL
    │   ├─ parent_span_id: 5e6f7a8b
    │   │
    │   ├─ security_rule.ruleset.name: pii_detection_policy
    │   ├─ event.action: deny
    │   ├─ event.outcome: success
    │   │
    │   ├─ error.type: GuardrailViolationError
    │   ├─ error.message: "PII detected: SSN, Credit Card"
    │   ├─ status: ERROR
    │   │
    │   └─► Span: mcp.guardrail.rule             [span_id: 1d2e3f4a]
    │       ├─ security_rule.name: block_sensitive_pii
    │       ├─ security_rule.match: true
    │       ├─ event.action: deny
    │       ├─ event.outcome: success
    │       ├─ guardrail.pii.types_detected: [ssn, credit_card]
    │       ├─ guardrail.pii.confidence: high
    │       └─ guardrail.pii.field: arguments.body
    │
    └─► Span: mcp.audit.log                     [span_id: 8b9c1d2e]
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 5ms ━━━━━━━━━━━
        ├─ trace_id: c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8  ← Same trace_id
        ├─ span.kind: INTERNAL
        ├─ audit.event.type: guardrail_violation
        ├─ ...
        ├─ audit.pii.types: [ssn, credit_card]
        ├─ audit.severity: critical
        └─ status: OK

      │
      ▼
   ⛔ 400 Bad Request - Guardrail violation: PII detected
   🔒 Blocked: SSN and Credit Card found in request
```
