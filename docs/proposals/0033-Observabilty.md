Date: 19th December 2025<br/>
Authors: david-martin, evaline-ju<br/>
Status: Provisional<br/>

# Observability in Agentic Networking

This proposal addresses observability challenges in agentic systems, where agents use LLMs and tools to autonomously solve user goals. It proposes leveraging distributed tracing standards (W3C Trace Context) with standardized agent-specific attributes to enable comprehensive auditing and debugging of agent execution flows, including user delegation context and permission enforcement.

This proposal focuses on defining tracing schemas, specfically the structure of traces that will be emitted at runtime of agentic systems. APIs such as Kubernetes CRDs to allow users to configure traces and other observability data such as metrics and logs will be addressed in subsequent proposals. Here, we also particularly focus on tracing for proxy-like workloads in Kubernetes environments, including but not limited to sidecars and gateways.

Generally this proposal recommends following existing OpenTelemetry semantic conventions. New permission and AccessPolicy attributes are also proposed here and can be considered for inclusion in an existing or new OpenTelemetry semantic convention registry.

## Problem space

Users of Agentic systems can set goals for an Agent to solve. For example, "Generate a sales report for Q4 and share it with the leadership team". Agents use LLMs and tools in a loop to reach the goal. This will require tools like 'database query', 'report generation', and 'email/messaging'. LLM access will be required for things like analyzing sales data patterns, formatting the report, and composing the distribution message.

If something goes wrong while the Agent is solving the goal, such as the Agent attempting to access restricted financial data beyond its permitted scope, or trying to share the report with unauthorized recipients, it's necessary to understand where the Agent went wrong and why.

This requires solving several observability challenges:
- How to trace an agent's entire execution flow from the initial user request through to completion
- How to reference which LLM calls were made, what prompts were sent, and what responses were received. For security and compliance, we recommend not capturing full prompts and responses in logs. Trace IDs could be used as pointers, and prompts could be identified via hashes or IDs, with full content retrieved only as necessary through appropriate access controls.
- How to log tool invocations with sufficient context about why they were called and what permissions were checked
- How to provide detailed information when a permission check fails, including which AccessPolicy rule caused the failure
- How to correlate agent actions back to the original user who delegated authority
- How to standardize the format for logging agent-related events across different components (agent runtime, LLM providers, MCP servers, etc.)

## Possible solution

The solution should provide:
- A holistic view of the entire agent flow, from the initial user goal to the final response
- Ability to drill down into each leg of the interaction: user-to-agent requests, agent-to-LLM requests, and agent-to-tool requests
- Standardized logging format that includes user identity, agent identity, and permission check results
- When a tool request fails due to an AccessPolicy, the audit trail should show the specific AccessPolicy and rule that caused the failure

### Distributed Tracing Foundation

All solutions leverage distributed tracing standards (W3C Trace Context) to track agent execution flows. The trace starts at the user-facing entry point (e.g., API gateway, agent controller) when the user submits their goal. The W3C `traceparent` header provides:
- **Trace ID**: A unique identifier for the entire agent session (from initial user goal to completion), propagated across all components
- **Span ID**: A unique identifier for each individual operation (e.g., a single LLM call or tool invocation)

Each component (agent runtime, LLM providers, MCP servers) propagates the trace context via standard headers or request attributes (e.g. `request.params._meta`) and emits spans for its operations. All spans share the same trace ID, allowing the full flow to be reconstructed.

### Solution Options

There are three approaches to propagating and logging observability context, each with different trade-offs:

#### Option 1: Minimal Propagation (Trace ID Only)

Propagate only the W3C `traceparent` header (trace ID + span ID). All contextual information (user identity, agent identity, permissions, etc.) is logged only in the root span at the entry point.

**Pros:**
- Minimal network/header size overhead
- Single source of truth for identity
- Better privacy - sensitive identifiers only at entry point
- Simpler component implementation

**Cons:**
- Requires a tracing and/or logging backend with join capabilities to correlate spans with root context

#### Option 2: Full Context Propagation (Everything in Baggage)

Propagate all contextual information (user.id (obfuscated), agent.id, tool.name, permission.policy, etc.) via W3C Baggage header or custom headers on every request.

**Pros:**
- Each span is self-contained and independently queryable
- Works with any (and no) observability backend

**Cons:**
- Additional network overhead, potentially reaching header size limits
- Data duplication - same values replicated across potentially thousands of spans
- Privacy risk - sensitive identifiers propagated to all components. Though this can be mitigated via obfuscation.
- More complex propagation logic in each component
- Not all context is relevant to all components (e.g., permission.rule not needed by LLM providers)

#### Option 3: Hybrid Approach with Critical Baggage (Recommended)

Propagate only **critical cross-cutting context** via W3C Baggage that components need for runtime decisions or independent queryability. Each component enriches spans with **component-specific attributes** relevant to their operations.

**What to propagate via W3C Baggage:**
- `user.id`: Identifier for the user who delegated authority (needed for authorization, rate limiting, auditing), obfuscated if needed.
- `agent.id`: Identifier for the agent executing operations (needed for authorization, attribution, auditing)

Note: W3C Baggage is used instead of `tracestate` because user and agent identities are application-level context that components need for runtime decisions (authorization, rate limiting), not tracing vendor metadata. The W3C Baggage specification is explicitly designed for "application-defined properties" that flow with requests.

**What each component emits as span attributes:**

Components should follow [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/) where available, and extend with domain-specific attributes as needed.

*Agent runtime spans:*

Follow [OpenTelemetry GenAI Agent spans conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/) such as:
- `gen_ai.agent.id`: Identifier for the agent
- `gen_ai.agent.name`: Name of the agent
- `gen_ai.operation.name`: The operation being performed (e.g., "chat", "generate_content")

*LLM provider spans:*

Follow [OpenTelemetry GenAI LLM spans conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/non-normative/examples-llm-calls/) such as:
- `gen_ai.provider.name`: The LLM system being used (e.g., "openai", "anthropic")
- `gen_ai.request.model`: Model identifier (e.g., "gpt-4", "claude-3-5-sonnet")
- `gen_ai.usage.input_tokens`: Input token count
- `gen_ai.usage.output_tokens`: Output token count
- `gen_ai.operation.name`: The operation being performed (e.g., "chat", "completion")

*Tool/MCP server spans:*

Follow [OpenTelemetry MCP semantic conventions](https://github.com/open-telemetry/semantic-conventions/pull/2083) such as:
- `mcp.method.name`: Name of the MCP method being invoked (e.g., "tools/call")
- `mcp.session.id`: Session identifier for the MCP connection
- `gen_ai.operation.name`: The operation being performed (e.g., "execute_tool")
- `gen_ai.tool.name`: Name of the tool utilized by the agent. (e.g. "Flights")

**Permission and AccessPolicy attributes (proposed):**

For permission checks and AccessPolicy enforcement, we propose the following span attributes to capture authorization decisions:
- `permission.policy.name`: Name or identifier of the AccessPolicy evaluated
- `permission.policy.rule`: Specific rule within the AccessPolicy that determined the outcome
- `permission.result`: Result of the permission check (`allowed` or `denied`)

**Pros:**
- Balances queryability with network efficiency
- Spans remain queryable by the most important dimensions without backend joins
- Backend can still enrich or aggregate as needed

**Cons:**
- Requires deciding what qualifies as "critical" (though user.id and agent.id are clear choices)
- Still some propagation overhead compared to Option 1

**Why this is recommended:**
1. User and agent identities are genuinely cross-cutting concerns needed for authorization and auditing across all components
2. These identifiers are typically small (UUIDs or short strings)
3. Component-specific details (tool names, permission rules, LLM tokens) are only relevant where they occur and shouldn't be propagated
4. Enables independent span queries for the most common use cases (filtering by user or agent) without requiring backend correlation
5. Maintains privacy by not propagating verbose or sensitive data unnecessarily

### Error and Retry Standardization

The protocols used by components in agentic systems to communicate are constantly evolving - including but not limited to MCP and A2A, where error formats can be subject to variety. They generally standardize on one of JSON-RPC or HTTP protocols with further protocol-specific additions (e.g. A2A's task_not_found error code). Errors in logs and spans should include identifiers for error source whether agent or tools, where a common trace ID allows for the error source (e.g. agent Y, tool server X, or LLM server W) to be more easily identified. Protocol-specific attributes can be added to spans.

Error format conventions as defined in [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/registry/attributes/error/) should be followed.

Tracing retries in agentic systems will be complicated by changing parameters. For example, an agent may "retry" a tool call with different tool call parameters, a slightly altered prompt or context, or try to call an entirely alternate tool. A common trace ID needs to be leveraged to track the retry attempts and allow an end user to observe the linked retry attempts. To avoid full logging of prompts and responses, updated prompts can be referenced by hashes.

### Examples

The shown span attributes utilize the example span attributes listed in previous sections but are not comprehensive of what attributes can be included.

#### Access policy enforcement

This shows a trace example of a permission rule checked prior to tool access through a gateway.

```
trace_id: f5a9d214e6b8c7a9d1e2f3a4b5c6d7e8

Claude AI Agent
      │
      │ POST /mcp
      │ Headers:
      │   traceparent: 00-f5a9d214e6b8c7a9d1e2f3a4b5c6d7e8-5e6f7a8b9c1d2e3f-01
      │   Authorization: Bearer eyJhbGc...
      │   ...
      │ tool: delete_customer_data
      ▼

Span : mcp.gateway.request                           [span_id: 5e6f7a8b]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 17ms ━━━━━━━━━━━━━━
├─ trace_id: f5a9d214e6b8c7a9d1e2f3a4b5c6d7e8
├─ span.kind: SERVER
├─ http.response.status_code: 403
│
├─ gen_ai.agent.id: claude-agent-prod-001
├─ gen_ai.agent.name: claude-sonnet-4.5
├─ gen_ai.operation.name: execute_tool
├─ gen_ai.tool.name: delete_customer_data
├─ gen_ai.system: anthropic
├─ gen_ai.request.model: claude-sonnet-4-20250514
├─ gen_ai.operation.name: tool_use
│
├─ mcp.method.name: tools/call
├─ mcp.session.id: sess_agent_2p7k4m
│
├─ error.type: PermissionDeniedError
└─ status: ERROR
    │
    │
    ├─► Span: mcp.authorization               [span_id: 7a8b9c1d]
    │   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 15ms ━━━━━━━━━━━━━
    │   ├─ trace_id: f5a9d214e6b8c7a9d1e2f3a4b5c6d7e8  ← Same trace_id
    │   ├─ span.kind: INTERNAL
    │   ├─ parent_span_id: 5e6f7a8b
    │   │
    │   ├─ permission.policy.name: crm_data_access_policy
    │   ├─ permission.policy.rule: admin_only_delete
    │   ├─ permission.result: denied
    │   ├─ permission.denial.reason: insufficient_privileges
    │   │
    │   ├─ error.type: PermissionDeniedError
    │   ├─ error.message: "User role 'support_agent' lacks privileges for customer_data.delete"
    │   └─ status: ERROR
    │
    │
    └─► Span: mcp.audit.log                   [span_id: 8b9c1d2e]
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2ms ━━━━━━━━━━━━━
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

#### Guardrailing

This shows a trace example of a guardrail blocking a request at a gateway.

```
trace_id: c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8

Claude AI Agent
      │
      │ POST /mcp
      │ Headers:
      │   traceparent: 00-c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8-9c1d2e3f4a5b6c7d-01
      │   ...
      │ {
      │   "method": "tools/call",
      │   "params": {
      │     "name": "send_email",
      │     "arguments": {
      │       "to": "bob@example.com",
      │       "body": "SSN: 123-45-6789, CC: 4532-1234-5678-9010"
      │     }
      │   }
      │ }
      ▼

Span : mcp.gateway.request                           [span_id: 5e6f7a8b]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 30ms ━━━━━━━━━━━━━━
├─ trace_id: c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8
├─ span.kind: SERVER
├─ http.response.status_code: 400
│
├─ gen_ai.agent.id: claude-agent-prod-001
├─ gen_ai.agent.name: claude-sonnet-4.5
├─ gen_ai.operation.name: execute_tool
├─ gen_ai.tool.name: send_email
│
├─ mcp.method.name: tools/call
├─ mcp.session.id: sess_agent_5k9m2n
│
├─ error.type: GuardrailViolationError
└─ status: ERROR
    │
    ├─► Span: mcp.guardrail.evaluate      [span_id: 7a8b9c1d]
    │   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 25ms ━━━━━━━━━━━━━
    │   ├─ trace_id: c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8  ← Same trace_id
    │   ├─ span.kind: INTERNAL
    │   ├─ parent_span_id: 5e6f7a8b
    │   │
    │   ├─ guardrail.type: content_filter
    │   ├─ guardrail.policy.name: pii_detection_policy
    │   ├─ guardrail.policy.rule: block_sensitive_pii
    │   ├─ guardrail.result: blocked
    │   │
    │   ├─ guardrail.pii.types_detected: [ssn, credit_card]
    │   ├─ guardrail.pii.confidence: high
    │   ├─ guardrail.pii.field: arguments.body
    │   │
    │   ├─ error.type: PIIDetectedError
    │   ├─ error.message: "PII detected: SSN, Credit Card"
    │   └─ status: ERROR
    │
    └─► Span: mcp.audit.log               [span_id: 8b9c1d2e]
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 5ms ━━━━━━━━━━━━━
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


TODO: worked example showing logs & spans, including flow diagram
