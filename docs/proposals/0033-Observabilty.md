Date: 19th December 2025<br/>
Authors: david-martin, evaline-ju<br/>
Status: Provisional<br/>

# Observability in Agentic Networking

This proposal addresses observability challenges in agentic systems, where agents use LLMs and tools to autonomously solve user goals. It proposes leveraging distributed tracing standards (W3C Trace Context) with standardized agent-specific attributes to enable comprehensive auditing and debugging of agent execution flows, including user delegation context and permission enforcement.

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

### Distributed Tracing Approach

Leverage distributed tracing standards (W3C Trace Context) to track agent execution flows. The W3C `traceparent` header provides:
- **Trace ID**: A unique identifier for the entire agent session (from initial user goal to completion), propagated across all components
- **Span ID**: A unique identifier for each individual operation (e.g., a single LLM call or tool invocation)

Each component (agent runtime, LLM providers, MCP servers) propagates the trace context via standard headers or request attributes (e.g. `request.params._meta`) and creates spans for its operations. All spans share the same trace ID, allowing the full flow to be reconstructed.

### Standardized Trace Attributes

Extend standard tracing with agent-specific attributes on each span:

- **agent.id**: Identifier for the agent executing the operation
- **user.id**: Identifier for the user who delegated authority to the agent
- **tool.name**: Name of the tool being invoked (for tool call spans)
- **tool.session_id**: Session identifier for the tool invocation
- **permission.policy**: AccessPolicy evaluated for the operation
- **permission.rule**: Specific rule within the AccessPolicy that caused success/failure
- **permission.result**: Whether the permission check passed or failed

### Error and retry standardization

The protocols used by components in agentic systems to communicate are constantly evolving - including but not limited to MCP and A2A, where error formats can be subject to variety. They generally standaridize on one of JSON-RPC or HTTP protocols with further protocol-specific additions (e.g. A2A's task_not_found error code). Errors in logs and spans should include identifiers for error source whether agent or tools, where a common request (trace) ID allows for the error source (e.g. agent Y, tool server X, or LLM server W) to be more easily identified.Protocol-specific attributes can be added to spans.

Error format conventions as defined in [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/registry/attributes/error/) should be followed.

Tracing retries in agentic systems will be complicated by changing parameters. For example, an agent may "retry" a tool call with different tool call parameters, a slightly altered prompt or context, or try to call an entirely alternate tool. A common request (trace) ID needs to be leveraged to track the retry attempts and allow an end user to observe the linked retry attempts. To avoid full logging of prompts and responses, updated prompts can be referenced by hashes.

### Identity Propagation Options

There are two approaches for propagating user and agent identity, which can be used individually or in combination:

1. **Header-based propagation**: Include user and agent identifiers in custom headers (e.g., `X-User-ID`, `X-Agent-ID`) alongside the `traceparent` header. This makes each span independently queryable but adds overhead to every request.

2. **Root span logging**: Log user and agent identity only in the root span at the entry point, relying on trace aggregation backends to correlate this information across all child spans. This reduces overhead but requires trace backend support for joining data.

TODO: worked example showing logs?

TODO: lean into otel?
