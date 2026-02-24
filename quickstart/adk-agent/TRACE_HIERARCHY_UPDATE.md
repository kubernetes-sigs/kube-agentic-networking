# Unified Trace Hierarchy Update

## Overview
Updated the OpenTelemetry instrumentation to ensure all agent spans are linked in a unified trace hierarchy with the same traceparent.

## Changes Made

### 1. `mcp_agent/genai_spans.py`
**Modified `create_agent_chat_span()` method:**
- Changed from `tracer.start_span()` to `tracer.start_as_current_span()`
- Made it a context manager using `@contextmanager` decorator
- Now properly sets the span as the active span in the OpenTelemetry context

**Impact:**
- The agent chat span now becomes the active parent span
- All child spans created within its context will automatically be linked to it
- Enables proper trace context propagation throughout the span hierarchy

### 2. `mcp_agent/agent.py`
**Wrapped MCP initialization in parent span:**
- Created a parent `gen_ai.agent.chat` span that encompasses all MCP toolset initialization
- Both `local_mcp_init` and `remote_mcp_init` spans are now children of this parent span
- Added `operation.type` attribute to identify this as agent initialization

**Impact:**
- All MCP initialization spans now share the same trace ID
- The `get_trace_headers()` function will inject the same traceparent for both local and remote MCP
- Creates a proper parent-child relationship: `agent_initialization` → `local_mcp_init` + `remote_mcp_init`

## Trace Hierarchy Structure

```
gen_ai.agent.chat (agent_initialization)
├── gen_ai.tool.call (local_mcp_init)
│   └── [HTTP requests to local MCP with propagated traceparent]
└── gen_ai.tool.call (remote_mcp_init)
    └── [HTTP requests to remote MCP with propagated traceparent]
```

## Benefits

1. **Unified Trace ID**: All spans now share the same trace ID, making it easy to correlate all operations
2. **Proper Parent-Child Relationships**: Clear hierarchy shows which operations are part of agent initialization
3. **Consistent Traceparent Propagation**: Both local and remote MCP receive the same traceparent header
4. **Better Observability**: Distributed tracing tools can now show the complete agent initialization flow
5. **Error Correlation**: Errors in any child span can be traced back to the parent initialization span

## Verification

To verify the unified trace hierarchy:

1. Check that all spans have the same trace ID in the first part of the traceparent header
2. Verify parent-child relationships using span IDs in the traceparent
3. Confirm that downstream services (MCP servers) receive consistent traceparent values
4. Use a tracing backend (e.g., Jaeger, Zipkin) to visualize the complete trace tree

## Example Traceparent Format

```
traceparent: 00-<trace-id>-<parent-span-id>-01

Where:
- trace-id: Same for all spans in the hierarchy (32 hex chars)
- parent-span-id: Different for each span, links to parent (16 hex chars)
- 01: Sampled flag
```

All spans created within the agent initialization context will have:
- **Same trace-id**: Links them to the same distributed trace
- **Different parent-span-id**: Shows parent-child relationships
- **Propagated to downstream**: MCP servers receive the traceparent and can continue the trace