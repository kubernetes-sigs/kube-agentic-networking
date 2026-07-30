# Copyright The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
GenAI Semantic Conventions for Agent-side OpenTelemetry spans.

Based on the 0033-Observability proposal:
https://github.com/kubernetes-sigs/kube-agentic-networking/blob/main/docs/proposals/0033-Observability.md

Follows OpenTelemetry GenAI semantic conventions:
- https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/
- https://opentelemetry.io/docs/specs/semconv/gen-ai/llm-spans/

Note: This module only includes spans that the agent itself emits.
Gateway-level spans (mcp.gateway.request, mcp.authorization, etc.) are emitted by the gateway/proxy.
"""

from contextlib import contextmanager
from typing import Optional
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode


class GenAISpanAttributes:
    """GenAI semantic convention attribute names for agent-side spans."""

    # Agent attributes
    AGENT_ID = "gen_ai.agent.id"
    AGENT_NAME = "gen_ai.agent.name"

    # Operation attributes
    OPERATION_NAME = "gen_ai.operation.name"
    SYSTEM = "gen_ai.system"

    # Request/Response attributes
    REQUEST_MODEL = "gen_ai.request.model"
    USAGE_INPUT_TOKENS = "gen_ai.usage.input_tokens"
    USAGE_OUTPUT_TOKENS = "gen_ai.usage.output_tokens"

    # Tool attributes
    TOOL_NAME = "gen_ai.tool.name"


class GenAISpanHelper:
    """Helper class for creating agent-side GenAI semantic convention spans."""

    def __init__(self, tracer: trace.Tracer):
        self.tracer = tracer

    @contextmanager
    def create_agent_chat_span(
        self,
        agent_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        system: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """Create a gen_ai.agent.chat span as the current span for trace hierarchy."""
        with self.tracer.start_as_current_span("gen_ai.agent.chat") as span:
            if agent_id:
                span.set_attribute(GenAISpanAttributes.AGENT_ID, agent_id)
            if agent_name:
                span.set_attribute(GenAISpanAttributes.AGENT_NAME, agent_name)
            if system:
                span.set_attribute(GenAISpanAttributes.SYSTEM, system)
            if model:
                span.set_attribute(GenAISpanAttributes.REQUEST_MODEL, model)

            span.set_attribute(GenAISpanAttributes.OPERATION_NAME, "chat")

            yield span

    @contextmanager
    def create_tool_call_span(self, tool_name: str):
        """Create a gen_ai.tool.call span as the current span, enabling context propagation via inject()."""
        with self.tracer.start_as_current_span("gen_ai.tool.call") as span:
            span.set_attribute(GenAISpanAttributes.TOOL_NAME, tool_name)
            span.set_attribute(GenAISpanAttributes.OPERATION_NAME, "execute_tool")
            yield span

    def set_token_usage(
        self,
        span: trace.Span,
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
    ):
        if input_tokens is not None:
            span.set_attribute(GenAISpanAttributes.USAGE_INPUT_TOKENS, input_tokens)
        if output_tokens is not None:
            span.set_attribute(GenAISpanAttributes.USAGE_OUTPUT_TOKENS, output_tokens)

    def set_success_status(self, span: trace.Span):
        """Set span status to OK."""
        span.set_status(Status(StatusCode.OK))

    def set_error_status(self, span: trace.Span, error: Exception, error_type: Optional[str] = None):
        span.set_status(Status(StatusCode.ERROR, str(error)))
        span.record_exception(error)

        if error_type:
            span.set_attribute("error.type", error_type)
