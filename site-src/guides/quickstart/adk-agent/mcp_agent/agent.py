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

import logging
import os
from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams

import contextvars

from opentelemetry import trace, context
from .genai_spans import GenAISpanHelper

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Environment variables
envoy_service = os.environ.get("ENVOY_SERVICE")
gemini_model = os.environ.get("GEMINI_MODEL")
hf_model = os.environ.get("HF_MODEL")
ollama_base_url = os.environ.get("OLLAMA_BASE_URL")
ollama_model = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")

# Agent configuration
AGENT_NAME = "multi_mcp_agent"
AGENT_SYSTEM = "huggingface"

# Default to Hugging Face mode if provided, then Gemini, then Ollama
if hf_model:
    logger.info(f"Using Hugging Face model: {hf_model}")
    model = LiteLlm(model=hf_model)
elif gemini_model:
    AGENT_SYSTEM = "gemini"
    logger.info(f"Using Gemini model: {gemini_model}")
    model = gemini_model
else:
    # Use Ollama (either custom URL or default host.docker.internal)
    AGENT_SYSTEM = "ollama"
    base_url = ollama_base_url or "http://host.docker.internal:11434"

    # LiteLLM requires OPENAI_API_KEY even for Ollama's openai-compatible endpoint
    if not os.environ.get("OPENAI_API_KEY"):
        os.environ["OPENAI_API_KEY"] = "ollama"
        logger.info("Setting OPENAI_API_KEY to dummy value for Ollama compatibility")

    if ollama_base_url:
        logger.info(f"Using Ollama model: {ollama_model} at {base_url}")
    else:
        logger.warning(f"No HF_MODEL or OLLAMA_BASE_URL found. Defaulting to Ollama at {base_url}")

    model = LiteLlm(
        model=f"openai/{ollama_model}",
        api_base=f"{base_url}/v1",
    )

tracer = trace.get_tracer(__name__)
genai_helper = GenAISpanHelper(tracer)

# Tracks the active tool call span across async boundaries so httpx instrumentation
# can inject the correct traceparent into outgoing requests to the gateway.
_active_tool_span: contextvars.ContextVar = contextvars.ContextVar("_active_tool_span", default=None)


def _before_tool_callback(tool, args, tool_context):
    """Create a gen_ai.tool.call span and attach it to the current context.

    ADK's httpx instrumentation reads the active span to inject traceparent,
    linking this agent span to the gateway's ingress span in the same trace.
    """
    tool_name = getattr(tool, "name", str(tool))
    span = tracer.start_span(
        "gen_ai.tool.call",
        attributes={
            "gen_ai.tool.name": tool_name,
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.agent.name": AGENT_NAME,
        },
    )
    token = context.attach(trace.set_span_in_context(span))
    _active_tool_span.set((span, token))
    logger.debug(
        f"tool_call_start tool={tool_name} "
        f"trace_id={span.get_span_context().trace_id:032x} "
        f"span_id={span.get_span_context().span_id:016x}"
    )
    return None


def _after_tool_callback(tool, args, tool_context, tool_response):
    """End the gen_ai.tool.call span after the MCP tool completes."""
    entry = _active_tool_span.get()
    if entry is None:
        return None
    span, token = entry
    _active_tool_span.set(None)
    tool_name = getattr(tool, "name", str(tool))
    if isinstance(tool_response, dict) and tool_response.get("error"):
        span.set_status(trace.Status(trace.StatusCode.ERROR, str(tool_response["error"])))
        span.set_attribute("error.type", "ToolExecutionError")
    else:
        span.set_status(trace.Status(trace.StatusCode.OK))
    span.end()
    context.detach(token)
    logger.debug(f"tool_call_end tool={tool_name}")
    return None


def _init_mcp(name: str, mcp_type: str) -> McpToolset:
    """Initialize an MCP toolset."""
    url = f"http://{envoy_service}/{mcp_type}/mcp"
    logger.info(f"Initializing McpToolset {name} at {url}")
    toolset = McpToolset(
        connection_params=StreamableHTTPConnectionParams(url=url),
    )
    logger.info(f"McpToolset {name} initialized successfully.")
    return toolset


# Initialize MCP connections through the Envoy sidecar
local_mcp = _init_mcp("local_mcp", "local")
remote_mcp = _init_mcp("remote_mcp", "remote")

root_agent = LlmAgent(
    model=model,
    name=AGENT_NAME,
    instruction="""You are an AI assistant that interacts with the world primarily
    via the provided MCP tools. When processing a user's prompt, you must use the
    available tools to answer the user's question. If you don't know the answer,
    say you can not find available tools to answer the question.""",
    tools=[local_mcp, remote_mcp],
    before_tool_callback=_before_tool_callback,
    after_tool_callback=_after_tool_callback,
)
