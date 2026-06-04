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

import httpx
from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams
from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.propagate import inject

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

# Shared slot for the current tool execution's OTel context. The MCP SDK runs HTTP
# requests in a background anyio task that doesn't inherit ContextVars, so we bridge
# the context manually: _before_tool_callback writes here, the httpx hook reads it.
_active_otel_ctx: list = [None]


def _create_traced_httpx_client(
    headers: dict | None = None,
    timeout: httpx.Timeout | None = None,
    auth: httpx.Auth | None = None,
) -> httpx.AsyncClient:
    """httpx factory that injects traceparent from the active tool execution context."""
    async def _inject_trace(request: httpx.Request):
        if _active_otel_ctx[0]:
            carrier: dict[str, str] = {}
            inject(carrier, context=_active_otel_ctx[0])
            request.headers.update(carrier)

    kwargs: dict = {"follow_redirects": True, "event_hooks": {"request": [_inject_trace]}}
    kwargs["timeout"] = timeout if timeout is not None else httpx.Timeout(30.0, read=300.0)
    if headers is not None:
        kwargs["headers"] = headers
    if auth is not None:
        kwargs["auth"] = auth
    return httpx.AsyncClient(**kwargs)


def _before_tool_callback(tool, args, tool_context):
    """Enrich the execute_tool span and capture OTel context for HTTP propagation."""
    span = trace.get_current_span()
    tool_name = getattr(tool, "name", str(tool))
    span.set_attribute("gen_ai.tool.name", tool_name)
    span.set_attribute("gen_ai.operation.name", "execute_tool")
    span.set_attribute("gen_ai.agent.name", AGENT_NAME)
    span.update_name(f"gen_ai.tool.call {tool_name}")
    _active_otel_ctx[0] = otel_context.get_current()
    logger.info(
        f"tool_call_start tool={tool_name} "
        f"trace_id={span.get_span_context().trace_id:032x}"
    )


def _after_tool_callback(tool, args, tool_context, tool_response):
    """Record tool call outcome on the current span."""
    span = trace.get_current_span()
    tool_name = getattr(tool, "name", str(tool))
    if isinstance(tool_response, dict) and tool_response.get("error"):
        span.set_status(trace.Status(trace.StatusCode.ERROR, str(tool_response["error"])))
        span.set_attribute("error.type", "ToolExecutionError")
    else:
        span.set_status(trace.Status(trace.StatusCode.OK))
    logger.info(f"tool_call_end tool={tool_name}")


def _init_mcp(name: str, mcp_type: str) -> McpToolset:
    """Initialize an MCP toolset."""
    url = f"http://{envoy_service}/{mcp_type}/mcp"
    logger.info(f"Initializing McpToolset {name} at {url}")
    toolset = McpToolset(
        connection_params=StreamableHTTPConnectionParams(
            url=url,
            httpx_client_factory=_create_traced_httpx_client,
        ),
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
