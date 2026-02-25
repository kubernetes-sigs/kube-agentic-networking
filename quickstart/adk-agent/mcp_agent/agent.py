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

# Import OpenTelemetry for custom tracing
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

# Import GenAI semantic conventions helper
from .genai_spans import GenAISpanHelper, GenAISpanAttributes

# Add these lines to configure logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Environment variables
envoy_service = os.environ.get("ENVOY_SERVICE")
hf_model = os.environ.get("HF_MODEL")
ollama_base_url = os.environ.get("OLLAMA_BASE_URL")
ollama_model = os.environ.get("OLLAMA_MODEL", "llama3.2")

# Agent configuration
AGENT_NAME = "multi_mcp_agent"
AGENT_SYSTEM = "huggingface"

# Automatically determine which model to use based on available credentials
if hf_model:
    # Use Hugging Face model
    logger.info(f"Using Hugging Face model: {hf_model}")
    model = LiteLlm(
        model=hf_model,
    )
else:
    AGENT_SYSTEM = "ollama"
    # Use Ollama (either custom URL or default local)
    base_url = ollama_base_url or "http://localhost:11434"

    # Set dummy OPENAI_API_KEY if not available (required for openai/ usage in LiteLLM)
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

# Get tracer for custom spans
tracer = trace.get_tracer(__name__)

# Initialize trace context propagator
propagator = TraceContextTextMapPropagator()

# Initialize GenAI span helper
genai_helper = GenAISpanHelper(tracer)


def get_trace_headers():
    """
    Get headers with trace context (traceparent) for propagating traces to downstream services.

    Returns:
        dict: Headers containing traceparent and tracestate if a span is active
    """
    headers = {}
    # Inject current trace context into headers
    propagator.inject(headers)
    return headers

# Initialize MCP toolsets with unified trace hierarchy
# Create a parent agent initialization span that encompasses all MCP setup
with genai_helper.create_agent_chat_span(
    agent_name=AGENT_NAME,
    system=AGENT_SYSTEM,
    model=model
) as parent_span:
    parent_span.set_attribute("operation.type", "agent_initialization")
    logger.info("Starting agent initialization with unified trace context")

    try:
        # Initialize local MCP with tracing using GenAI semantic conventions
        # Use gen_ai.tool.call span for MCP initialization as it represents setting up tool access
        with genai_helper.create_tool_call_span("local_mcp_init") as span:
            try:
                span.set_attribute("mcp.type", "local")
                span.set_attribute("mcp.url", f"http://{envoy_service}/local/mcp")

                # Get trace context headers to propagate to MCP
                trace_headers = get_trace_headers()
                logger.debug(f"Trace headers for local MCP: {trace_headers}")

                local_mcp = McpToolset(
                    connection_params=StreamableHTTPConnectionParams(
                        url=f"http://{envoy_service}/local/mcp",
                        headers=trace_headers,
                    ),
                )
                logger.info("McpToolset local_mcp initialized successfully.")
                genai_helper.set_success_status(span)
            except Exception as e:
                logger.error(f"Error initializing McpToolset local_mcp: {e}")
                genai_helper.set_error_status(span, e, error_type="MCPInitializationError")
                raise

        # Initialize remote MCP with tracing using GenAI semantic conventions
        with genai_helper.create_tool_call_span("remote_mcp_init") as span:
            try:
                span.set_attribute("mcp.type", "remote")
                span.set_attribute("mcp.url", f"http://{envoy_service}/remote/mcp")

                # Get trace context headers to propagate to MCP
                trace_headers = get_trace_headers()
                logger.debug(f"Trace headers for remote MCP: {trace_headers}")

                remote_mcp = McpToolset(
                    connection_params=StreamableHTTPConnectionParams(
                        url=f"http://{envoy_service}/remote/mcp",
                        headers=trace_headers,
                    ),
                )
                logger.info("McpToolset remote_mcp initialized successfully.")
                genai_helper.set_success_status(span)
            except Exception as e:
                logger.error(f"Error initializing McpToolset remote_mcp: {e}")
                genai_helper.set_error_status(span, e, error_type="MCPInitializationError")
                raise

        # Mark parent span as successful
        genai_helper.set_success_status(parent_span)
        logger.info("Agent initialization completed successfully with unified trace")

    except Exception as e:
        logger.error(f"Agent initialization failed: {e}")
        genai_helper.set_error_status(parent_span, e, error_type="AgentInitializationError")
        raise

root_agent = LlmAgent(
    model=model,
    name=AGENT_NAME,
    instruction="""You are an AI assistant that interacts with the world primarily
    via the provided MCP tools. When processing a user's prompt, first check both MCPs
    for available tools before processing it internally.""",
    tools=[local_mcp, remote_mcp],
)
