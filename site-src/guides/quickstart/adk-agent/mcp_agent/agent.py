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

# Add these lines to configure logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Environment variables
envoy_service = os.environ.get("ENVOY_SERVICE")
hf_model = os.environ.get("HF_MODEL")
ollama_base_url = os.environ.get("OLLAMA_BASE_URL")
ollama_model = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")

# Automatically determine which model to use based on available credentials
if hf_model:
    # Use Hugging Face model
    logger.info(f"Using Hugging Face model: {hf_model}")
    model = LiteLlm(
        model=hf_model,
    )
else:
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

try:
    local_mcp = McpToolset(
        connection_params=StreamableHTTPConnectionParams(
            url=f"http://{envoy_service}/local/mcp",
        ),
    )
    logger.info("McpToolset local_mcp initialized successfully.")
except Exception as e:
    logger.error(f"Error initializing McpToolset local_mcp: {e}")

try:
    remote_mcp = McpToolset(
        connection_params=StreamableHTTPConnectionParams(
            url=f"http://{envoy_service}/remote/mcp",
        ),
    )
    logger.info("McpToolset remote_mcp initialized successfully.")
except Exception as e:
    logger.error(f"Error initializing McpToolset remote_mcp: {e}")

root_agent = LlmAgent(
    model=model,
    name="multi_mcp_agent",
    instruction="""You are an AI assistant that interacts with the world primarily
    via the provided MCP tools. When processing a user's prompt, you must use the
    available tools to answer the user's question. If you don't know the answer,
    say you can not find available tools to answer the question.""",
    tools=[local_mcp, remote_mcp],
)
