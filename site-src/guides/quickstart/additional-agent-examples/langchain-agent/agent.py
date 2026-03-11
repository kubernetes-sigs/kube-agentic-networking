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

import litellm
import streamlit as st
import logging
import os
import asyncio
import contextlib
from langchain_litellm import ChatLiteLLM
from langchain.agents import create_agent 
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.tools import load_mcp_tools
from langchain_core.messages import HumanMessage, AIMessage

# Turn on LiteLLM debugging to catch Hugging Face routing errors
litellm.set_verbose = True

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

st.set_page_config(page_title="LangChain Agent", page_icon="🤖")
st.title("🤖 LangChain Agent")

# 1. Environment Variable Check
envoy_service = os.environ.get("ENVOY_SERVICE")
if not envoy_service:
    st.error("Please set the ENVOY_SERVICE environment variable.")
    st.stop()

api_key = os.getenv("HF_TOKEN")
if not api_key:
    st.error("Please set the HF_TOKEN environment variable.")
    st.stop()

hf_model = os.getenv("HF_MODEL")
if not hf_model:
    st.error("Please set the HF_MODEL environment variable.")
    st.stop()

# 2. Chat History
if "messages" not in st.session_state:
     st.session_state.messages = [
        AIMessage(content="Hello! I am your Agent that uses MCP to access tools. How can I help?")
    ]

# 3. Display Chat Messages
for msg in st.session_state.messages:
    if isinstance(msg, HumanMessage):
        with st.chat_message("user"):
            st.write(msg.content)
    elif isinstance(msg, AIMessage):
        with st.chat_message("assistant"):
            st.write(msg.content)

# 4. Define the Async Agent Interaction
async def run_agent_interaction(user_input, chat_history):
    """
    Connects to MCP, creates agent, and processes the new message
    while preserving the context of previous messages.
    """
    mcp_config = {}

    mcp_config["deepwiki"] = {
        "url": f"http://{envoy_service}/remote/mcp",
            "transport": "streamable_http",
    }

    mcp_config["everythingmcp"] = {
        "url": f"http://{envoy_service}/local/mcp",
            "transport": "streamable_http",
    }

    try:
        logger.info(f"Attempting to create MultiServerMCPClient with config: {mcp_config}")
        client = MultiServerMCPClient(mcp_config)
        logger.info("MultiServerMCPClient created successfully.")
    except Exception as e:
        logger.error(f"Failed to create MultiServerMCPClient: {e}")

    # Start MCP Sessions for all configured servers
    async with contextlib.AsyncExitStack() as stack:
        tools = []
        for name in mcp_config.keys():
            session = await stack.enter_async_context(client.session(name))
            tools.extend(await load_mcp_tools(session))
        try:
            logger.info(f"Attempting to create agent with tools: {tools}")
            # Define the LLM using LiteLLM
            llm = ChatLiteLLM(
                model=hf_model,
                api_key=api_key,
                temperature=0.7,
            )
            # Create the Agent
            agent = create_agent(
                model=llm,
                tools=tools,
                system_prompt="You must use the available tools to answer the user's question. If you don't know the answer, say you can not find available tools to answer the question.",
            )
            logger.info("Agent created successfully.")
        except Exception as e:
            logger.error(f"Failed to create agent: {e}")
            return "Sorry, I am having trouble setting up the tools to answer your question right now."
        # Prepare the full message history (Context)
        messages = chat_history + [HumanMessage(content=user_input)]
        try:
            # Invoke Agent
            response = await agent.ainvoke({"messages": messages})
            return response["messages"][-1].content
        except Exception as e:
            logger.error(f"Agent invocation failed: {e}")
            return f"An error occurred while generating a response: {str(e)}"

# 5. Handle User Input
if prompt := st.chat_input("Ask me anything..."):
    # Display user message immediately
    with st.chat_message("user"):
        st.write(prompt)

    # Show a spinner while the agent works
    with st.spinner("Thinking..."):
        # Run the async agent loop
        response_text = asyncio.run(
            run_agent_interaction(prompt, st.session_state.messages)
        )
        # Display AI response
        with st.chat_message("assistant"):
            st.write(response_text)
        # Update Session State History
        st.session_state.messages.append(HumanMessage(content=prompt))
        st.session_state.messages.append(AIMessage(content=response_text))
