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
import os
import json
from contextlib import AsyncExitStack
import gradio as gr
import logging
from openai import AsyncOpenAI
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


envoy_service = os.environ.get("ENVOY_SERVICE")
if not envoy_service:
    raise ValueError("the ENVOY_SERVICE environment variable is missing.")

DEEPWIKI_URL = f"http://{envoy_service}/remote/mcp"
EVERYTHINGMCP_URL = f"http://{envoy_service}/local/mcp",

HF_TOKEN = os.getenv("HF_TOKEN")
if not HF_TOKEN:
    raise ValueError("the HF_TOKEN environment variable is missing.")

hf_model = os.getenv("HF_MODEL")
if not hf_model:
    raise ValueError("the HF_MODEL environment variable is missing.")

client = AsyncOpenAI(
    base_url="https://router.huggingface.co/v1",
    api_key=HF_TOKEN
)
MODEL_NAME = "deepseek-ai/DeepSeek-R1-0528"

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

# maintain persistent connections and tool mappings globally 
# so they stay alive across multiple UI interactions.
mcp_state = {
    "stack": AsyncExitStack(),
    "tool_to_session_map": {},
    "mcp_tools": [],
    "initialized": False
}

async def initialize_mcp():
    """Connects to MCP servers and loads tools into the global state."""
    if mcp_state["initialized"]:
        return
        
    logger.info("🔌 Connecting to MCP Servers...")
    servers = [
        ("DeepWiki", DEEPWIKI_URL),
        ("EverythingMCP", EVERYTHINGMCP_URL)
    ]

    for name, url in servers:
        try:
            read_stream, write_stream, _ = await mcp_state["stack"].enter_async_context(
                streamable_http_client(url)
            )
            session = await mcp_state["stack"].enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            await session.initialize()
            
            list_result = await session.list_tools()
            for tool in list_result.tools:
                mcp_state["tool_to_session_map"][tool.name] = session
                mcp_state["mcp_tools"].append({
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.inputSchema 
                    }
                })
            logger.info(f"   ✅ Connected to {name}.")
        except Exception as e:
            logger.error(f"   ❌ Failed to connect to {name}: {e}")

    mcp_state["initialized"] = True
    logger.info(f"🤖 Agent Ready with {len(mcp_state['mcp_tools'])} tools.")

async def process_chat(user_text, messages_state):
    """Core agent logic handling LLM calls, tool execution, and state updates."""
    if not mcp_state["initialized"]:
        await initialize_mcp()

    if not messages_state:
        messages_state = [
            {"role": "system", "content": "You are a helpful assistant. You must use the available tools to answer the user's question. If you don't know the answer, say you can not find available tools to answer the question."}
        ]

    messages_state.append({"role": "user", "content": user_text})
    
    try:
        # -- 1. Model Decision --
        response = await client.chat.completions.create(
            model=MODEL_NAME,
            messages=messages_state,
            tools=mcp_state["mcp_tools"] if mcp_state["mcp_tools"] else None,
            tool_choice="auto" if mcp_state["mcp_tools"] else None
        )
        
        response_msg = response.choices[0].message
        messages_state.append(response_msg.model_dump(exclude_none=True)) 

        # -- 2. Tool Execution --
        if response_msg.tool_calls:
            tool_names = [t.function.name for t in response_msg.tool_calls]
            yield f"*(🛠️ Running tools: {', '.join(tool_names)}...)*", messages_state
            
            for tool_call in response_msg.tool_calls:
                fname = tool_call.function.name
                fargs = json.loads(tool_call.function.arguments)
                target_session = mcp_state["tool_to_session_map"].get(fname)
                
                if target_session:
                    try:
                        mcp_result = await target_session.call_tool(fname, arguments=fargs)
                        result_text = mcp_result.content[0].text
                    except Exception as e:
                        result_text = f"Error executing tool {fname}: {str(e)}"
                else:
                    result_text = f"Error: Tool {fname} not found."

                messages_state.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": str(result_text)
                })
            
            # -- 3. Final Response --
            final_response = await client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages_state,
            )
            final_text = final_response.choices[0].message.content
            messages_state.append({"role": "assistant", "content": final_text})
            yield final_text, messages_state
        
        else:
            messages_state.append({"role": "assistant", "content": response_msg.content})
            yield response_msg.content, messages_state

    except Exception as e:
        yield f"❌ Runtime Error: {str(e)}", messages_state

# --- Gradio UI Layout ---
with gr.Blocks() as demo:
    gr.Markdown("# 🤖 MCP Agent Chatbot built by OpenAI SDK")
    
    messages_state = gr.State([])
    chatbot = gr.Chatbot(height=600)
    
    with gr.Row():
        msg = gr.Textbox(label="Message", placeholder="Ask a question...", scale=4)
        submit_btn = gr.Button("Send", scale=1)
        
    clear = gr.ClearButton([msg, chatbot, messages_state], value="Clear Conversation")

    async def user_input(user_message, history):
        if history is None:
            history = []
        return "", history + [
            {"role": "user", "content": user_message}, 
            {"role": "assistant", "content": ""}
        ]

    async def bot_response(history, m_state):
        user_message = history[-2]["content"] if isinstance(history[-2], dict) else history[-2].content
        async for partial_response, updated_state in process_chat(user_message, m_state):
            if isinstance(history[-1], dict):
                history[-1]["content"] = partial_response
            else:
                history[-1].content = partial_response
            yield history, updated_state

    msg.submit(user_input, [msg, chatbot], [msg, chatbot], queue=False).then(
        bot_response, [chatbot, messages_state], [chatbot, messages_state]
    )
    submit_btn.click(user_input, [msg, chatbot], [msg, chatbot], queue=False).then(
        bot_response, [chatbot, messages_state], [chatbot, messages_state]
    )

if __name__ == "__main__":
    demo.queue().launch(theme=gr.themes.Soft())
