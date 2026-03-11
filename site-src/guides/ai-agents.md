# AI Agents Overview

The [Agentic Networking Quickstart](quickstart/README.md) demonstrates the power of declarative authorization policies using the Multi-Server MCP Client. To help users get started, the project provides three different AI agents, demonstrating various ways to build and integrate these capabilities.

## ADK Agent

The **ADK Agent** is a custom-built, lightweight agent demonstrating a direct integration with the Multi-Server MCP Client. It does not rely on any third-party agent framework, instead implementing its own core logic to interact with language models and execute tools exposed by various MCP servers.

- [View ADK Agent Directory](https://github.com/kubernetes-sigs/kube-agentic-networking/tree/main/site-src/guides/quickstart/adk-agent/)

## LangChain Agent

The **LangChain Agent** demonstrates how to integrate with the Multi-Server MCP Client using the popular Langchain framework. The agent is built using `langchain`, `litellm`, and `streamlit` to provide a user-friendly chat interface. The LiteLLM integration gives you the flexibility to easily connect to a variety of language models, including Hugging Face models.

- [View LangChain Agent Directory](https://github.com/kubernetes-sigs/kube-agentic-networking/tree/main/site-src/guides/quickstart/additional-agent-examples/langchain-agent/)

## OpenAI Agent

The **OpenAI Agent** demonstrates how to build an agent using the official OpenAI SDK. It uses the SDK to communicate with a language model and dynamically loads tools from connected MCP servers. Built using Gradio to provide an intuitive web chat interface, it connects to any OpenAI-compatible endpoint—meaning you can use it with OpenAI's models or open-source models hosted on platforms like Hugging Face.

- [View OpenAI Agent Directory](https://github.com/kubernetes-sigs/kube-agentic-networking/tree/main/site-src/guides/quickstart/additional-agent-examples/openai-agent/)
