# Personas

**AI Engineer**: A hands-on builder focused on the end-to-end development, deployment, and optimization of AI agents. They are distinct from ML Researchers and ML Engineers; AI Engineers are product-first, operating on the other side of the LLM Inference Serving API, and are not responsible for training, tuning, or deploying the models themselves.

**AI Platform Engineer**: A builder and operator of the foundational platform that enables AI engineers to develop and deploy agents at scale. 

**Tool Developer**: A builder focused on developing MCP tools that can be leveraged by agents.

# CUJs

## Agent Identity 

As an AI Engineer, I want to assign a unique, verifiable identity to my agent running in Kubernetes, so that gateways or external systems can securely authenticate it and make authorization decisions.

## Protocol-Aware Authorization

As an AI Platform Engineer, I want to:

* Deny any traffic coming from Agents to MCP servers & other Agents by default

* Allow agents to connect to specific, defined sets of MCP servers (e.g. "toolsets", "virtual service")

* Allow agents to use specific tools

* Allow agents to use specific tools from specific MCP servers

* Control whether access to tools is read, write or both

## Observability

As an AI Engineer I want to:

* Understand why my agent is getting denied when calling a certain tool

As an AI Platform Engineer I want to:

* Have an aggregated way of seeing failures/denials across the platform
