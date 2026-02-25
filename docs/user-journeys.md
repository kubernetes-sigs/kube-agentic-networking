# Personas

**AI Engineer**: A hands-on builder focused on the end-to-end development, deployment, and optimization of AI agents. They are distinct from ML Researchers and ML Engineers; AI Engineers are product-first, operating on the other side of the LLM Inference Serving API, and are not responsible for training, tuning, or deploying the models themselves.

**Platform Engineer**: A builder and operator of the foundational platform (e.g. the provider of ingress/egress Gateways for the cluster).

**AI Platform Engineer**: A builder and operator that leverages the foundational platform and builds layers on top that enable AI engineers to develop and deploy agents at scale. 

**AI Security Engineer**: A specialist focused on designing safeguards to ensure AI agents operate safely and securely.

**Application Developer**: A builder that is primarily focused on traditional APIs / applications but also surfaces functionality to agents using MCP.

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

* Audit agent actions in the context of the user who delegated authority, so that I can attribute outcomes to both human intent and agent behaviour.

As an AI Platform Engineer I want to:

* Have an aggregated way of seeing failures/denials across the platform

## Security

As an AI Security Engineer I want to:

* Develop MCP guardrails for pre-request filtering to prevent attacks such as prompt injection.

* Develop MCP guardrails for post-response filtering to prevent data breaches.
