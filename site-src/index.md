# Introduction

The continuous evolution of the AI ecosystem has led to the emergence of agent-based development, a paradigm in which autonomous AI agents execute intricate tasks. This transformation is fostering the development of "AI-first" protocols, such as the Model Context Protocol (MCP) and A2A, which diverge significantly from conventional protocols.

Agents in a sense are microservices for AI. They are self-contained, autonomous units of work that can be composed to build complex applications. These agents, and the tools they use to perform their functions, are becoming ubiquitous. They can run anywhere: on-premises, in traditional hyperscaler cloud environments (like Kubernetes or serverless functions), on new cloud platforms (neoclouds), or across the public internet.

This distributed nature, combined with the new communication patterns of "AI-first" protocols, introduces novel security and governance challenges. Unlike traditional REST APIs, these protocols require integration with AI safety and security models in addition to conventional security measures. This is because agents can act autonomously, potentially with significant impact. It is therefore essential for Kubernetes to provide a consistent API for a well-governed, secure, and auditable flow of communication:

- From agents in Kubernetes to agents in the cluster and remote agents anywhere.

- From agents running anywhere to agents in Kubernetes.

- For agents in Kubernetes to access tools anywhere.

## Goals

This subproject aims to deliver the following:

**Core Capabilities**

-   Provide standardized APIs for secure, governed communication between agents, tools, and potentially LLMs across Kubernetes cluster boundaries (ingress, egress, and east-west traffic)

-   Attempt to design APIs around user-facing goals (e.g., "Agent A can communicate with Tool B") rather than protocol-specific constructs, ensuring adaptability as new AI-first protocols emerge alongside MCP and A2A

-   Enable protocol-aware networking capabilities where necessary (e.g., MCP tool-level authorization) while keeping core APIs protocol-agnostic and future-proof

-   Establish agent identity and authentication mechanisms that allow agents to be uniquely identified and verified across network boundaries


**Security & Governance**

-   Define authorization policies that control which agents can communicate with other agents, tools, and LLMs at a granular level (e.g., specific MCP tool functions)

-   Integrate AI safety and security extension points to support external authentication, authorization, and policy enforcement decisions

-   Provide auditable traffic management capabilities (rate limiting, access controls) suitable for autonomous agent workloads


**Ecosystem Integration**

-   Maintain alignment and collaboration with Gateway API, Gateway Inference Extension, WG AI Gateway, and WG AI Integration

-   Design APIs extensible enough for diverse implementations (service meshes, gateways, future architectures)

![Architecture Diagram](/docs/docs/diagram.svg)

## API Resources

Check back soon for the initial API proposal!

## Who is working on this project?

TODO
