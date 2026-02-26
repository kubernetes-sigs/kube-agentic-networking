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

<img src="images/diagram.svg" alt="Architecture Diagram" class="center" />

## API Resources

### Tool Authorization API in Agentic Networking

This defines authorization policies for tool access from AI agents running inside a Kubernetes cluster to MCP servers running in the Kubernetes cluster or outside of the Kubernetes cluster.

- [API Proposal](https://github.com/kubernetes-sigs/kube-agentic-networking/blob/a52a78a1665d3f036cdb3208fafbac7a85cddcf1/docs/proposals/0008-ToolAuthAPI.md)

The API introduces 2 new CRDs:

- [XBackend](https://github.com/kubernetes-sigs/kube-agentic-networking/blob/a52a78a1665d3f036cdb3208fafbac7a85cddcf1/api/v0alpha0/backend_types.go): describes a backend in agentic networking
- [XAccessPolicy](https://github.com/kubernetes-sigs/kube-agentic-networking/blob/a52a78a1665d3f036cdb3208fafbac7a85cddcf1/api/v0alpha0/accesspolicy_types.go): describes who can access what (the permissions/grants) in relation to the agentic networking backends

## Who is working on this project?

This project is part of [SIG Network](https://github.com/kubernetes/community/tree/master/sig-network).

### Maintainers

| Name | GitHub |
|------|--------|
| Lior Lieberman | [@LiorLieberman](https://github.com/LiorLieberman) |
| David Martin | [@david-martin](https://github.com/david-martin) |

### Emeritus Maintainers

| Name | GitHub |
|------|--------|
| Guilherme Cassolato | [@guicassolato](https://github.com/guicassolato) |

### Contributors

| Name | GitHub |
|------|--------|
| Haiyan Meng | [@haiyanmeng](https://github.com/haiyanmeng) |
| Chuang Wang | [@chuangw6](https://github.com/chuangw6) |
| Evaline Ju | [@evaline-ju](https://github.com/evaline-ju) |
| Rohit Ramkumar | [@rramkumar1](https://github.com/rramkumar1) |
| Taahir Ahmed | [@ahmedtd](https://github.com/ahmedtd) |
| Priyanka Saggu | [@Priyankasaggu11929](https://github.com/Priyankasaggu11929) |
| Ziyue Yan | [@ziyue-101](https://github.com/ziyue-101) |
| Ian Rudie | [@ilrudie](https://github.com/ilrudie) |
| Harshitha | [@HarshithaMS005](https://github.com/HarshithaMS005) |
| Gloire Rubambiza | [@rubambiza](https://github.com/rubambiza) |
