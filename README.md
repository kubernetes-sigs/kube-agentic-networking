# kube-agentic-networking

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

![Architecture Diagram](./docs/diagram.svg)

## Community, discussion, contribution, and support

Learn how to engage with the Kubernetes community on the [community page](http://kubernetes.io/community/).

You can reach the maintainers of this project at:

- [Slack channel (#sig-network-agentic-networking)](https://kubernetes.slack.com/archives/C09P6KS6EQZ)
- [Mailing List](https://groups.google.com/a/kubernetes.io/g/sig-network)

### Code of conduct

Participation in the Kubernetes community is governed by the [Kubernetes Code of Conduct](code-of-conduct.md).
