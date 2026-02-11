Date: 9th February 2026<br/>
Authors: gkhom<br/>
Status: draft<br/>

# TelemetryPolicy
A Kubernetes API for Gateway/Mesh Observability

## Summary
This proposal introduces the `TelemetryPolicy`, a direct policy attachment designed to configure observability signals (metrics, logs, traces) 
for Gateway API resources (via `Gateway` attachment) and Service Mesh resources (via `namespace` attachment).

This K8s API standardizes how users enable and configure telemetry across different data plane implementations, replacing vendor-specific CRDs 
with a unified, portable spec.

# Context
## The Fragmentation of Observability
In the current Kubernetes landscape, the “Who, What, Where, and How Long” of network traffic is answered differently depending on the underlying 
proxy technology. While the Gateway API specification has unified how traffic is routed via `HTTPRoute` and `Gateway`, it has deferred the standardization 
of how that traffic is observed.
This deferral has led to "Observability Lock-in". Platform Engineering teams are forced to learn and manage distinct APIs for each environment. 
A standardized `TelemetryPolicy` is necessary to decouple the intent of observability from the implementation. Without such standardization it is 
difficult for platform owners to: 

1. Enforce consistent auditing standards across different infrastructure providers.
2. Support emerging workloads like AI Agents, which require specialized metrics (e.g., token usage, model latency) and detailed audit logs for tool-use verification.
3. Manage “Mesh” and “Gateway” observability with a single unified API.

## The Emergence of Agentic Networking

The most pressing driver for this proposal is the shift in traffic patterns introduced by agentic workloads. We are moving from a deterministic Service-to-Service 
paradigm to a non-deterministic Agent-to-Tool and Agent-to-Agent paradigm.

In an Agentic Mesh:
* **Entities are Autonomous**: An AI Agent (Pod) decides entirely on its own to call a Tool (Service).
* **Cost is Volatile**: Usage is measured in tokens, not just requests. A single HTTP 200 OK could cost $0.01 or $10.00 depending on the prompt and model used.
* **Context is King**: Debugging requires knowing the semantic context: Which Model? Which Prompt? Which tool?

Existing telemetry policies are unaware of the emerging Generative AI semantic conventions. They see an opaque TCP stream or HTTP POST. Without a standardized API to 
configure the extraction and export of these attributes, the “Agentic Mesh” will remain a black box, increasing governance and cost control challenges.

## Design Objectives

To address these challenges, the `TelemetryPolicy` proposal targets four core objectives:

1. **Standardization**: A single API for Gateway and Mesh to configure Access Logging, Metrics generation, and Tracing propagation.
2. **GEP-713 Compliance**: Support `targetRef` attachment to `Gateway` and `Namespace`. The latter covers Mesh use-cases.
3. **Agentic Support**: Enable the capture of OpenTelemetry GenAI Semantic Conventions and support the requirements of PR #33.
4. **Protocol Agnostic**: Support OpenTelemetry as the primary data model while allowing vendor-specific extensions.

