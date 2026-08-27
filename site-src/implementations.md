# Implementations

This page lists implementations of the Kube Agentic Networking APIs and their
conformance status. It follows the same model as the
[Gateway API implementations page](https://gateway-api.sigs.k8s.io/implementations/).

An implementation is listed as **conformant** when it has submitted a passing
[conformance report](conformance.md) for at least one profile. Reports are the
source of truth: each entry below links to the implementation's submitted
reports in the repository.

!!! note
    The APIs are still experimental (`XAccessPolicy` is `v1alpha1`, `XBackend`
    is `v0alpha0`) and may change between releases. Conformance claims are made
    against a specific extension version.

## Conformant Implementations

| Implementation | Organization | Profile | Extended Features | Reports |
|----------------|--------------|---------|-------------------|---------|
| [Kube Agentic Networking reference implementation](https://github.com/kubernetes-sigs/kube-agentic-networking) | Kubernetes SIG Network | Gateway | SPIFFE source matching, External auth | [Reports](https://github.com/kubernetes-sigs/kube-agentic-networking/tree/main/conformance/reports/v0.0.0-dev/gateway/kube-agentic-networking) |

### Kube Agentic Networking reference implementation

The reference implementation is an Envoy-based Gateway API controller
maintained in this repository. It implements the full `Gateway` conformance
profile, including MCP tool-level authorization, CEL-based rules, SPIFFE/mTLS
agent identity, external authorization, and authorization tracing.

## Adding your implementation

If you implement the Kube Agentic Networking APIs, we would love to list you
here. To be added:

1. Run the [conformance suite](conformance.md) against your implementation.
2. Generate and submit a conformance report by following the
   [submission process](https://github.com/kubernetes-sigs/kube-agentic-networking/blob/main/conformance/reports/README.md#submission-process).
3. In the same or a follow-up Pull Request, add your implementation to the
   table on this page with a short description.

If your implementation is still working toward conformance, reach out in the
[#sig-network-agentic-networking](https://kubernetes.slack.com/archives/C09P6KS6EQZ)
Slack channel — we can help you get there.
