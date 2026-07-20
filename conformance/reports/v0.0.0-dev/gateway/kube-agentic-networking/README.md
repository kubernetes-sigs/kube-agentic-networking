# Kube Agentic Networking Reference Implementation (Gateway Profile Conformance)

This folder contains the conformance report for the Kube Agentic Networking reference implementation.

## Table of Contents

| Extension Version Tested | Profile Tested | Implementation Version | Mode    | Report                                                                     |
|--------------------------|----------------|------------------------|---------|----------------------------------------------------------------------------|
| v0.0.0-dev               | Gateway        | [v0.0.0-dev](https://github.com/kubernetes-sigs/kube-agentic-networking/tree/main) | default | [v0.0.0-dev Gateway report](./v0.0.0-dev-default-gateway-report.yaml) |

## Reproduce

To reproduce these results, follow the instructions in the main [README.md](../../../../../README.md) to set up the environment, and then run:

```bash
make conformance GATEWAY_CLASS=kube-agentic-networking
```
