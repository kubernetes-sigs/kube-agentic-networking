# Repo Process and Guidelines

This document outlines the development process, release policy, and key timelines for the Agentic Networking repository. Our goal is to foster rapid iteration through prototyping while working toward a broadly implementable, stable API.

These guidelines truly embrace the prototyping phase and iteration by defining some guardrails and intentions to ensure we communicate clearly that this is not production ready and establish a safe place for iteration.

## Core Intent

The primary purpose of this repository is to serve as a space for defining and iterating on Agentic Networking concepts/APIs/capabilities within Kubernetes.

* We explicitly welcome and intend to host **multiple iterations of prototypes** that explore different architectural approaches or integration points for Agentic Networking. This allows for evaluation and robust comparison before API finalization.  
* Contributions should initially focus on refining the core API and concepts, not a final, production-ready state.

## Release and API Stability Policy

To ensure the community is engaging with stable and meaningful artifacts, we are adopting a conservative release strategy:

* **No Releases Until API Readiness:** The repository will **not** publish any official releases, alpha, or beta tags until the maintainers and implementation representatives determine that the core API is ready for broad implementation.  
* **Commitment to Implementation:** The API is considered "release-ready" once it has a prototype implementation that clearly demonstrates the proposed functionality.


## Key Timeline and Milestones

Our timeline prioritizes rapid prototyping to inform a stable API definition.

| Activity | Target Timeline | Milestone Goal |
| :---- | :---- | :---- |
| **Initial Prototyping Phase** | Next 2-3 Months | Explore core concepts and technical feasibility across multiple approaches. |
| **Alpha API** | Targeting February 2026 | Define a stable alpha, implementable API that can be consumed by implementations. |
| **Initial Implementations** | Targeting KubeCon EU 2026 (end of March) | Aim to have one or more full reference implementations demonstrating the finalized API at KubeCon EU. |

*This timeline is aggressive but reflects the critical need for Kubernetes to provide timely solutions in this space.* 
