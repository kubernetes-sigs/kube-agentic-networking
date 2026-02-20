# Proposals

Design proposals and enhancement documents for Kubernetes Agentic Networking.

## Index

| Proposal | Description |
|----------|-------------|
| [0008-ToolAuthAPI.md](0008-ToolAuthAPI.md) | Tool Authorization API |
| [0017-DynamicAuth.md](0017-DynamicAuth.md) | Dynamic Auth |
| [0059-AccessPolicyTargetRefs.md](0059-AccessPolicyTargetRefs.md) | AccessPolicy TargetRefs |

## Naming

- Use a **4-digit number** (PR number when available) followed by a **kebab-cased title**: `NNNN-short-title.md`.
- Examples: `0008-ToolAuthAPI.md`, `0059-AccessPolicyTargetRefs.md`.
- While developing, you can use a placeholder (e.g. `XXXX-my-proposal.md`) and rename to the PR number when the PR is opened.
- The number gives a chronological order to proposals.

## Adding a new proposal

1. Create a new markdown file under `docs/proposals/` with the naming above.
2. Include: context, goals, design (API changes, behavior), and alternatives considered.
3. Add the new proposal to the **Index** table in this README.
