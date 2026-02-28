# Repository structure

This document describes where to find and where to add proposals, APIs, documentation, and code in this repo.

## Top-level layout

```
├── api/                 # API type definitions (Go structs)
├── cmd/                 # Application entrypoints (e.g. controller main)
├── docs/                # Design docs, proposals, and repo documentation
├── hack/                # Build, codegen, and CI helpers
├── k8s/                 # Generated clients, CRDs, and deploy manifests
├── pkg/                 # Go packages (controller, translator, infra, etc.)
├── quickstart/          # Quickstart examples (agents, MCP server, policy)
├── site-src/            # MkDocs source for the published docs site
└── tests/               # Tests (CEL, CRD validation, examples)
```

## Proposals

**Location:** [`docs/proposals/`](proposals/)

Design proposals and enhancement docs live here. Each proposal is a markdown file.

- **Naming:** `NNNN-short-title.md` (e.g. `0008-ToolAuthAPI.md`). Use the 4-digit PR number once the PR exists; use a placeholder like `XXXX-my-proposal` during development.
- **Index and practices:** See [docs/proposals/README.md](proposals/README.md).

## APIs

**Type definitions:** [`api/`](../api/) (Go)

- `api/v0alpha0/` — Current API version (e.g. `backend_types.go`, `accesspolicy_types.go`). Run `make generate` after editing.

**CRDs (manifests):** [`k8s/crds/`](../k8s/crds/)

- Installed YAML for XBackend, XAccessPolicy, etc. Generated from `api/`.

**Generated clients:** [`k8s/client/`](../k8s/client/)

- Clientsets, listers, informers for the API types. Regenerated via project Makefile/codegen.

For an overview of the APIs and how they relate, see [docs/api/README.md](api/README.md).

## Documentation

- **Repo docs (design, structure, proposals):** [`docs/`](.) — Markdown in the repo; good for GitHub browsing and linking from the docs site.
- **Published docs site:** [`site-src/`](../site-src/) — MkDocs source; built output goes to `site/`. Add user-facing pages, guides, and links to proposals/APIs here. Config: [`mkdocs.yml`](../mkdocs.yml).

## Code

- **Controller and business logic:** [`pkg/controller/`](../pkg/controller/), [`pkg/translator/`](../pkg/translator/)
- **Infrastructure (xDS, Envoy):** [`pkg/infra/`](../pkg/infra/)
- **Constants and shared config:** [`pkg/constants/`](../pkg/constants/)
- **Entrypoint:** [`cmd/main.go`](../cmd/main.go)

## Quickstart and examples

- **Quickstart:** [`quickstart/`](../quickstart/) — ADK agent, MCP server, and policy examples (e.g. `quickstart/policy/e2e.yaml`).
- **CRD examples (valid/invalid):** [`tests/crd/examples/`](../tests/crd/examples/)

## Summary table

| Content type        | Where it lives              | Notes                          |
|---------------------|-----------------------------|--------------------------------|
| Proposals           | `docs/proposals/`           | `NNNN-title.md`; see proposals README |
| API types (Go)      | `api/v0alpha0/`             | Run `make generate` after edits |
| CRD YAML            | `k8s/crds/`                 | Generated from `api/`          |
| API overview        | `docs/api/README.md`        | High-level API description    |
| Repo structure doc  | `docs/REPO_STRUCTURE.md`    | This file                      |
| Docs site content   | `site-src/`                 | MkDocs                         |
