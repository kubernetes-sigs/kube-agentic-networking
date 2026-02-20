# Contributing

We welcome contributions from the community. This page explains how to get started and where to find help.

## Getting started

Before contributing, please read the project's [Contributing Guidelines](https://github.com/kubernetes-sigs/kube-agentic-networking/blob/main/CONTRIBUTING.md) in the repository. In particular:

- **[Contributor License Agreement (CLA)](https://git.k8s.io/community/CLA.md)** — You must sign the Kubernetes CLA before we can accept your pull requests.
- **[Kubernetes Contributor Guide](https://k8s.dev/guide)** — Main contributor documentation; you can jump to the [contributing page](https://k8s.dev/docs/guide/contributing/).
- **[Contributor Cheat Sheet](https://k8s.dev/cheatsheet)** — Common resources for existing developers.

The Kubernetes community abides by the CNCF [Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md).

## Development workflow

From the repository root:

- **Build:** `go build ./...`
- **Format:** `make fmt`
- **Lint / vet:** `make vet`
- **Tests:** `make test` (runs unit tests, CEL tests, and CRD tests)
- **Verify (static analysis):** `make verify`

After making changes, open a pull request on GitHub. Ensure CI passes and address any review feedback.

## Mentorship

- [Mentoring Initiatives](https://k8s.dev/community/mentoring) — Kubernetes offers mentorship programs and is always looking for volunteers.

## Bug reports

Bug reports should be filed as [GitHub Issues](https://github.com/kubernetes-sigs/kube-agentic-networking/issues/new) on this repo.

## Communications

- [Slack channel (#sig-network-agentic-networking)](https://kubernetes.slack.com/archives/C09P6KS6EQZ)
- [Mailing List](https://groups.google.com/a/kubernetes.io/g/sig-network)

## Meetings

Our community meetings are held weekly on **Thursday at 4PM UTC** ([convert to your timezone](http://www.thetimezoneconverter.com/?t=4PM&tz=UTC)).

- [Meeting Notes](https://docs.google.com/document/d/1EQET_VWe_IAINyQhVj-wduZg99gBaObpz9612eZ1iYg/edit?tab=t.0#heading=h.q1zi45aa3n69)
- [Zoom (client) Meeting Link](https://zoom.us/j/92037420986)
- [Zoom (web) Meeting Link](https://zoom.us/j/94686253452/join)

Meeting agendas and notes are maintained in the [meeting notes](https://docs.google.com/document/d/1EQET_VWe_IAINyQhVj-wduZg99gBaObpz9612eZ1iYg/edit?tab=t.0#heading=h.q1zi45aa3n69) doc. Feel free to add topics for discussion at an upcoming meeting.
