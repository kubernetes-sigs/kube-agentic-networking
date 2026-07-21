# Conformance

Kube Agentic Networking conformance tests give implementations a shared way to
verify that their APIs behave consistently. Implementers can run the suite while
developing support, then generate a report when every test for a claimed profile
passes.

This process follows the same profile-and-report model as
[Gateway API conformance](https://gateway-api.sigs.k8s.io/docs/concepts/conformance/),
adapted for Kube Agentic Networking features.

## Conformance Profiles

Conformance is defined through **profiles**, each covering a specific area of
the specification. An implementation is considered conformant for a profile when
it passes **all core tests** in that profile. Currently, the specification defines
the `Gateway` profile, which covers core agentic networking behaviors including
`AccessPolicy` enforcement and protocol matching.

### Core vs Extended Features

Within each profile, features are classified as:

- **Core features** — Must pass for an implementation to claim conformance with
  that profile.
- **Extended features** — Optional capabilities. Implementations may choose to
  support them and include the results in their report.

Extended features in the `Gateway` profile currently include:

| Feature | Description |
|---------|-------------|
| `SupportAccessPolicySPIFFESource` | SPIFFE-based identity matching in `AccessPolicy` |
| `SupportAccessPolicyExternalAuth` | External authorization (ExtAuth) integration |

## Prepare an implementation

Before running the suite, make sure that:

- a Kubernetes cluster is reachable through the current kubeconfig context;
- the Kube Agentic Networking CRDs are installed;
- the implementation is running and exposes a ready `GatewayClass`; and
- the local checkout matches the Kube Agentic Networking version being tested.

The suite creates its test resources in the `agentic-conformance-infra`
namespace. It applies Gateways, Routes, policies, and test workloads, then
checks the observed behavior through the selected `GatewayClass`.

## Run the tests

Set the implementation's `GatewayClass` name and run:

```bash
GATEWAY_CLASS=my-gateway-class make conformance
```

The Make target keeps the base resources after the run so that failures can be
inspected. To run a single test during development, call the Go suite directly:

```bash
go test -v ./conformance -run TestConformance -args \
  --gateway-class=my-gateway-class \
  --run-test=XAccessPolicyAccepted \
  --cleanup-base-resources=false
```

### Selecting Features

Core features are enabled by default. Add extended features only when the
implementation supports them, for example:

```bash
go test -v ./conformance -run TestConformance -args \
  --gateway-class=my-gateway-class \
  --supported-features=SupportAccessPolicySPIFFESource,SupportAccessPolicyExternalAuth
```

## Generate a report

Once the selected profile passes, rerun the suite with complete implementation
metadata and a report output path:

```bash
go test -v ./conformance -run TestConformance -args \
  --gateway-class=my-gateway-class \
  --organization=my-organization \
  --project=my-implementation \
  --url=https://example.com/my-implementation \
  --version=v1.2.3 \
  --contact=@maintainer \
  --report-output=./v1.2.3-default-gateway-report.yaml
```

Use a reproducible release, tag, or commit for `--version`; do not use a branch
name. The generated YAML is the evidence for the tested version and must not be
edited before submission.

## Submit the result

Once you have a passing report, refer to the
[Conformance Reports README](https://github.com/kubernetes-sigs/kube-agentic-networking/blob/main/conformance/reports/README.md#submission-process)
for detailed rules on report content, folder structure, versioning, and how to submit your report via Pull Request.

## Further Reading

- [Conformance Reports](https://github.com/kubernetes-sigs/kube-agentic-networking/blob/main/conformance/reports/README.md) — Report format, rules, and submission process
- [Gateway API Conformance](https://gateway-api.sigs.k8s.io/concepts/conformance/) — The upstream model this process is modeled after
- The test implementation lives in [`conformance/`](https://github.com/kubernetes-sigs/kube-agentic-networking/tree/main/conformance),
  with individual test definitions under
  [`conformance/tests/`](https://github.com/kubernetes-sigs/kube-agentic-networking/tree/main/conformance/tests).

