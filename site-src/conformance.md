# Conformance

Kube Agentic Networking conformance tests give implementations a shared way to
verify that their APIs behave consistently. Implementers can run the suite while
developing support, then generate a report when every test for a claimed profile
passes.

This process follows the same profile-and-report model as
[Gateway API conformance](https://gateway-api.sigs.k8s.io/concepts/conformance/),
adapted for Kube Agentic Networking features.

The current `Gateway` profile covers the core Gateway, HTTPRoute,
ReferenceGrant, and AccessPolicy behavior. Implementations can also claim the
extended SPIFFE source and external authorization features when they support
them.

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

Core features are enabled by default. Add extended features only when the
implementation supports them, for example:

```bash
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

Successful reports are submitted by pull request under
`conformance/reports/<extension-version>/<profile>/<implementation>/`. Each
implementation folder also includes a README that links the reports and
explains how to reproduce them.

See the
[conformance report guide](https://github.com/kubernetes-sigs/kube-agentic-networking/blob/main/conformance/reports/README.md)
for the required directory layout, metadata, naming rules, and submission
checklist.

The test implementation lives in [`conformance/`](https://github.com/kubernetes-sigs/kube-agentic-networking/tree/main/conformance),
with individual test definitions under
[`conformance/tests/`](https://github.com/kubernetes-sigs/kube-agentic-networking/tree/main/conformance/tests).
