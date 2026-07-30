# Observability Example

**This is an example observability stack for development and demo use only. It is not production-grade.**

Deploys an OTel Collector, Tempo, and Grafana for visualizing distributed traces from the [kube-agentic-networking quickstart](https://github.com/kubernetes-sigs/kube-agentic-networking/tree/main/site-src/guides/quickstart).

## Install

```bash
helm install observability-example charts/observability-example \
  --namespace quickstart-ns --create-namespace
```

## Access

```bash
# Grafana UI (admin/admin)
kubectl port-forward -n quickstart-ns svc/grafana 3000:3000

# Tempo API
kubectl port-forward -n quickstart-ns svc/tempo 3200:3200
```

In Grafana, go to **Explore → Tempo** and search by service name (`adk-agent` or `envoy-gateway-*`) or trace ID.

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `collector.enabled` | Deploy OTel Collector | `true` |
| `collector.tempoEndpoint` | Tempo gRPC endpoint | `tempo.<namespace>.svc.cluster.local:4317` |
| `tempo.enabled` | Deploy Tempo | `true` |
| `tempo.retention` | Trace retention period | `1h` |
| `grafana.enabled` | Deploy Grafana | `true` |

## Bring Your Own Backend

To use an external trace backend, disable Tempo and point the collector at your endpoint:

```bash
helm install observability-example charts/observability-example \
  --set tempo.enabled=false \
  --set collector.tempoEndpoint=your-tempo.example.com:4317
```
