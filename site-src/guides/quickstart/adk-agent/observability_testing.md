# Observability Testing: adk-trace-draft branch

Run all commands from repo root unless noted otherwise.

## Prerequisites

- Kind cluster `kan-quickstart` running with the quickstart deployed:
  ```bash
  site-src/guides/quickstart/run-quickstart.sh --ollama
  ```
- Ollama running on Mac (port 11434)

## Phase 1: Build and patch controller with tracing

```bash
docker build --build-arg GO_VERSION=$(cat .go-version) -t agentic-networking-controller:trace-test .
kind load docker-image agentic-networking-controller:trace-test --name kan-quickstart

kubectl set image deployment/agentic-net-controller -n agentic-net-system \
  manager=agentic-networking-controller:trace-test
kubectl rollout status deployment/agentic-net-controller -n agentic-net-system
```

## Phase 2: Deploy observability stack

```bash
kubectl apply -f site-src/guides/quickstart/adk-agent/otel-collector.yaml
kubectl apply -f site-src/guides/quickstart/adk-agent/tempo.yaml
kubectl apply -f site-src/guides/quickstart/adk-agent/grafana.yaml

kubectl wait --for=condition=available --timeout=120s deployment/otel-collector -n quickstart-ns
kubectl wait --for=condition=available --timeout=120s deployment/tempo -n quickstart-ns
kubectl wait --for=condition=available --timeout=120s deployment/grafana -n quickstart-ns
```

## Phase 3: Regenerate gateway ConfigMap with OTel tracing

The controller generates an Envoy bootstrap ConfigMap with OTel tracing configured.
Since the ConfigMap is only created once, delete it and trigger reconciliation.

```bash
GATEWAY_DEPLOY=$(kubectl get deployment -n quickstart-ns \
  -l "gateway.networking.k8s.io/gateway-name=agentic-net-gateway" \
  -o jsonpath='{.items[0].metadata.name}')

kubectl delete configmap ${GATEWAY_DEPLOY} -n quickstart-ns

kubectl annotate gateway agentic-net-gateway -n quickstart-ns \
  reconcile-trigger="$(date +%s)" --overwrite

sleep 5
kubectl get configmap ${GATEWAY_DEPLOY} -n quickstart-ns \
  -o jsonpath='{.data.envoy\.yaml}' | grep -A8 "tracing"

# Restart gateway pod (bootstrap is static, requires restart)
kubectl rollout restart deployment/${GATEWAY_DEPLOY} -n quickstart-ns
kubectl rollout status deployment/${GATEWAY_DEPLOY} -n quickstart-ns
```

## Phase 4: Build and patch agent

```bash
docker build -t adk-agent:latest site-src/guides/quickstart/adk-agent/
kind load docker-image adk-agent:latest --name kan-quickstart

kubectl set env deployment/adk-agent -n quickstart-ns \
  HF_MODEL- HF_TOKEN- GEMINI_MODEL- GOOGLE_API_KEY- \
  OLLAMA_BASE_URL="http://host.docker.internal:11434" \
  OLLAMA_MODEL="qwen2.5:7b" \
  ADK_ENABLE_OTEL=true

kubectl rollout restart deployment/adk-agent -n quickstart-ns
kubectl rollout status deployment/adk-agent -n quickstart-ns
```

## Span attributes

### Gateway ingress spans (tools/call requests)

| Attribute | Values | Source |
|---|---|---|
| `security_rule.name` | named rule name, or `""` | Envoy shadow RBAC (`shadow_effective_policy_id`) |
| `security_rule.match` | `true` / `false` | Derived in OTel collector |
| `event.action` | `allow` / `deny` | Derived in OTel collector (only for `tools/call`) |
| `event.outcome` | `success` | Derived in OTel collector |
| `peer.spiffe.id` | SPIFFE ID | Envoy RBAC (`principal`) |

### Non-tool-call requests (initialize, tools/list, SSE)

- `security_rule.match` = `false`
- `event.action` is **not set** — these are unconditionally allowed by built-in rules, not authorization failures

### Expected trace structure for a single tool call

| Span | `security_rule.name` | `event.action` | Purpose |
|---|---|---|---|
| ingress | `""` | *(not set)* | MCP session setup (initialize) |
| ingress | `""` | *(not set)* | Tool discovery (tools/list) |
| ingress | `tools-for-adk-agent-sa` | `allow` | Tool invocation (tools/call) |
| ingress | `""` | *(not set)* | MCP protocol overhead |

## Verify

```bash
kubectl get pods -n quickstart-ns

# Agent tool call spans
kubectl logs deployment/adk-agent -n quickstart-ns -c adk-agent --tail=30 | grep "tool_call"

# Gateway OTel config
GATEWAY_DEPLOY=$(kubectl get deployment -n quickstart-ns \
  -l "gateway.networking.k8s.io/gateway-name=agentic-net-gateway" \
  -o jsonpath='{.items[0].metadata.name}')
kubectl get configmap ${GATEWAY_DEPLOY} -n quickstart-ns \
  -o jsonpath='{.data.envoy\.yaml}' | grep -c "otel"

# Access UIs
kubectl port-forward -n quickstart-ns svc/grafana 3000:3000 &
kubectl port-forward -n quickstart-ns service/adk-agent-svc 8081:80 &

# Agent UI: http://localhost:8081/dev-ui/?app=mcp_agent
# Grafana:  http://localhost:3000 (admin/admin)
#   Explore → Tempo → Service: envoy-gateway-quickstart-ns/agentic-net-gateway
#   Tag: security_rule.name=tools-for-adk-agent-sa
#   Tag: event.action=allow
```
