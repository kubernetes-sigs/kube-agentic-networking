# Deploy Steps: adk-trace-draft branch

Run all commands from repo root unless noted otherwise.

## 1. Build controller image

```bash
docker build \
  --build-arg GO_VERSION=$(cat .go-version) \
  -t agentic-networking-controller:shadow-rules \
  .
```

## 2. Load controller image into kind

```bash
kind load docker-image agentic-networking-controller:shadow-rules --name kan-quickstart
```

## 3. Update controller deployment and wait for rollout

Use `rollout restart` rather than `set image` — kind caches images by digest, so `set image`
with the same tag does not trigger a pod restart or pull the new image.

```bash
kubectl rollout restart deployment/agentic-net-controller -n agentic-net-system
kubectl rollout status deployment/agentic-net-controller -n agentic-net-system
```

## 4. Force gateway ConfigMap regeneration

The controller only regenerates the Envoy bootstrap ConfigMap if it doesn't exist.
Delete it, then annotate the Gateway to trigger reconciliation.

```bash
kubectl delete configmap envoy-proxy-3e11a0abd055 -n quickstart-ns

kubectl annotate gateway agentic-net-gateway -n quickstart-ns \
  reconcile-trigger="$(date +%s)" --overwrite

# Verify OTel tracing config is present
kubectl get configmap envoy-proxy-3e11a0abd055 -n quickstart-ns \
  -o jsonpath='{.data.envoy\.yaml}' | grep -A8 "tracing"
```

## 5. Restart the gateway pod

The bootstrap config (OTel tracer) is static — pod must restart to pick it up.

```bash
kubectl rollout restart deployment/envoy-proxy-3e11a0abd055 -n quickstart-ns
kubectl rollout status deployment/envoy-proxy-3e11a0abd055 -n quickstart-ns
```

## 6. Build agent image

```bash
cd site-src/guides/quickstart/adk-agent
docker build -t adk-agent:ej-test .
cd -
```

## 7. Load agent image into kind

```bash
kind load docker-image adk-agent:ej-test --name kan-quickstart
```

## 8. Apply sidecar configs (with envsubst)

IMPORTANT: sidecar-configs.yaml has template variables — always use envsubst.

```bash
GATEWAY_ADDRESS=$(kubectl get gateway agentic-net-gateway -n quickstart-ns \
  -o jsonpath='{.status.addresses[0].value}')

GATEWAY_SA=$(kubectl get sa -n quickstart-ns \
  -l "kube-agentic-networking.sigs.k8s.io/gateway-name=agentic-net-gateway" \
  -o jsonpath='{.items[0].metadata.name}')

GATEWAY_SPIFFE_ID="spiffe://cluster.local/ns/quickstart-ns/sa/${GATEWAY_SA}"

GATEWAY_ADDRESS="${GATEWAY_ADDRESS}" GATEWAY_SPIFFE_ID="${GATEWAY_SPIFFE_ID}" \
  envsubst < site-src/guides/quickstart/adk-agent/sidecar/sidecar-configs.yaml \
  | kubectl apply -f -
```

## 9. Apply agent deployment and restart

```bash
kubectl apply -f site-src/guides/quickstart/adk-agent/deployment.yaml
kubectl rollout restart deployment/adk-agent -n quickstart-ns
kubectl rollout status deployment/adk-agent -n quickstart-ns
```

## 10. Deploy observability stack (OTel collector, Tempo, Grafana)

Run from `site-src/guides/quickstart/adk-agent/`:

```bash
# Deploy Tempo
kubectl apply -f tempo.yaml
kubectl wait --for=condition=available --timeout=120s deployment/tempo -n quickstart-ns

# Deploy Grafana
kubectl apply -f grafana.yaml
kubectl wait --for=condition=available --timeout=120s deployment/grafana -n quickstart-ns

# Apply OTel collector config and restart to pick up changes
kubectl apply -f otel-collector.yaml
kubectl rollout restart deployment/otel-collector -n quickstart-ns
kubectl rollout status deployment/otel-collector -n quickstart-ns
```

## Span attributes

These attributes appear on gateway `ingress` spans for `tools/call` requests. All four are derived
in the OTel collector from `security_rule.name`, which is the only value Envoy emits directly
(via `shadow_effective_policy_id`). `shadow_engine_result` is not used because the catch-all
`__no_match__` shadow rule always emits `"allowed"` in RBAC_ALLOW mode, making it unreliable
for denied requests.

| Attribute | Values | Source | Rationale |
|---|---|---|---|
| `security_rule.name` | named rule or `__no_match__` | Envoy shadow RBAC (`shadow_effective_policy_id`) | The matching shadow rule name. `__no_match__` is a catch-all added last so named rules take priority; fires when no named rule matches. |
| `security_rule.match` | `true` / `false` | Derived in collector | `true` if a named rule matched; `false` if `__no_match__` fired (no rule matched → default deny). |
| `event.action` | `allow` / `deny` | Derived in collector | The enforcement decision. Named rule matched → `allow` (all policy rules are allow-type). `__no_match__` → `deny` (deny by default). |
| `event.outcome` | `success` | Derived in collector | Outcome of the RBAC check itself (not the HTTP response). Always `success` when `security_rule.name` is set, meaning RBAC evaluated and returned a decision. |

## Verify

```bash
# All pods running
kubectl get pods -n quickstart-ns

# Envoy sidecar resolving gateway address (not literal ${GATEWAY_ADDRESS})
kubectl logs -n quickstart-ns deployment/adk-agent -c envoy --tail=10 | grep "DNS resolution"

# Gateway has OTel tracing config
kubectl get configmap envoy-proxy-3e11a0abd055 -n quickstart-ns \
  -o jsonpath='{.data.envoy\.yaml}' | grep -c "otel"

# Access Grafana
kubectl port-forward -n quickstart-ns svc/grafana 3000:3000
# http://localhost:3000  (admin/admin)

# Access Tempo directly
kubectl port-forward -n quickstart-ns svc/tempo 3200:3200
# http://localhost:3200

# Search for traces in Grafana:
#   Explore → Tempo datasource → search by:
#   - Service name: adk-agent or envoy-gateway-quickstart-ns/agentic-net-gateway
#   - Tag: security_rule.name=tools-for-adk-agent-sa
#   - Tag: security_rule.match=true/false
#   - Tag: event.action=allow/deny
```
