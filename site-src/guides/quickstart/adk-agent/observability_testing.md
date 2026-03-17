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

```bash
kubectl set image deployment/agentic-net-controller \
  manager=agentic-networking-controller:shadow-rules \
  -n agentic-net-system

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
