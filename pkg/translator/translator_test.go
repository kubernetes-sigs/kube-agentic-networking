/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package translator

import (
	"context"
	"fmt"
	"strings"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"
	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticclient "sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned/fake"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

type expectedResult struct {
	listenerNames     []string
	routeNames        []string
	clusterNames      []string
	gwPrincipals      []string
	backendPrincipals []string
}

func TestTranslateGatewayToXDS_Full(t *testing.T) {
	ns := "quickstart-ns"
	trustDomain := "cluster.local"

	tests := []struct {
		name     string
		gw       *gatewayv1.Gateway
		backend  *agenticv0alpha0.XBackend
		route    *gatewayv1.HTTPRoute
		policies []*agenticv0alpha0.XAccessPolicy
		mcpSvc   *corev1.Service
		expected expectedResult
	}{
		{
			name:    "Basic mTLS and RBAC Translation",
			gw:      newTestGateway("agentic-net-gateway", ns),
			backend: newTestBackend("local-mcp-backend", ns),
			route:   newTestHTTPRoute("httproute-local-mcp", ns, "agentic-net-gateway", "local-mcp-backend"),
			policies: []*agenticv0alpha0.XAccessPolicy{
				newTestAccessPolicy("auth-policy-local-mcp", ns, "local-mcp-backend", "XBackend", "spiffe://cluster.local/ns/quickstart-ns/sa/adk-agent-sa"),
			},
			mcpSvc: newTestService("local-mcp-backend-svc", ns, 3001),
			expected: expectedResult{
				listenerNames:     []string{"listener-10001"},
				routeNames:        []string{"route-10001"},
				clusterNames:      []string{"quickstart-ns-local-mcp-backend"},
				backendPrincipals: []string{"spiffe://cluster.local/ns/quickstart-ns/sa/adk-agent-sa"},
			},
		},
		{
			name:    "Multiple Policies Targeting Gateway and Backend",
			gw:      newTestGateway("multi-policy-gw", ns),
			backend: newTestBackend("multi-policy-backend", ns),
			route:   newTestHTTPRoute("multi-policy-route", ns, "multi-policy-gw", "multi-policy-backend"),
			policies: []*agenticv0alpha0.XAccessPolicy{
				newTestAccessPolicy("gw-policy", ns, "multi-policy-gw", "Gateway", "spiffe://cluster.local/ns/ns1/sa/sa1"),
				newTestAccessPolicy("backend-policy", ns, "multi-policy-backend", "XBackend", "spiffe://cluster.local/ns/ns2/sa/sa2"),
			},
			mcpSvc: newTestService("multi-policy-backend-svc", ns, 3001),
			expected: expectedResult{
				listenerNames:     []string{"listener-10001"},
				routeNames:        []string{"route-10001"},
				clusterNames:      []string{"quickstart-ns-multi-policy-backend"},
				gwPrincipals:      []string{"spiffe://cluster.local/ns/ns1/sa/sa1"},
				backendPrincipals: []string{"spiffe://cluster.local/ns/ns2/sa/sa2"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup Fake Clients and Informers
			ctx := context.Background()
			k8sClient := fake.NewClientset(tc.mcpSvc)
			gwClient := gatewayclient.NewClientset(tc.gw, tc.route)

			var agenticObjs []runtime.Object
			agenticObjs = append(agenticObjs, tc.backend)
			for _, p := range tc.policies {
				agenticObjs = append(agenticObjs, p)
			}
			agenticClient := agenticclient.NewSimpleClientset(agenticObjs...)

			gwInformerFactory := gatewayinformers.NewSharedInformerFactory(gwClient, 0)
			agenticInformerFactory := agenticinformers.NewSharedInformerFactory(agenticClient, 0)
			coreInformerFactory := informers.NewSharedInformerFactory(k8sClient, 0)

			tr := New(
				trustDomain,
				k8sClient,
				gwClient,
				coreInformerFactory.Core().V1().Namespaces().Lister(),
				coreInformerFactory.Core().V1().Services().Lister(),
				coreInformerFactory.Core().V1().Secrets().Lister(),
				gwInformerFactory.Gateway().V1().Gateways().Lister(),
				gwInformerFactory.Gateway().V1().HTTPRoutes().Lister(),
				nil, // referenceGrantLister
				agenticInformerFactory.Agentic().V0alpha0().XAccessPolicies().Lister(),
				agenticInformerFactory.Agentic().V0alpha0().XBackends().Lister(),
			)

			// Populate Informer caches
			_ = coreInformerFactory.Core().V1().Services().Informer().GetIndexer().Add(tc.mcpSvc)
			_ = gwInformerFactory.Gateway().V1().Gateways().Informer().GetIndexer().Add(tc.gw)
			_ = gwInformerFactory.Gateway().V1().HTTPRoutes().Informer().GetIndexer().Add(tc.route)
			_ = agenticInformerFactory.Agentic().V0alpha0().XBackends().Informer().GetIndexer().Add(tc.backend)
			for _, p := range tc.policies {
				_ = agenticInformerFactory.Agentic().V0alpha0().XAccessPolicies().Informer().GetIndexer().Add(p)
			}

			// Run Translation
			resources, err := tr.TranslateGatewayToXDS(ctx, tc.gw)
			if err != nil {
				t.Fatalf("Translation failed: %v", err)
			}

			// Assertions
			// Verify ListenerType
			listeners := resources[resourcev3.ListenerType]
			if len(listeners) != len(tc.expected.listenerNames) {
				t.Errorf("expected %d listeners, got %d", len(tc.expected.listenerNames), len(listeners))
			}
			for _, expectedName := range tc.expected.listenerNames {
				found := false
				for _, res := range listeners {
					lis := res.(*listenerv3.Listener)
					if lis.Name == expectedName {
						found = true
						checkListenerMTLS(t, lis)
						checkListenerRBAC(t, lis, tc.expected.gwPrincipals, tc.expected.backendPrincipals)
					}
				}
				if !found {
					t.Errorf("expected listener %s not found", expectedName)
				}
			}

			// Verify RouteType
			routes := resources[resourcev3.RouteType]
			if len(routes) != len(tc.expected.routeNames) {
				t.Errorf("expected %d route configurations, got %d", len(tc.expected.routeNames), len(routes))
			}
			for _, expectedName := range tc.expected.routeNames {
				found := false
				for _, res := range routes {
					rc := res.(*routev3.RouteConfiguration)
					if rc.Name == expectedName {
						found = true
						checkRouteRBAC(t, rc, tc.expected.backendPrincipals)
					}
				}
				if !found {
					t.Errorf("expected route configuration %s not found", expectedName)
				}
			}

			// Verify ClusterType
			clusters := resources[resourcev3.ClusterType]
			if len(clusters) != len(tc.expected.clusterNames) {
				t.Errorf("expected %d clusters, got %d", len(tc.expected.clusterNames), len(clusters))
			}
			for _, expectedName := range tc.expected.clusterNames {
				found := false
				for _, res := range clusters {
					cl := res.(*clusterv3.Cluster)
					if cl.Name == expectedName {
						found = true
					}
				}
				if !found {
					t.Errorf("expected cluster %s not found", expectedName)
				}
			}
		})
	}
}

func checkListenerMTLS(t *testing.T, lis *listenerv3.Listener) {
	foundTLS := false
	for _, fc := range lis.FilterChains {
		if fc.TransportSocket != nil && fc.TransportSocket.Name == "envoy.transport_sockets.tls" {
			foundTLS = true
			tlsContext := &tlsv3.DownstreamTlsContext{}
			if err := fc.TransportSocket.GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
				t.Fatalf("failed to unmarshal TLS context: %v", err)
			}
			if !tlsContext.RequireClientCertificate.GetValue() {
				t.Error("RequireClientCertificate should be true for mTLS")
			}

			// Verify SDS config names
			common := tlsContext.CommonTlsContext
			if common.TlsCertificateSdsSecretConfigs[0].Name != constants.SpiffeIdentitySdsConfigName {
				t.Errorf("Identity SDS config name mismatch: got %s, want %s", common.TlsCertificateSdsSecretConfigs[0].Name, constants.SpiffeIdentitySdsConfigName)
			}
			if common.GetValidationContextSdsSecretConfig().Name != constants.SpiffeTrustSdsConfigName {
				t.Errorf("Trust SDS config name mismatch: got %s, want %s", common.GetValidationContextSdsSecretConfig().Name, constants.SpiffeTrustSdsConfigName)
			}
		}
	}
	if !foundTLS {
		t.Errorf("mTLS transport socket configuration not found in listener %s", lis.Name)
	}
}

// checkRouteRBAC verifies the RBAC configuration at the route level.
// It checks that:
// 1. All clusters in weighted clusters have exactly the expected number of backend-level RBAC filters.
// 2. Each backend-level RBAC filter follows the correct naming convention (e.g., backend_level_1).
// 3. Each provided principal is present in its corresponding backend-level RBAC filter override.
func checkRouteRBAC(t *testing.T, rc *routev3.RouteConfiguration, expectedPrincipals []string) {
	for _, vh := range rc.VirtualHosts {
		for _, r := range vh.Routes {
			if routeAction := r.GetRoute(); routeAction != nil {
				if weightedClusters := routeAction.GetWeightedClusters(); weightedClusters != nil {
					for _, wc := range weightedClusters.Clusters {
						// Verify count of backend RBAC overrides
						beFilterCount := 0
						for filterName := range wc.TypedPerFilterConfig {
							if strings.HasPrefix(filterName, constants.BackendRBACFilterNamePrefix) {
								beFilterCount++
							}
						}
						if beFilterCount != len(expectedPrincipals) {
							t.Errorf("expected %d backend RBAC overrides in cluster %s, got %d", len(expectedPrincipals), wc.Name, beFilterCount)
						}

						// Check each expected principal and filter name
						for i, expectedPrincipal := range expectedPrincipals {
							filterName := fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, i+1)
							rbacAny, ok := wc.TypedPerFilterConfig[filterName]
							if !ok {
								t.Errorf("Backend RBAC filter %s not found in cluster %s", filterName, wc.Name)
								continue
							}

							rbacPerRoute := &rbacv3.RBACPerRoute{}
							if err := rbacAny.UnmarshalTo(rbacPerRoute); err != nil {
								t.Fatalf("failed to unmarshal RBACPerRoute: %v", err)
							}

							if !hasPrincipal(rbacPerRoute.Rbac, expectedPrincipal) {
								t.Errorf("RBAC policy for cluster %s filter %s missing expected principal: %s", wc.Name, filterName, expectedPrincipal)
							}
						}
					}
				}
			}
		}
	}
}

// checkListenerRBAC verifies the RBAC configuration at the listener level.
// It checks that:
// 1. The HTTP Connection Manager has exactly the expected number of Gateway-level RBAC filters.
// 2. The HTTP Connection Manager has exactly the expected number of Backend-level RBAC filters.
// 3. All RBAC filters follow the correct naming convention (gateway_level_N or backend_level_N).
// 4. Gateway-level RBAC filters contain the expected principals.
func checkListenerRBAC(t *testing.T, lis *listenerv3.Listener, expectedGWPrincipals []string, expectedBEPrincipals []string) {
	for _, fc := range lis.FilterChains {
		for _, filter := range fc.Filters {
			if filter.Name == wellknown.HTTPConnectionManager {
				hcmConfig := &hcm.HttpConnectionManager{}
				if err := filter.GetTypedConfig().UnmarshalTo(hcmConfig); err != nil {
					t.Fatalf("failed to unmarshal HCM config: %v", err)
				}

				gwFilterCount := 0
				beFilterCount := 0
				for _, httpFilter := range hcmConfig.HttpFilters {
					if strings.HasPrefix(httpFilter.Name, constants.GatewayRBACFilterNamePrefix) {
						gwFilterCount++
						// Verify exact name
						expectedName := fmt.Sprintf("%s%d", constants.GatewayRBACFilterNamePrefix, gwFilterCount)
						if httpFilter.Name != expectedName {
							t.Errorf("Gateway RBAC filter name mismatch: got %s, want %s", httpFilter.Name, expectedName)
						}

						// Verify principal if it's within the expected list
						if gwFilterCount <= len(expectedGWPrincipals) {
							rbacConfig := &rbacv3.RBAC{}
							if err := httpFilter.GetTypedConfig().UnmarshalTo(rbacConfig); err != nil {
								t.Fatalf("failed to unmarshal RBAC config from listener: %v", err)
							}
							expectedPrincipal := expectedGWPrincipals[gwFilterCount-1]
							if !hasPrincipal(rbacConfig, expectedPrincipal) {
								t.Errorf("Gateway RBAC filter %s missing expected principal: %s", httpFilter.Name, expectedPrincipal)
							}
						}
					} else if strings.HasPrefix(httpFilter.Name, constants.BackendRBACFilterNamePrefix) {
						beFilterCount++
						// Verify exact name
						expectedName := fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, beFilterCount)
						if httpFilter.Name != expectedName {
							t.Errorf("Backend RBAC filter name mismatch in listener: got %s, want %s", httpFilter.Name, expectedName)
						}
					}
				}

				if gwFilterCount != len(expectedGWPrincipals) {
					t.Errorf("expected %d Gateway RBAC filters, got %d", len(expectedGWPrincipals), gwFilterCount)
				}
				if beFilterCount != len(expectedBEPrincipals) {
					t.Errorf("expected %d Backend RBAC filters in listener, got %d", len(expectedBEPrincipals), beFilterCount)
				}
			}
		}
	}
}
