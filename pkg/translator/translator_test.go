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
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"
	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticclient "sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned/fake"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

func TestTranslateGatewayToXDS_Full(t *testing.T) {
	ns := "quickstart-ns"
	trustDomain := "cluster.local"

	tests := []struct {
		name     string
		gw       *gatewayv1.Gateway
		backend  *agenticv0alpha0.XBackend
		route    *gatewayv1.HTTPRoute
		policy   *agenticv0alpha0.XAccessPolicy
		mcpSvc   *corev1.Service
		expected struct {
			listenerNames []string
			routeNames    []string
			clusterNames  []string
			spiffeID      string
		}
	}{
		{
			name: "Basic mTLS and RBAC Translation",
			gw: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "agentic-net-gateway", Namespace: ns},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "cloud-provider-kind",
					Listeners: []gatewayv1.Listener{{
						Name:     "https-listener",
						Port:     10001,
						Protocol: gatewayv1.HTTPSProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{From: ptr.To(gatewayv1.NamespacesFromSame)},
						},
					}},
				},
			},
			backend: &agenticv0alpha0.XBackend{
				ObjectMeta: metav1.ObjectMeta{Name: "local-mcp-backend", Namespace: ns},
				Spec: agenticv0alpha0.BackendSpec{
					MCP: agenticv0alpha0.MCPBackend{
						ServiceName: ptr.To("mcp-everything-svc"),
						Port:        3001,
						Path:        "/mcp",
					},
				},
			},
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "httproute-local-mcp", Namespace: ns},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: "agentic-net-gateway"}},
					},
					Rules: []gatewayv1.HTTPRouteRule{{
						Matches: []gatewayv1.HTTPRouteMatch{{
							Path: &gatewayv1.HTTPPathMatch{Type: ptr.To(gatewayv1.PathMatchPathPrefix), Value: ptr.To("/local/mcp")},
						}},
						Filters: []gatewayv1.HTTPRouteFilter{{
							Type: gatewayv1.HTTPRouteFilterURLRewrite,
							URLRewrite: &gatewayv1.HTTPURLRewriteFilter{
								Path: &gatewayv1.HTTPPathModifier{
									Type:               gatewayv1.PrefixMatchHTTPPathModifier,
									ReplacePrefixMatch: ptr.To("/mcp"),
								},
							},
						}},
						BackendRefs: []gatewayv1.HTTPBackendRef{{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name:  "local-mcp-backend",
									Group: ptr.To(gatewayv1.Group("agentic.prototype.x-k8s.io")),
									Kind:  ptr.To(gatewayv1.Kind("XBackend")),
								},
							},
						}},
					}},
				},
			},
			policy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "auth-policy-local-mcp", Namespace: ns},
				Spec: agenticv0alpha0.AccessPolicySpec{
					TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
						LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
							Group: "agentic.prototype.x-k8s.io",
							Kind:  "XBackend",
							Name:  "local-mcp-backend",
						},
					}},
					Rules: []agenticv0alpha0.AccessRule{{
						Name: "tools-for-adk-agent-sa",
						Source: agenticv0alpha0.Source{
							Type: agenticv0alpha0.AuthorizationSourceTypeServiceAccount,
							ServiceAccount: &agenticv0alpha0.AuthorizationSourceServiceAccount{
								Name:      "adk-agent-sa",
								Namespace: ns,
							},
						},
						Authorization: &agenticv0alpha0.AuthorizationRule{
							Type:  agenticv0alpha0.AuthorizationRuleTypeInlineTools,
							Tools: []string{"get-sum"},
						},
					}},
				},
			},
			mcpSvc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "mcp-everything-svc", Namespace: ns},
				Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 3001}}},
			},
			expected: struct {
				listenerNames []string
				routeNames    []string
				clusterNames  []string
				spiffeID      string
			}{
				listenerNames: []string{"listener-10001"},
				routeNames:    []string{"route-10001"},
				clusterNames:  []string{"quickstart-ns-local-mcp-backend", "kubernetes_api_cluster"},
				spiffeID:      "spiffe://cluster.local/ns/quickstart-ns/sa/adk-agent-sa",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// 2. Setup Fake Clients and Informers
			ctx := context.Background()
			k8sClient := fake.NewClientset(tc.mcpSvc)
			gwClient := gatewayclient.NewClientset(tc.gw, tc.route)
			agenticClient := agenticclient.NewSimpleClientset(tc.backend, tc.policy)

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
				agenticInformerFactory.Agentic().V0alpha0().XAccessPolicies().Lister(),
				agenticInformerFactory.Agentic().V0alpha0().XBackends().Lister(),
			)

			// Populate Informer caches
			_ = coreInformerFactory.Core().V1().Services().Informer().GetIndexer().Add(tc.mcpSvc)
			_ = gwInformerFactory.Gateway().V1().Gateways().Informer().GetIndexer().Add(tc.gw)
			_ = gwInformerFactory.Gateway().V1().HTTPRoutes().Informer().GetIndexer().Add(tc.route)
			_ = agenticInformerFactory.Agentic().V0alpha0().XBackends().Informer().GetIndexer().Add(tc.backend)
			_ = agenticInformerFactory.Agentic().V0alpha0().XAccessPolicies().Informer().GetIndexer().Add(tc.policy)

			// 3. Run Translation
			resources, err := tr.TranslateGatewayToXDS(ctx, tc.gw)
			if err != nil {
				t.Fatalf("Translation failed: %v", err)
			}

			// 4. Assertions
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
						checkRouteRBAC(t, rc, tc.expected.spiffeID)
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

func checkRouteRBAC(t *testing.T, rc *routev3.RouteConfiguration, expectedPrincipal string) {
	foundRBAC := false
	for _, vh := range rc.VirtualHosts {
		for _, r := range vh.Routes {
			if routeAction := r.GetRoute(); routeAction != nil {
				if weightedClusters := routeAction.GetWeightedClusters(); weightedClusters != nil {
					for _, wc := range weightedClusters.Clusters {
						if rbacAny, ok := wc.TypedPerFilterConfig[wellknown.HTTPRoleBasedAccessControl]; ok {
							foundRBAC = true
							rbacPerRoute := &rbacv3.RBACPerRoute{}
							if err := rbacAny.UnmarshalTo(rbacPerRoute); err != nil {
								t.Fatalf("failed to unmarshal RBACPerRoute: %v", err)
							}

							foundPrincipal := false
							for _, policy := range rbacPerRoute.Rbac.Rules.Policies {
								for _, princ := range policy.Principals {
									if auth := princ.GetAuthenticated(); auth != nil {
										if auth.PrincipalName.GetExact() == expectedPrincipal {
											foundPrincipal = true
											break
										}
									}
								}
								if foundPrincipal {
									break
								}
							}
							if !foundPrincipal {
								t.Errorf("RBAC policy for cluster %s missing expected principal: %s", wc.Name, expectedPrincipal)
							}
						}
					}
				}
			}
		}
	}
	if !foundRBAC {
		t.Errorf("RBAC per-cluster config not found in route configuration %s", rc.Name)
	}
}
