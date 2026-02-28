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
	envoyproxytypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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
	// listeners is the set of expected Envoy Listeners and their corresponding K8s Gateway listener statuses.
	listeners []expectedListener
	// routes is the set of expected Envoy RouteConfigurations and their corresponding K8s HTTPRoute parent statuses.
	routes []expectedRoute
	// clusters is the list of expected Envoy Cluster names.
	clusters []string
}

type expectedListener struct {
	// envoyName is the expected name of the Envoy Listener resource (e.g., "listener-10001").
	envoyName string
	// k8sName is the name of the listener in the Gateway spec used to find the corresponding status.
	k8sName string
	// gatewayPrincipals are the SPIFFE IDs expected in the Gateway-level RBAC filters.
	gatewayPrincipals []string
	// maxBackendPolicies is the expected number of placeholder backend-level RBAC filters in the HCM.
	maxBackendPolicies int
	// conditions are the expected status conditions for this listener.
	conditions []metav1.Condition
}

type expectedRoute struct {
	// envoyName is the expected name of the Envoy RouteConfiguration resource (e.g., "route-10001").
	envoyName string
	// k8sName is the name of the K8s HTTPRoute resource used to find the corresponding status.
	k8sName string
	// k8sNamespace is the namespace of the K8s HTTPRoute resource.
	k8sNamespace string
	// backendPrincipals are the SPIFFE IDs expected in the backend-level RBAC filter overrides.
	backendPrincipals []string
	// parentStatuses are the expected parent statuses for this HTTPRoute.
	parentStatuses []gatewayv1.RouteParentStatus
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
				listeners: []expectedListener{
					{
						envoyName:          "listener-10001",
						k8sName:            "https-listener",
						maxBackendPolicies: 1,
						conditions: []metav1.Condition{
							{
								Type:   string(gatewayv1.ListenerConditionProgrammed),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonProgrammed),
							},
							{
								Type:   string(gatewayv1.ListenerConditionAccepted),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonAccepted),
							},
						},
					},
				},
				routes: []expectedRoute{
					{
						envoyName:         "route-10001",
						k8sName:           "httproute-local-mcp",
						k8sNamespace:      ns,
						backendPrincipals: []string{"spiffe://cluster.local/ns/quickstart-ns/sa/adk-agent-sa"},
						parentStatuses: []gatewayv1.RouteParentStatus{
							{
								ParentRef:      gatewayv1.ParentReference{Name: "agentic-net-gateway"},
								ControllerName: gatewayv1.GatewayController(constants.ControllerName),
								Conditions: []metav1.Condition{
									{
										Type:   string(gatewayv1.RouteConditionAccepted),
										Status: metav1.ConditionTrue,
										Reason: string(gatewayv1.RouteReasonAccepted),
									},
									{
										Type:   string(gatewayv1.RouteConditionResolvedRefs),
										Status: metav1.ConditionTrue,
										Reason: string(gatewayv1.RouteReasonResolvedRefs),
									},
								},
							},
						},
					},
				},
				clusters: []string{"quickstart-ns-local-mcp-backend"},
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
			mcpSvc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "multi-policy-backend-svc", Namespace: ns},
				Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 3001}}},
			},
			expected: expectedResult{
				listeners: []expectedListener{
					{
						envoyName:          "listener-10001",
						k8sName:            "https-listener",
						gatewayPrincipals:  []string{"spiffe://cluster.local/ns/ns1/sa/sa1"},
						maxBackendPolicies: 1,
						conditions: []metav1.Condition{
							{
								Type:   string(gatewayv1.ListenerConditionProgrammed),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonProgrammed),
							},
							{
								Type:   string(gatewayv1.ListenerConditionAccepted),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonAccepted),
							},
						},
					},
				},
				routes: []expectedRoute{
					{
						envoyName:         "route-10001",
						k8sName:           "multi-policy-route",
						k8sNamespace:      ns,
						backendPrincipals: []string{"spiffe://cluster.local/ns/ns2/sa/sa2"},
						parentStatuses: []gatewayv1.RouteParentStatus{
							{
								ParentRef:      gatewayv1.ParentReference{Name: "multi-policy-gw"},
								ControllerName: gatewayv1.GatewayController(constants.ControllerName),
								Conditions: []metav1.Condition{
									{
										Type:   string(gatewayv1.RouteConditionAccepted),
										Status: metav1.ConditionTrue,
										Reason: string(gatewayv1.RouteReasonAccepted),
									},
									{
										Type:   string(gatewayv1.RouteConditionResolvedRefs),
										Status: metav1.ConditionTrue,
										Reason: string(gatewayv1.RouteReasonResolvedRefs),
									},
								},
							},
						},
					},
				},
				clusters: []string{"quickstart-ns-multi-policy-backend"},
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
			//nolint:staticcheck // generated clientset doesn't have NewClientset without applyconfig
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
			resources, listenerStatuses, httpRouteStatuses, _, err := tr.TranslateGatewayToXDS(ctx, tc.gw)
			if err != nil {
				t.Fatalf("Translation failed: %v", err)
			}

			// Assertions
			verifyListeners(t, resources[resourcev3.ListenerType], listenerStatuses, tc.expected.listeners)
			verifyRoutes(t, resources[resourcev3.RouteType], httpRouteStatuses, tc.expected.routes)
			verifyClusters(t, resources[resourcev3.ClusterType], tc.expected.clusters)
		})
	}
}

func verifyListeners(t *testing.T, got []envoyproxytypes.Resource, gotStatuses []gatewayv1.ListenerStatus, expected []expectedListener) {
	if len(got) != len(expected) {
		t.Errorf("expected %d listeners, got %d", len(expected), len(got))
	}
	for _, exp := range expected {
		// Verify Envoy Listener
		found := false
		for _, res := range got {
			lis := res.(*listenerv3.Listener)
			if lis.GetName() == exp.envoyName {
				found = true
				checkListenerMTLS(t, lis)
				checkListenerRBAC(t, lis, exp.gatewayPrincipals, exp.maxBackendPolicies)
			}
		}
		if !found {
			t.Errorf("expected listener %s not found", exp.envoyName)
		}

		// Verify Listener Status
		var ls *gatewayv1.ListenerStatus
		for i := range gotStatuses {
			if string(gotStatuses[i].Name) == exp.k8sName {
				ls = &gotStatuses[i]
				break
			}
		}
		if ls == nil {
			t.Errorf("expected listener status %s not found", exp.k8sName)
			continue
		}
		for _, cond := range exp.conditions {
			if !meta.IsStatusConditionTrue(ls.Conditions, cond.Type) {
				t.Errorf("expected listener %s condition %s to be True", exp.k8sName, cond.Type)
			}
		}
	}
}

func verifyRoutes(t *testing.T, got []envoyproxytypes.Resource, gotStatuses map[types.NamespacedName][]gatewayv1.RouteParentStatus, expected []expectedRoute) {
	if len(got) != len(expected) {
		t.Errorf("expected %d route configurations, got %d", len(expected), len(got))
	}
	for _, exp := range expected {
		// Verify Envoy Route Configuration
		found := false
		for _, res := range got {
			rc := res.(*routev3.RouteConfiguration)
			if rc.GetName() == exp.envoyName {
				found = true
				checkRouteRBAC(t, rc, exp.backendPrincipals)
			}
		}
		if !found {
			t.Errorf("expected route configuration %s not found", exp.envoyName)
		}

		// Verify HTTPRoute Status
		if exp.k8sName == "" {
			continue
		}
		key := types.NamespacedName{Namespace: exp.k8sNamespace, Name: exp.k8sName}
		actualStatuses, ok := gotStatuses[key]
		if !ok {
			t.Errorf("expected http route status for %s", key)
			continue
		}
		if len(actualStatuses) != len(exp.parentStatuses) {
			t.Errorf("expected %d route parent statuses for %s, got %d", len(exp.parentStatuses), key, len(actualStatuses))
			continue
		}
		for i, expStatus := range exp.parentStatuses {
			got := actualStatuses[i]
			if got.ParentRef.Name != expStatus.ParentRef.Name {
				t.Errorf("expected parent ref name %s for %s, got %s", expStatus.ParentRef.Name, key, got.ParentRef.Name)
			}
			if got.ControllerName != expStatus.ControllerName {
				t.Errorf("expected controller name %s for %s, got %s", expStatus.ControllerName, key, got.ControllerName)
			}
			for _, cond := range expStatus.Conditions {
				if !meta.IsStatusConditionTrue(got.Conditions, cond.Type) {
					t.Errorf("expected route %s condition %s to be True", key, cond.Type)
				}
			}
		}
	}
}

func verifyClusters(t *testing.T, got []envoyproxytypes.Resource, expected []string) {
	if len(got) != len(expected) {
		t.Errorf("expected %d clusters, got %d", len(expected), len(got))
	}
	for _, expectedName := range expected {
		found := false
		for _, res := range got {
			cl := res.(*clusterv3.Cluster)
			if cl.GetName() == expectedName {
				found = true
			}
		}
		if !found {
			t.Errorf("expected cluster %s not found", expectedName)
		}
	}
}

func checkListenerMTLS(t *testing.T, lis *listenerv3.Listener) {
	foundTLS := false
	for _, fc := range lis.GetFilterChains() {
		if fc.GetTransportSocket() != nil && fc.GetTransportSocket().GetName() == "envoy.transport_sockets.tls" {
			foundTLS = true
			tlsContext := &tlsv3.DownstreamTlsContext{}
			if err := fc.GetTransportSocket().GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
				t.Fatalf("failed to unmarshal TLS context: %v", err)
			}
			if !tlsContext.GetRequireClientCertificate().GetValue() {
				t.Error("RequireClientCertificate should be true for mTLS")
			}

			// Verify SDS config names
			common := tlsContext.GetCommonTlsContext()
			if common.GetTlsCertificateSdsSecretConfigs()[0].GetName() != constants.SpiffeIdentitySdsConfigName {
				t.Errorf("Identity SDS config name mismatch: got %s, want %s", common.GetTlsCertificateSdsSecretConfigs()[0].GetName(), constants.SpiffeIdentitySdsConfigName)
			}
			if common.GetValidationContextSdsSecretConfig().GetName() != constants.SpiffeTrustSdsConfigName {
				t.Errorf("Trust SDS config name mismatch: got %s, want %s", common.GetValidationContextSdsSecretConfig().GetName(), constants.SpiffeTrustSdsConfigName)
			}
		}
	}
	if !foundTLS {
		t.Errorf("mTLS transport socket configuration not found in listener %s", lis.GetName())
	}
}

// checkRouteRBAC verifies the RBAC configuration at the route level.
// It checks that:
// 1. All clusters in weighted clusters have exactly the expected number of backend-level RBAC filters.
// 2. Each backend-level RBAC filter follows the correct naming convention (e.g., backend_level_1).
// 3. Each provided principal is present in its corresponding backend-level RBAC filter override.
func checkRouteRBAC(t *testing.T, rc *routev3.RouteConfiguration, expectedPrincipals []string) {
	for _, vh := range rc.GetVirtualHosts() {
		for _, r := range vh.GetRoutes() {
			if routeAction := r.GetRoute(); routeAction != nil {
				if weightedClusters := routeAction.GetWeightedClusters(); weightedClusters != nil {
					for _, wc := range weightedClusters.GetClusters() {
						// Verify count of backend RBAC overrides
						beFilterCount := 0
						for filterName := range wc.GetTypedPerFilterConfig() {
							if strings.HasPrefix(filterName, constants.BackendRBACFilterNamePrefix) {
								beFilterCount++
							}
						}
						if beFilterCount != len(expectedPrincipals) {
							t.Errorf("expected %d backend RBAC overrides in cluster %s, got %d", len(expectedPrincipals), wc.GetName(), beFilterCount)
						}

						// Check each expected principal and filter name
						for i, expectedPrincipal := range expectedPrincipals {
							filterName := fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, i+1)
							rbacAny, ok := wc.GetTypedPerFilterConfig()[filterName]
							if !ok {
								t.Errorf("Backend RBAC filter %s not found in cluster %s", filterName, wc.GetName())
								continue
							}

							rbacPerRoute := &rbacv3.RBACPerRoute{}
							if err := rbacAny.UnmarshalTo(rbacPerRoute); err != nil {
								t.Fatalf("failed to unmarshal RBACPerRoute: %v", err)
							}

							if !hasPrincipal(rbacPerRoute.GetRbac(), expectedPrincipal) {
								t.Errorf("RBAC policy for cluster %s filter %s missing expected principal: %s", wc.GetName(), filterName, expectedPrincipal)
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
func checkListenerRBAC(t *testing.T, lis *listenerv3.Listener, expectedGWPrincipals []string, maxBackendPolicies int) {
	for _, fc := range lis.GetFilterChains() {
		for _, filter := range fc.GetFilters() {
			if filter.GetName() == wellknown.HTTPConnectionManager {
				hcmConfig := &hcm.HttpConnectionManager{}
				if err := filter.GetTypedConfig().UnmarshalTo(hcmConfig); err != nil {
					t.Fatalf("failed to unmarshal HCM config: %v", err)
				}

				gwFilterCount := 0
				beFilterCount := 0
				for _, httpFilter := range hcmConfig.GetHttpFilters() {
					if strings.HasPrefix(httpFilter.GetName(), constants.GatewayRBACFilterNamePrefix) {
						gwFilterCount++
						// Verify exact name
						expectedName := fmt.Sprintf("%s%d", constants.GatewayRBACFilterNamePrefix, gwFilterCount)
						if httpFilter.GetName() != expectedName {
							t.Errorf("Gateway RBAC filter name mismatch: got %s, want %s", httpFilter.GetName(), expectedName)
						}

						// Verify principal if it's within the expected list
						if gwFilterCount <= len(expectedGWPrincipals) {
							rbacConfig := &rbacv3.RBAC{}
							if err := httpFilter.GetTypedConfig().UnmarshalTo(rbacConfig); err != nil {
								t.Fatalf("failed to unmarshal RBAC config from listener: %v", err)
							}
							expectedPrincipal := expectedGWPrincipals[gwFilterCount-1]
							if !hasPrincipal(rbacConfig, expectedPrincipal) {
								t.Errorf("Gateway RBAC filter %s missing expected principal: %s", httpFilter.GetName(), expectedPrincipal)
							}
						}
					} else if strings.HasPrefix(httpFilter.GetName(), constants.BackendRBACFilterNamePrefix) {
						beFilterCount++
						// Verify exact name
						expectedName := fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, beFilterCount)
						if httpFilter.GetName() != expectedName {
							t.Errorf("Backend RBAC filter name mismatch in listener: got %s, want %s", httpFilter.GetName(), expectedName)
						}
					}
				}

				if gwFilterCount != len(expectedGWPrincipals) {
					t.Errorf("expected %d Gateway RBAC filters, got %d", len(expectedGWPrincipals), gwFilterCount)
				}
				if beFilterCount != maxBackendPolicies {
					t.Errorf("expected %d Backend RBAC filters in listener, got %d", maxBackendPolicies, beFilterCount)
				}
			}
		}
	}
}
