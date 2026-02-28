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
	"fmt"
	"reflect"
	"testing"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticclient "sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned/fake"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

func TestBuildDownstreamTLSContext(t *testing.T) {
	anyContext, err := buildDownstreamTLSContext()
	if err != nil {
		t.Fatalf("failed to build downstream TLS context: %v", err)
	}

	if anyContext == nil {
		t.Fatal("expected non-nil TLS context")
	}

	tlsContext := &tlsv3.DownstreamTlsContext{}
	if err := anyContext.UnmarshalTo(tlsContext); err != nil {
		t.Fatalf("failed to unmarshal any to DownstreamTlsContext: %v", err)
	}

	// Verify mTLS requirement
	if tlsContext.GetRequireClientCertificate() == nil || !tlsContext.GetRequireClientCertificate().GetValue() {
		t.Errorf("RequireClientCertificate should be true for mTLS")
	}

	// Verify SDS Config Names
	common := tlsContext.GetCommonTlsContext()
	if len(common.GetTlsCertificateSdsSecretConfigs()) != 1 || common.GetTlsCertificateSdsSecretConfigs()[0].GetName() != constants.SpiffeIdentitySdsConfigName {
		t.Errorf("Identity SDS secret config name mismatch")
	}

	validation := common.GetValidationContextSdsSecretConfig()
	if validation == nil || validation.GetName() != constants.SpiffeTrustSdsConfigName {
		t.Errorf("Trust SDS secret config name mismatch")
	}
}

func TestTranslateListenerToFilterChain(t *testing.T) {
	agenticClient := agenticclient.NewSimpleClientset()
	agenticInformerFactory := agenticinformers.NewSharedInformerFactory(agenticClient, 0)
	accessPolicyLister := agenticInformerFactory.Agentic().V0alpha0().XAccessPolicies().Lister()

	gwClient := gatewayclient.NewSimpleClientset()
	gwInformerFactory := gatewayinformers.NewSharedInformerFactory(gwClient, 0)
	httprouteLister := gwInformerFactory.Gateway().V1().HTTPRoutes().Lister()

	translator := &Translator{
		accessPolicyLister: accessPolicyLister,
		httprouteLister:    httprouteLister,
	}

	testCases := []struct {
		name                string
		listener            gatewayv1.Listener
		expectedServerNames []string
	}{
		{
			name: "HTTPS with hostname",
			listener: gatewayv1.Listener{
				Name:     "https",
				Port:     443,
				Protocol: gatewayv1.HTTPSProtocolType,
				Hostname: ptr.To(gatewayv1.Hostname("example.com")),
			},
			expectedServerNames: []string{"example.com"},
		},
		{
			name: "HTTPS with wildcard hostname",
			listener: gatewayv1.Listener{
				Name:     "https-wildcard",
				Port:     443,
				Protocol: gatewayv1.HTTPSProtocolType,
				Hostname: ptr.To(gatewayv1.Hostname("*.example.com")),
			},
			expectedServerNames: []string{"*.example.com"},
		},
		{
			name: "HTTP without hostname",
			listener: gatewayv1.Listener{
				Name:     "http",
				Port:     80,
				Protocol: gatewayv1.HTTPProtocolType,
			},
			expectedServerNames: nil,
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fc, err := translator.translateListenerToFilterChain(tc.listener, "route-config", gw)
			if err != nil {
				t.Fatalf("failed to translate listener: %v", err)
			}

			if len(tc.expectedServerNames) > 0 {
				if fc.GetFilterChainMatch() == nil {
					t.Fatal("expected FilterChainMatch to be set")
				}
				if !reflect.DeepEqual(fc.GetFilterChainMatch().GetServerNames(), tc.expectedServerNames) {
					t.Errorf("expected ServerNames %v, got %v", tc.expectedServerNames, fc.GetFilterChainMatch().GetServerNames())
				}
			} else if fc.GetFilterChainMatch() != nil && len(fc.GetFilterChainMatch().GetServerNames()) > 0 {
				t.Errorf("expected no ServerNames in FilterChainMatch, got %v", fc.GetFilterChainMatch().GetServerNames())
			}
		})
	}
}

func TestBuildHTTPFilters(t *testing.T) {
	ns := "test-ns"
	gwName := "test-gw"

	tests := []struct {
		name     string
		policies []runtime.Object
		routes   []*gatewayv1.HTTPRoute
		expected []string
	}{
		{
			name:     "0 Gateway-level Policies, 0 Backend-level policies, 0 external auth policies",
			policies: []runtime.Object{},
			expected: []string{
				"envoy.filters.http.mcp",
				"envoy.filters.http.router",
			},
		},
		{
			name: "2 Gateway-level Policies, 0 Backend-level policies, 0 external auth policies",
			policies: []runtime.Object{
				newTestAccessPolicy("gw-policy-1", ns, gwName, "Gateway", "spiffe://cluster.local/ns/ns1/sa/sa1"),
				newTestAccessPolicy("gw-policy-2", ns, gwName, "Gateway", "spiffe://cluster.local/ns/ns2/sa/sa2"),
			},
			expected: []string{
				"envoy.filters.http.mcp",
				fmt.Sprintf("%s%d", constants.GatewayRBACFilterNamePrefix, 1),
				fmt.Sprintf("%s%d", constants.GatewayRBACFilterNamePrefix, 2),
				"envoy.filters.http.router",
			},
		},
		{
			name: "0 Gateway-level Policies, 2 Backend-level policies, 0 external auth policies",
			routes: []*gatewayv1.HTTPRoute{
				newTestHTTPRoute("route-1", ns, gwName, "backend-1"),
			},
			policies: []runtime.Object{
				newTestAccessPolicy("be-policy-1", ns, "backend-1", "XBackend", "spiffe://cluster.local/ns/ns1/sa/sa1"),
				newTestAccessPolicy("be-policy-2", ns, "backend-1", "XBackend", "spiffe://cluster.local/ns/ns2/sa/sa2"),
			},
			expected: []string{
				"envoy.filters.http.mcp",
				fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, 1),
				fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, 2),
				"envoy.filters.http.router",
			},
		},
		{
			name: "0 Gateway-level Policies, 0 Backend-level policies, 2 external auth policies",
			policies: []runtime.Object{
				func() *agenticv0alpha0.XAccessPolicy {
					p := newTestAccessPolicy("ext-auth-policy-1", ns, "dummy", "Gateway", "spiffe://cluster.local/ns/ns1/sa/sa1")
					p.Spec.Rules[0].Name = "ext-rule-1"
					p.Spec.Rules[0].Authorization = &agenticv0alpha0.AuthorizationRule{
						Type: agenticv0alpha0.AuthorizationRuleTypeExternalAuth,
						ExternalAuth: &gatewayv1.HTTPExternalAuthFilter{
							ExternalAuthProtocol: gatewayv1.HTTPRouteExternalAuthGRPCProtocol,
							BackendRef: gatewayv1.BackendObjectReference{
								Name: "ext-auth-svc-1",
							},
						},
					}
					return p
				}(),
				func() *agenticv0alpha0.XAccessPolicy {
					p := newTestAccessPolicy("ext-auth-policy-2", ns, "dummy", "Gateway", "spiffe://cluster.local/ns/ns2/sa/sa2")
					p.Spec.Rules[0].Name = "ext-rule-2"
					p.Spec.Rules[0].Authorization = &agenticv0alpha0.AuthorizationRule{
						Type: agenticv0alpha0.AuthorizationRuleTypeExternalAuth,
						ExternalAuth: &gatewayv1.HTTPExternalAuthFilter{
							ExternalAuthProtocol: gatewayv1.HTTPRouteExternalAuthGRPCProtocol,
							BackendRef: gatewayv1.BackendObjectReference{
								Name: "ext-auth-svc-2",
							},
						},
					}
					return p
				}(),
			},
			expected: []string{
				"envoy.filters.http.mcp",
				"envoy.filters.http.ext_authz",
				"envoy.filters.http.ext_authz",
				"envoy.filters.http.router",
			},
		},
		{
			name: "2 Gateway-level Policies, 2 Backend-level policies, 2 external auth policies",
			routes: []*gatewayv1.HTTPRoute{
				newTestHTTPRoute("route-1", ns, gwName, "backend-1"),
			},
			policies: []runtime.Object{
				newTestAccessPolicy("gw-policy-1", ns, gwName, "Gateway", "spiffe://cluster.local/ns/ns1/sa/sa1"),
				newTestAccessPolicy("gw-policy-2", ns, gwName, "Gateway", "spiffe://cluster.local/ns/ns2/sa/sa2"),
				newTestAccessPolicy("be-policy-1", ns, "backend-1", "XBackend", "spiffe://cluster.local/ns/ns3/sa/sa3"),
				newTestAccessPolicy("be-policy-2", ns, "backend-1", "XBackend", "spiffe://cluster.local/ns/ns4/sa/sa4"),
				func() *agenticv0alpha0.XAccessPolicy {
					p := newTestAccessPolicy("ext-auth-policy-1", ns, "dummy", "Gateway", "spiffe://cluster.local/ns/ns1/sa/sa1")
					p.Spec.Rules[0].Name = "ext-rule-1"
					p.Spec.Rules[0].Authorization = &agenticv0alpha0.AuthorizationRule{
						Type: agenticv0alpha0.AuthorizationRuleTypeExternalAuth,
						ExternalAuth: &gatewayv1.HTTPExternalAuthFilter{
							ExternalAuthProtocol: gatewayv1.HTTPRouteExternalAuthGRPCProtocol,
							BackendRef: gatewayv1.BackendObjectReference{
								Name: "ext-auth-svc-1",
							},
						},
					}
					return p
				}(),
				func() *agenticv0alpha0.XAccessPolicy {
					p := newTestAccessPolicy("ext-auth-policy-2", ns, "dummy", "Gateway", "spiffe://cluster.local/ns/ns2/sa/sa2")
					p.Spec.Rules[0].Name = "ext-rule-2"
					p.Spec.Rules[0].Authorization = &agenticv0alpha0.AuthorizationRule{
						Type: agenticv0alpha0.AuthorizationRuleTypeExternalAuth,
						ExternalAuth: &gatewayv1.HTTPExternalAuthFilter{
							ExternalAuthProtocol: gatewayv1.HTTPRouteExternalAuthGRPCProtocol,
							BackendRef: gatewayv1.BackendObjectReference{
								Name: "ext-auth-svc-2",
							},
						},
					}
					return p
				}(),
			},
			expected: []string{
				"envoy.filters.http.mcp",
				fmt.Sprintf("%s%d", constants.GatewayRBACFilterNamePrefix, 1),
				fmt.Sprintf("%s%d", constants.GatewayRBACFilterNamePrefix, 2),
				fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, 1),
				fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, 2),
				"envoy.filters.http.ext_authz",
				"envoy.filters.http.ext_authz",
				"envoy.filters.http.router",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agenticClient := agenticclient.NewSimpleClientset(tt.policies...)
			agenticInformerFactory := agenticinformers.NewSharedInformerFactory(agenticClient, 0)
			lister := agenticInformerFactory.Agentic().V0alpha0().XAccessPolicies().Lister()

			for _, p := range tt.policies {
				_ = agenticInformerFactory.Agentic().V0alpha0().XAccessPolicies().Informer().GetIndexer().Add(p)
			}

			// Initialize other listers with empty fake clients to avoid nil pointer panics
			gwObjs := make([]runtime.Object, len(tt.routes))
			for i, r := range tt.routes {
				gwObjs[i] = r
			}
			gwClient := gatewayclient.NewSimpleClientset(gwObjs...)
			gwInformerFactory := gatewayinformers.NewSharedInformerFactory(gwClient, 0)
			for _, r := range tt.routes {
				_ = gwInformerFactory.Gateway().V1().HTTPRoutes().Informer().GetIndexer().Add(r)
			}

			tr := &Translator{
				accessPolicyLister: lister,
				httprouteLister:    gwInformerFactory.Gateway().V1().HTTPRoutes().Lister(),
			}
			gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: gwName, Namespace: ns}}

			filters, err := tr.buildHTTPFilters(gw)
			if err != nil {
				t.Fatalf("Failed to build filters: %v", err)
			}

			if len(filters) != len(tt.expected) {
				t.Fatalf("Expected %d total filters, got %d", len(tt.expected), len(filters))
			}

			for i, f := range filters {
				if f.GetName() != tt.expected[i] {
					t.Errorf("Filter %d: expected %s, got %s", i, tt.expected[i], f.GetName())
				}
			}
		})
	}
}
