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
	"testing"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
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
	if tlsContext.RequireClientCertificate == nil || !tlsContext.RequireClientCertificate.Value {
		t.Errorf("RequireClientCertificate should be true for mTLS")
	}

	// Verify SDS Config Names
	common := tlsContext.CommonTlsContext
	if len(common.TlsCertificateSdsSecretConfigs) != 1 || common.TlsCertificateSdsSecretConfigs[0].Name != constants.SpiffeIdentitySdsConfigName {
		t.Errorf("Identity SDS secret config name mismatch")
	}

	validation := common.GetValidationContextSdsSecretConfig()
	if validation == nil || validation.Name != constants.SpiffeTrustSdsConfigName {
		t.Errorf("Trust SDS secret config name mismatch")
	}
}

func TestBuildHTTPFilters(t *testing.T) {
	ns := "test-ns"
	gwName := "test-gw"
	maxLimit := 2

	tests := []struct {
		name     string
		policies []runtime.Object
		expected []string
	}{
		{
			name:     "0 gw policy, 0 ext",
			policies: []runtime.Object{},
			expected: []string{
				"envoy.filters.http.mcp",
				fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, 1),
				fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, 2),
				"envoy.filters.http.router",
			},
		},
		{
			name: "2 gw policy, 0 ext",
			policies: []runtime.Object{
				&agenticv0alpha0.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "gw-policy-1", Namespace: ns, CreationTimestamp: metav1.Now()},
					Spec: agenticv0alpha0.AccessPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
							LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
								Group: gatewayv1.Group(gatewayv1.GroupName),
								Kind:  gatewayv1.Kind("Gateway"),
								Name:  gatewayv1.ObjectName(gwName),
							},
						}},
						Rules: []agenticv0alpha0.AccessRule{{Name: "rule-1"}},
					},
					Status: agenticv0alpha0.AccessPolicyStatus{
						Ancestors: []gatewayv1.PolicyAncestorStatus{{
							Conditions: []metav1.Condition{{
								Type:   string(agenticv0alpha0.PolicyConditionAccepted),
								Status: metav1.ConditionTrue,
							}},
						}},
					},
				},
				&agenticv0alpha0.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "gw-policy-2", Namespace: ns, CreationTimestamp: metav1.Now()},
					Spec: agenticv0alpha0.AccessPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
							LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
								Group: gatewayv1.Group(gatewayv1.GroupName),
								Kind:  gatewayv1.Kind("Gateway"),
								Name:  gatewayv1.ObjectName(gwName),
							},
						}},
						Rules: []agenticv0alpha0.AccessRule{{Name: "rule-1"}},
					},
					Status: agenticv0alpha0.AccessPolicyStatus{
						Ancestors: []gatewayv1.PolicyAncestorStatus{{
							Conditions: []metav1.Condition{{
								Type:   string(agenticv0alpha0.PolicyConditionAccepted),
								Status: metav1.ConditionTrue,
							}},
						}},
					},
				},
			},
			expected: []string{
				"envoy.filters.http.mcp",
				fmt.Sprintf("%s%d", constants.GatewayRBACFilterNamePrefix, 1),
				fmt.Sprintf("%s%d", constants.GatewayRBACFilterNamePrefix, 2),
				fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, 1),
				fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, 2),
				"envoy.filters.http.router",
			},
		},
		{
			name: "0 gw policy, 2 ext",
			policies: []runtime.Object{
				&agenticv0alpha0.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "ext-auth-policy-1", Namespace: ns},
					Spec: agenticv0alpha0.AccessPolicySpec{
						Rules: []agenticv0alpha0.AccessRule{{
							Name: "ext-rule-1",
							Authorization: &agenticv0alpha0.AuthorizationRule{
								Type: agenticv0alpha0.AuthorizationRuleTypeExternalAuth,
								ExternalAuth: &gatewayv1.HTTPExternalAuthFilter{
									ExternalAuthProtocol: gatewayv1.HTTPRouteExternalAuthGRPCProtocol,
									BackendRef: gatewayv1.BackendObjectReference{
										Name: "ext-auth-svc-1",
									},
								},
							},
						}},
					},
					Status: agenticv0alpha0.AccessPolicyStatus{
						Ancestors: []gatewayv1.PolicyAncestorStatus{{
							Conditions: []metav1.Condition{{
								Type:   string(agenticv0alpha0.PolicyConditionAccepted),
								Status: metav1.ConditionTrue,
							}},
						}},
					},
				},
				&agenticv0alpha0.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "ext-auth-policy-2", Namespace: ns},
					Spec: agenticv0alpha0.AccessPolicySpec{
						Rules: []agenticv0alpha0.AccessRule{{
							Name: "ext-rule-2",
							Authorization: &agenticv0alpha0.AuthorizationRule{
								Type: agenticv0alpha0.AuthorizationRuleTypeExternalAuth,
								ExternalAuth: &gatewayv1.HTTPExternalAuthFilter{
									ExternalAuthProtocol: gatewayv1.HTTPRouteExternalAuthGRPCProtocol,
									BackendRef: gatewayv1.BackendObjectReference{
										Name: "ext-auth-svc-2",
									},
								},
							},
						}},
					},
					Status: agenticv0alpha0.AccessPolicyStatus{
						Ancestors: []gatewayv1.PolicyAncestorStatus{{
							Conditions: []metav1.Condition{{
								Type:   string(agenticv0alpha0.PolicyConditionAccepted),
								Status: metav1.ConditionTrue,
							}},
						}},
					},
				},
			},
			expected: []string{
				"envoy.filters.http.mcp",
				fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, 1),
				fmt.Sprintf("%s%d", constants.BackendRBACFilterNamePrefix, 2),
				"envoy.filters.http.ext_authz",
				"envoy.filters.http.ext_authz",
				"envoy.filters.http.router",
			},
		},
		{
			name: "2 gw policy, 2 ext",
			policies: []runtime.Object{
				&agenticv0alpha0.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "mixed-policy-1", Namespace: ns, CreationTimestamp: metav1.Now()},
					Spec: agenticv0alpha0.AccessPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
							LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
								Group: gatewayv1.Group(gatewayv1.GroupName),
								Kind:  gatewayv1.Kind("Gateway"),
								Name:  gatewayv1.ObjectName(gwName),
							},
						}},
						Rules: []agenticv0alpha0.AccessRule{{
							Name: "rule-1",
							Authorization: &agenticv0alpha0.AuthorizationRule{
								Type: agenticv0alpha0.AuthorizationRuleTypeExternalAuth,
								ExternalAuth: &gatewayv1.HTTPExternalAuthFilter{
									ExternalAuthProtocol: gatewayv1.HTTPRouteExternalAuthGRPCProtocol,
									BackendRef: gatewayv1.BackendObjectReference{
										Name: "ext-auth-svc-1",
									},
								},
							},
						}},
					},
					Status: agenticv0alpha0.AccessPolicyStatus{
						Ancestors: []gatewayv1.PolicyAncestorStatus{{
							Conditions: []metav1.Condition{{
								Type:   string(agenticv0alpha0.PolicyConditionAccepted),
								Status: metav1.ConditionTrue,
							}},
						}},
					},
				},
				&agenticv0alpha0.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "mixed-policy-2", Namespace: ns, CreationTimestamp: metav1.Now()},
					Spec: agenticv0alpha0.AccessPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
							LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
								Group: gatewayv1.Group(gatewayv1.GroupName),
								Kind:  gatewayv1.Kind("Gateway"),
								Name:  gatewayv1.ObjectName(gwName),
							},
						}},
						Rules: []agenticv0alpha0.AccessRule{{
							Name: "rule-2",
							Authorization: &agenticv0alpha0.AuthorizationRule{
								Type: agenticv0alpha0.AuthorizationRuleTypeExternalAuth,
								ExternalAuth: &gatewayv1.HTTPExternalAuthFilter{
									ExternalAuthProtocol: gatewayv1.HTTPRouteExternalAuthGRPCProtocol,
									BackendRef: gatewayv1.BackendObjectReference{
										Name: "ext-auth-svc-2",
									},
								},
							},
						}},
					},
					Status: agenticv0alpha0.AccessPolicyStatus{
						Ancestors: []gatewayv1.PolicyAncestorStatus{{
							Conditions: []metav1.Condition{{
								Type:   string(agenticv0alpha0.PolicyConditionAccepted),
								Status: metav1.ConditionTrue,
							}},
						}},
					},
				},
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

			tr := &Translator{accessPolicyLister: lister, maxAccessPoliciesPerTarget: maxLimit}
			gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: gwName, Namespace: ns}}

			filters, err := tr.buildHTTPFilters(gw)
			if err != nil {
				t.Fatalf("Failed to build filters: %v", err)
			}

			if len(filters) != len(tt.expected) {
				t.Fatalf("Expected %d total filters, got %d", len(tt.expected), len(filters))
			}

			for i, f := range filters {
				if f.Name != tt.expected[i] {
					t.Errorf("Filter %d: expected %s, got %s", i, tt.expected[i], f.Name)
				}
			}
		})
	}
}
