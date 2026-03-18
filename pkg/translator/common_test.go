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
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
)

func newTestGateway(name, ns string) *gatewayv1.Gateway {
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
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
	}
}

func newTestBackend(name, ns string) *agenticv0alpha0.XBackend {
	return &agenticv0alpha0.XBackend{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: agenticv0alpha0.BackendSpec{
			MCP: agenticv0alpha0.MCPBackend{
				ServiceName: ptr.To(name + "-svc"),
				Port:        3001,
				Path:        "/mcp",
			},
		},
	}
}

func newTestHTTPRoute(name, ns, gwName, backendName string) *gatewayv1.HTTPRoute {
	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gwName)}},
			},
			Rules: []gatewayv1.HTTPRouteRule{{
				Matches: []gatewayv1.HTTPRouteMatch{{
					Path: &gatewayv1.HTTPPathMatch{Type: ptr.To(gatewayv1.PathMatchPathPrefix), Value: ptr.To("/mcp")},
				}},
				BackendRefs: []gatewayv1.HTTPBackendRef{{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{
							Name:  gatewayv1.ObjectName(backendName),
							Group: ptr.To(gatewayv1.Group(agenticv0alpha0.GroupName)),
							Kind:  ptr.To(gatewayv1.Kind("XBackend")),
						},
					},
				}},
			}},
		},
	}
}

func newTestAccessPolicy(name, ns, targetName, targetKind, principal string) *agenticv0alpha0.XAccessPolicy {
	var group string
	if targetKind == "Gateway" {
		group = gatewayv1.GroupName
	} else {
		group = agenticv0alpha0.GroupName
	}
	return &agenticv0alpha0.XAccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: agenticv0alpha0.AccessPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
					Group: gatewayv1.Group(group),
					Kind:  gatewayv1.Kind(targetKind),
					Name:  gatewayv1.ObjectName(targetName),
				},
			}},
			Rules: []agenticv0alpha0.AccessRule{{
				Name: "rule-1",
				Source: agenticv0alpha0.Source{
					Type:   agenticv0alpha0.AuthorizationSourceTypeSPIFFE,
					SPIFFE: (*agenticv0alpha0.AuthorizationSourceSPIFFE)(&principal),
				},
			}},
		},
		Status: agenticv0alpha0.AccessPolicyStatus{
			Ancestors: []gatewayv1.PolicyAncestorStatus{
				{
					Conditions: []metav1.Condition{
						{
							Type:               string(agenticv0alpha0.PolicyConditionAccepted),
							Status:             metav1.ConditionTrue,
							Reason:             "Accepted",
							LastTransitionTime: metav1.Now(),
						},
					},
				},
			},
		},
	}
}

func newTestService(name, ns string, port int32) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: port}}},
	}
}

// hasPrincipal is a helper to check if an RBAC config contains a specific SPIFFE ID principal.
func hasPrincipal(rbac *rbacv3.RBAC, expectedPrincipal string) bool {
	if rbac == nil || rbac.GetRules() == nil {
		return false
	}
	for _, policy := range rbac.GetRules().GetPolicies() {
		for _, princ := range policy.GetPrincipals() {
			if auth := princ.GetAuthenticated(); auth != nil {
				if auth.GetPrincipalName().GetExact() == expectedPrincipal {
					return true
				}
			}
		}
	}
	return false
}
