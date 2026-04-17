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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"
)

func TestAllowedByReferenceGrant(t *testing.T) {
	tests := []struct {
		name          string
		fromNamespace string
		fromGroup     string
		fromKind      string
		toNamespace   string
		toGroup       string
		toKind        string
		toName        string
		grants        []*gatewayv1beta1.ReferenceGrant
		expected      bool
	}{
		{
			name:          "same namespace",
			fromNamespace: "ns1",
			toNamespace:   "ns1",
			expected:      true,
		},
		{
			name:          "allowed cross-namespace",
			fromNamespace: "ns1",
			fromGroup:     gatewayv1.GroupName,
			fromKind:      "HTTPRoute",
			toNamespace:   "ns2",
			toGroup:       "",
			toKind:        "Service",
			toName:        "svc1",
			grants: []*gatewayv1beta1.ReferenceGrant{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "rg1", Namespace: "ns2"},
					Spec: gatewayv1beta1.ReferenceGrantSpec{
						From: []gatewayv1beta1.ReferenceGrantFrom{
							{
								Namespace: "ns1",
								Group:     gatewayv1.Group(gatewayv1.GroupName),
								Kind:      "HTTPRoute",
							},
						},
						To: []gatewayv1beta1.ReferenceGrantTo{
							{
								Group: "",
								Kind:  "Service",
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name:          "allowed cross-namespace with name specific",
			fromNamespace: "ns1",
			fromGroup:     gatewayv1.GroupName,
			fromKind:      "HTTPRoute",
			toNamespace:   "ns2",
			toGroup:       "",
			toKind:        "Service",
			toName:        "svc1",
			grants: []*gatewayv1beta1.ReferenceGrant{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "rg1", Namespace: "ns2"},
					Spec: gatewayv1beta1.ReferenceGrantSpec{
						From: []gatewayv1beta1.ReferenceGrantFrom{
							{
								Namespace: "ns1",
								Group:     gatewayv1.Group(gatewayv1.GroupName),
								Kind:      "HTTPRoute",
							},
						},
						To: []gatewayv1beta1.ReferenceGrantTo{
							{
								Group: "",
								Kind:  "Service",
								Name:  ptr.To(gatewayv1.ObjectName("svc1")),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name:          "not allowed cross-namespace - no grant",
			fromNamespace: "ns1",
			fromGroup:     gatewayv1.GroupName,
			fromKind:      "HTTPRoute",
			toNamespace:   "ns2",
			toGroup:       "",
			toKind:        "Service",
			toName:        "svc1",
			expected:      false,
		},
		{
			name:          "not allowed cross-namespace - from namespace mismatch",
			fromNamespace: "ns_other",
			fromGroup:     gatewayv1.GroupName,
			fromKind:      "HTTPRoute",
			toNamespace:   "ns2",
			toGroup:       "",
			toKind:        "Service",
			toName:        "svc1",
			grants: []*gatewayv1beta1.ReferenceGrant{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "rg1", Namespace: "ns2"},
					Spec: gatewayv1beta1.ReferenceGrantSpec{
						From: []gatewayv1beta1.ReferenceGrantFrom{
							{
								Namespace: "ns1",
								Group:     gatewayv1.Group(gatewayv1.GroupName),
								Kind:      "HTTPRoute",
							},
						},
						To: []gatewayv1beta1.ReferenceGrantTo{
							{
								Group: "",
								Kind:  "Service",
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name:          "not allowed cross-namespace - from group mismatch",
			fromNamespace: "ns1",
			fromGroup:     "other.group",
			fromKind:      "HTTPRoute",
			toNamespace:   "ns2",
			toGroup:       "",
			toKind:        "Service",
			toName:        "svc1",
			grants: []*gatewayv1beta1.ReferenceGrant{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "rg1", Namespace: "ns2"},
					Spec: gatewayv1beta1.ReferenceGrantSpec{
						From: []gatewayv1beta1.ReferenceGrantFrom{
							{
								Namespace: "ns1",
								Group:     gatewayv1.Group(gatewayv1.GroupName),
								Kind:      "HTTPRoute",
							},
						},
						To: []gatewayv1beta1.ReferenceGrantTo{
							{
								Group: "",
								Kind:  "Service",
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name:          "not allowed cross-namespace - from kind mismatch",
			fromNamespace: "ns1",
			fromGroup:     gatewayv1.GroupName,
			fromKind:      "OtherRoute",
			toNamespace:   "ns2",
			toGroup:       "",
			toKind:        "Service",
			toName:        "svc1",
			grants: []*gatewayv1beta1.ReferenceGrant{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "rg1", Namespace: "ns2"},
					Spec: gatewayv1beta1.ReferenceGrantSpec{
						From: []gatewayv1beta1.ReferenceGrantFrom{
							{
								Namespace: "ns1",
								Group:     gatewayv1.Group(gatewayv1.GroupName),
								Kind:      "HTTPRoute",
							},
						},
						To: []gatewayv1beta1.ReferenceGrantTo{
							{
								Group: "",
								Kind:  "Service",
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name:          "not allowed cross-namespace - to group mismatch",
			fromNamespace: "ns1",
			fromGroup:     gatewayv1.GroupName,
			fromKind:      "HTTPRoute",
			toNamespace:   "ns2",
			toGroup:       "other.group",
			toKind:        "Service",
			toName:        "svc1",
			grants: []*gatewayv1beta1.ReferenceGrant{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "rg1", Namespace: "ns2"},
					Spec: gatewayv1beta1.ReferenceGrantSpec{
						From: []gatewayv1beta1.ReferenceGrantFrom{
							{
								Namespace: "ns1",
								Group:     gatewayv1.Group(gatewayv1.GroupName),
								Kind:      "HTTPRoute",
							},
						},
						To: []gatewayv1beta1.ReferenceGrantTo{
							{
								Group: "",
								Kind:  "Service",
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name:          "not allowed cross-namespace - to kind mismatch",
			fromNamespace: "ns1",
			fromGroup:     gatewayv1.GroupName,
			fromKind:      "HTTPRoute",
			toNamespace:   "ns2",
			toGroup:       "",
			toKind:        "OtherResource",
			toName:        "svc1",
			grants: []*gatewayv1beta1.ReferenceGrant{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "rg1", Namespace: "ns2"},
					Spec: gatewayv1beta1.ReferenceGrantSpec{
						From: []gatewayv1beta1.ReferenceGrantFrom{
							{
								Namespace: "ns1",
								Group:     gatewayv1.Group(gatewayv1.GroupName),
								Kind:      "HTTPRoute",
							},
						},
						To: []gatewayv1beta1.ReferenceGrantTo{
							{
								Group: "",
								Kind:  "Service",
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name:          "not allowed cross-namespace - to name mismatch",
			fromNamespace: "ns1",
			fromGroup:     gatewayv1.GroupName,
			fromKind:      "HTTPRoute",
			toNamespace:   "ns2",
			toGroup:       "",
			toKind:        "Service",
			toName:        "svc_other",
			grants: []*gatewayv1beta1.ReferenceGrant{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "rg1", Namespace: "ns2"},
					Spec: gatewayv1beta1.ReferenceGrantSpec{
						From: []gatewayv1beta1.ReferenceGrantFrom{
							{
								Namespace: "ns1",
								Group:     gatewayv1.Group(gatewayv1.GroupName),
								Kind:      "HTTPRoute",
							},
						},
						To: []gatewayv1beta1.ReferenceGrantTo{
							{
								Group: "",
								Kind:  "Service",
								Name:  ptr.To(gatewayv1.ObjectName("svc1")),
							},
						},
					},
				},
			},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			for _, g := range tc.grants {
				objs = append(objs, g)
			}
			fakeClient := gatewayclient.NewClientset(objs...)
			informerFactory := gatewayinformers.NewSharedInformerFactory(fakeClient, 0)
			lister := informerFactory.Gateway().V1beta1().ReferenceGrants().Lister()

			// Populate cache
			for _, g := range tc.grants {
				_ = informerFactory.Gateway().V1beta1().ReferenceGrants().Informer().GetIndexer().Add(g)
			}

			got := AllowedByReferenceGrant(
				tc.fromNamespace, tc.fromGroup, tc.fromKind,
				tc.toNamespace, tc.toGroup, tc.toKind, tc.toName,
				lister,
			)

			if got != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}
