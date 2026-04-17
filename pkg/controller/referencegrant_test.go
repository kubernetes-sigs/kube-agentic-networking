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

package controller

import (
	"testing"

	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	gatewaylisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"
)

func testControllerForEnqueueGatewaysForReferenceGrant(
	httpRouteIndexer cache.Indexer,
	gatewayIndexer cache.Indexer,
) *Controller {
	return &Controller{
		gateway: gatewayResources{
			httprouteLister:  gatewaylisters.NewHTTPRouteLister(httpRouteIndexer),
			httprouteIndexer: httpRouteIndexer,
			gatewayLister:    gatewaylisters.NewGatewayLister(gatewayIndexer),
			gatewayIndexer:   gatewayIndexer,
		},
		gatewayqueue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "gateway"},
		),
	}
}

func TestEnqueueGatewaysForReferenceGrant_HTTPRouteRef(t *testing.T) {
	routeNS := "foo"
	backendNS := "bar"
	otherNS := "baz"
	gwName := "my-gateway"

	tests := []struct {
		name         string
		route        *gatewayv1.HTTPRoute
		expectedKeys []string
	}{
		{
			name: "route references backend in RG namespace",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route1", Namespace: routeNS},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: gatewayv1.ObjectName(gwName)},
						},
					},
					Rules: []gatewayv1.HTTPRouteRule{
						{
							BackendRefs: []gatewayv1.HTTPBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name:      "some-svc",
											Namespace: ptr.To(gatewayv1.Namespace(backendNS)),
										},
									},
								},
							},
						},
					},
				},
			},
			expectedKeys: []string{routeNS + "/" + gwName},
		},
		{
			name: "route does not reference backend in RG namespace",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route2", Namespace: routeNS},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: gatewayv1.ObjectName(gwName)},
						},
					},
					Rules: []gatewayv1.HTTPRouteRule{
						{
							BackendRefs: []gatewayv1.HTTPBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name:      "other-svc",
											Namespace: ptr.To(gatewayv1.Namespace(otherNS)),
										},
									},
								},
							},
						},
					},
				},
			},
			expectedKeys: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpRouteIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{HTTPRouteBackendRefNamespaceIndex: HTTPRouteBackendRefNamespaceIndexFunc})
			gatewayIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{GatewaySecretRefNamespaceIndex: GatewaySecretRefNamespaceIndexFunc})

			_ = httpRouteIndexer.Add(tt.route)

			c := testControllerForEnqueueGatewaysForReferenceGrant(httpRouteIndexer, gatewayIndexer)
			rg := &gatewayv1beta1.ReferenceGrant{
				ObjectMeta: metav1.ObjectMeta{Name: "allow-foo", Namespace: backendNS},
			}

			c.enqueueGatewaysForReferenceGrant(rg)
			keys := drainGatewayQueue(c)

			if len(keys) != len(tt.expectedKeys) {
				t.Fatalf("expected %d keys, got %v", len(tt.expectedKeys), keys)
			}
			for i, v := range keys {
				if v != tt.expectedKeys[i] {
					t.Errorf("expected key at index %d to be %q, got %q", i, tt.expectedKeys[i], v)
				}
			}
		})
	}
}

func TestEnqueueGatewaysForReferenceGrant_GatewaySecretRef(t *testing.T) {
	gwNS := "foo"
	secretNS := "bar"
	otherNS := "baz"
	gwName := "my-gateway"

	tests := []struct {
		name         string
		gateway      *gatewayv1.Gateway
		expectedKeys []string
	}{
		{
			name: "gateway references secret in RG namespace",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: gwName, Namespace: gwNS},
				Spec: gatewayv1.GatewaySpec{
					Listeners: []gatewayv1.Listener{
						{
							TLS: &gatewayv1.ListenerTLSConfig{
								CertificateRefs: []gatewayv1.SecretObjectReference{
									{
										Name:      "my-secret",
										Namespace: ptr.To(gatewayv1.Namespace(secretNS)),
									},
								},
							},
						},
					},
				},
			},
			expectedKeys: []string{gwNS + "/" + gwName},
		},
		{
			name: "gateway does not reference secret in RG namespace",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "other-gateway", Namespace: gwNS},
				Spec: gatewayv1.GatewaySpec{
					Listeners: []gatewayv1.Listener{
						{
							TLS: &gatewayv1.ListenerTLSConfig{
								CertificateRefs: []gatewayv1.SecretObjectReference{
									{
										Name:      "other-secret",
										Namespace: ptr.To(gatewayv1.Namespace(otherNS)),
									},
								},
							},
						},
					},
				},
			},
			expectedKeys: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpRouteIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{HTTPRouteBackendRefNamespaceIndex: HTTPRouteBackendRefNamespaceIndexFunc})
			gatewayIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{GatewaySecretRefNamespaceIndex: GatewaySecretRefNamespaceIndexFunc})

			_ = gatewayIndexer.Add(tt.gateway)

			c := testControllerForEnqueueGatewaysForReferenceGrant(httpRouteIndexer, gatewayIndexer)
			rg := &gatewayv1beta1.ReferenceGrant{
				ObjectMeta: metav1.ObjectMeta{Name: "allow-secret", Namespace: secretNS},
			}

			c.enqueueGatewaysForReferenceGrant(rg)
			keys := drainGatewayQueue(c)

			if len(keys) != len(tt.expectedKeys) {
				t.Fatalf("expected %d keys, got %v", len(tt.expectedKeys), keys)
			}
			for i, v := range keys {
				if v != tt.expectedKeys[i] {
					t.Errorf("expected key at index %d to be %q, got %q", i, tt.expectedKeys[i], v)
				}
			}
		})
	}
}
