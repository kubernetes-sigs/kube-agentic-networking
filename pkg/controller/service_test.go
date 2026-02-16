/*
Copyright 2025 The Kubernetes Authors.

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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	gatewaylisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"
	gatewaylistersv1beta1 "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1beta1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticlisters "sigs.k8s.io/kube-agentic-networking/k8s/client/listers/api/v0alpha0"
)

// Test helper: build a minimal Controller that has only the dependencies needed for enqueueGatewaysForService.
func testControllerForEnqueueGatewaysForService(
	httpRouteIndexer cache.Indexer,
	referenceGrantIndexer cache.Indexer,
	backendIndexer cache.Indexer,
) *Controller {
	return &Controller{
		gateway: gatewayResources{
			httprouteLister:      gatewaylisters.NewHTTPRouteLister(httpRouteIndexer),
			referenceGrantLister: gatewaylistersv1beta1.NewReferenceGrantLister(referenceGrantIndexer),
		},
		agentic: agenticNetResources{
			backendLister: agenticlisters.NewXBackendLister(backendIndexer),
		},
		gatewayqueue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "gateway"},
		),
	}
}

// drainGatewayQueue returns all keys that were added to the gateway queue.
func drainGatewayQueue(c *Controller) []string {
	var keys []string
	for c.gatewayqueue.Len() > 0 {
		key, shutdown := c.gatewayqueue.Get()
		if shutdown {
			break
		}
		keys = append(keys, key)
		c.gatewayqueue.Done(key)
	}
	return keys
}

func TestEnqueueGatewaysForService_DirectHTTPRouteRef(t *testing.T) {
	ns := "default"
	svcName := "my-svc"
	gwName := "my-gateway"

	httpRouteIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	refGrantIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	backendIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route1", Namespace: ns},
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
									Name: gatewayv1.ObjectName(svcName),
								},
							},
						},
					},
				},
			},
		},
	}
	_ = httpRouteIndexer.Add(route)

	c := testControllerForEnqueueGatewaysForService(httpRouteIndexer, refGrantIndexer, backendIndexer)
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: svcName, Namespace: ns},
	}

	c.enqueueGatewaysForService(svc)
	keys := drainGatewayQueue(c)

	if len(keys) != 1 || keys[0] != ns+"/"+gwName {
		t.Errorf("expected one gateway key %q, got %v", ns+"/"+gwName, keys)
	}
}

func TestEnqueueGatewaysForService_ViaXBackend(t *testing.T) {
	ns := "default"
	svcName := "my-svc"
	gwName := "my-gateway"

	httpRouteIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	refGrantIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	backendIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	backend := &agenticv0alpha0.XBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "my-backend", Namespace: ns},
		Spec: agenticv0alpha0.BackendSpec{
			MCP: agenticv0alpha0.MCPBackend{
				ServiceName: ptr.To(svcName),
				Port:        3000,
			},
		},
	}
	_ = backendIndexer.Add(backend)

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route1", Namespace: ns},
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
									Name:  gatewayv1.ObjectName("my-backend"),
									Group: ptr.To(gatewayv1.Group(agenticv0alpha0.GroupName)),
									Kind:  ptr.To(gatewayv1.Kind("XBackend")),
								},
							},
						},
					},
				},
			},
		},
	}
	_ = httpRouteIndexer.Add(route)

	c := testControllerForEnqueueGatewaysForService(httpRouteIndexer, refGrantIndexer, backendIndexer)
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: svcName, Namespace: ns},
	}

	c.enqueueGatewaysForService(svc)
	keys := drainGatewayQueue(c)

	if len(keys) != 1 || keys[0] != ns+"/"+gwName {
		t.Errorf("expected one gateway key %q (via XBackend), got %v", ns+"/"+gwName, keys)
	}
}

func TestEnqueueGatewaysForService_NoRefs_EnqueuesNothing(t *testing.T) {
	ns := "default"
	httpRouteIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	refGrantIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	backendIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	c := testControllerForEnqueueGatewaysForService(httpRouteIndexer, refGrantIndexer, backendIndexer)
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "orphan-svc", Namespace: ns},
	}

	c.enqueueGatewaysForService(svc)
	keys := drainGatewayQueue(c)

	if len(keys) != 0 {
		t.Errorf("expected no gateway keys when no routes/backends reference the service, got %v", keys)
	}
}

func TestEnqueueGatewaysForService_SkipsXBackendRefInDirectPath(t *testing.T) {
	ns := "default"
	svcName := "my-svc"
	gwName := "my-gateway"

	httpRouteIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	refGrantIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	backendIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	// Route that references an XBackend named like the service.
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route1", Namespace: ns},
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
									Name:  gatewayv1.ObjectName(svcName),
									Group: ptr.To(gatewayv1.Group(agenticv0alpha0.GroupName)),
									Kind:  ptr.To(gatewayv1.Kind("XBackend")),
								},
							},
						},
					},
				},
			},
		},
	}
	_ = httpRouteIndexer.Add(route)

	c := testControllerForEnqueueGatewaysForService(httpRouteIndexer, refGrantIndexer, backendIndexer)
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: svcName, Namespace: ns},
	}

	c.enqueueGatewaysForServiceDirectHTTPRouteRefs(svc)
	keys := drainGatewayQueue(c)

	if len(keys) != 0 {
		t.Errorf("expected no gateway keys from direct path when route references XBackend with same name, got %v", keys)
	}
}

func TestEnqueueGatewaysForService_CrossNamespaceRef_RequiresReferenceGrant(t *testing.T) {
	routeNS := "foo"
	backendNS := "bar"
	svcName := "bar-svc"
	gwName := "my-gateway"

	httpRouteIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	refGrantIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	backendIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	// HTTPRoute in foo references Service bar-svc in bar.
	route := &gatewayv1.HTTPRoute{
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
									Name:      gatewayv1.ObjectName(svcName),
									Namespace: ptr.To(gatewayv1.Namespace(backendNS)),
								},
							},
						},
					},
				},
			},
		},
	}
	_ = httpRouteIndexer.Add(route)

	// ReferenceGrant in bar allowing HTTPRoutes from foo to reference Services.
	refGrant := &gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-foo", Namespace: backendNS},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{
				{
					Group:     gatewayv1beta1.Group(gatewayv1.GroupName),
					Kind:      gatewayv1beta1.Kind("HTTPRoute"),
					Namespace: gatewayv1beta1.Namespace(routeNS),
				},
			},
			To: []gatewayv1beta1.ReferenceGrantTo{
				{Group: gatewayv1beta1.Group(""), Kind: gatewayv1beta1.Kind("Service")},
			},
		},
	}
	_ = refGrantIndexer.Add(refGrant)

	c := testControllerForEnqueueGatewaysForService(httpRouteIndexer, refGrantIndexer, backendIndexer)
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: svcName, Namespace: backendNS},
	}

	c.enqueueGatewaysForService(svc)
	keys := drainGatewayQueue(c)

	if len(keys) != 1 || keys[0] != routeNS+"/"+gwName {
		t.Errorf("expected one gateway key %q when ReferenceGrant allows cross-namespace ref, got %v", routeNS+"/"+gwName, keys)
	}
}

func TestEnqueueGatewaysForService_CrossNamespaceRef_WithoutReferenceGrant_EnqueuesNothing(t *testing.T) {
	routeNS := "foo"
	backendNS := "bar"
	svcName := "bar-svc"

	httpRouteIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	refGrantIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	backendIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	// HTTPRoute in foo references Service in bar, but no ReferenceGrant.
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route1", Namespace: routeNS},
		Spec: gatewayv1.HTTPRouteSpec{
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name:      gatewayv1.ObjectName(svcName),
									Namespace: ptr.To(gatewayv1.Namespace(backendNS)),
								},
							},
						},
					},
				},
			},
		},
	}
	_ = httpRouteIndexer.Add(route)

	c := testControllerForEnqueueGatewaysForService(httpRouteIndexer, refGrantIndexer, backendIndexer)
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: svcName, Namespace: backendNS},
	}

	c.enqueueGatewaysForServiceDirectHTTPRouteRefs(svc)
	keys := drainGatewayQueue(c)

	if len(keys) != 0 {
		t.Errorf("expected no gateway keys when cross-namespace ref has no ReferenceGrant, got %v", keys)
	}
}
