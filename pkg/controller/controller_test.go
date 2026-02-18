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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewaylisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"
)

func TestHasHTTPRoutesReferencingGateway(t *testing.T) {
	gwNamespace := "default"
	gwName := "my-gateway"

	t.Run("no routes", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		c := &Controller{
			gateway: gatewayResources{
				httprouteLister: gatewaylisters.NewHTTPRouteLister(indexer),
			},
		}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: gwName},
		}
		if hasHTTPRoutesReferencingGateway(c, gw) {
			t.Error("expected false when no HTTPRoutes exist")
		}
	})

	t.Run("route with no parentRefs", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		route := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: "route-1"},
			Spec:       gatewayv1.HTTPRouteSpec{},
		}
		if err := indexer.Add(route); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
		c := &Controller{
			gateway: gatewayResources{
				httprouteLister: gatewaylisters.NewHTTPRouteLister(indexer),
			},
		}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: gwName},
		}
		if hasHTTPRoutesReferencingGateway(c, gw) {
			t.Error("expected false when route has no parentRefs")
		}
	})

	t.Run("route references different gateway", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		route := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: "route-1"},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{Name: gatewayv1.ObjectName("other-gateway")},
					},
				},
			},
		}
		if err := indexer.Add(route); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
		c := &Controller{
			gateway: gatewayResources{
				httprouteLister: gatewaylisters.NewHTTPRouteLister(indexer),
			},
		}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: gwName},
		}
		if hasHTTPRoutesReferencingGateway(c, gw) {
			t.Error("expected false when route references a different gateway")
		}
	})

	t.Run("route references this gateway (same namespace)", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		route := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: "route-1"},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{Name: gatewayv1.ObjectName(gwName)},
					},
				},
			},
		}
		if err := indexer.Add(route); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
		c := &Controller{
			gateway: gatewayResources{
				httprouteLister: gatewaylisters.NewHTTPRouteLister(indexer),
			},
		}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: gwName},
		}
		if !hasHTTPRoutesReferencingGateway(c, gw) {
			t.Error("expected true when route references this gateway in same namespace")
		}
	})

	t.Run("route in other namespace references this gateway via parentRef.Namespace", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		route := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns", Name: "route-1"},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name:      gatewayv1.ObjectName(gwName),
							Namespace: ptrGatewayNamespace(gwNamespace),
						},
					},
				},
			},
		}
		if err := indexer.Add(route); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
		c := &Controller{
			gateway: gatewayResources{
				httprouteLister: gatewaylisters.NewHTTPRouteLister(indexer),
			},
		}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: gwName},
		}
		if !hasHTTPRoutesReferencingGateway(c, gw) {
			t.Error("expected true when route in other namespace references this gateway via parentRef.Namespace")
		}
	})

	t.Run("route has wrong Group in parentRef", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		otherGroup := gatewayv1.Group("other.group")
		route := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: "route-1"},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Group: &otherGroup,
							Kind:  ptrGatewayKind("Gateway"),
							Name:  gatewayv1.ObjectName(gwName),
						},
					},
				},
			},
		}
		if err := indexer.Add(route); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
		c := &Controller{
			gateway: gatewayResources{
				httprouteLister: gatewaylisters.NewHTTPRouteLister(indexer),
			},
		}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: gwName},
		}
		if hasHTTPRoutesReferencingGateway(c, gw) {
			t.Error("expected false when parentRef has wrong Group")
		}
	})

	t.Run("multiple parentRefs one references this gateway", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		route := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: "route-1"},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{Name: gatewayv1.ObjectName("other-gateway")},
						{Name: gatewayv1.ObjectName(gwName)},
					},
				},
			},
		}
		if err := indexer.Add(route); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
		c := &Controller{
			gateway: gatewayResources{
				httprouteLister: gatewaylisters.NewHTTPRouteLister(indexer),
			},
		}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: gwName},
		}
		if !hasHTTPRoutesReferencingGateway(c, gw) {
			t.Error("expected true when one parentRef references this gateway")
		}
	})
}

func ptrGatewayNamespace(ns string) *gatewayv1.Namespace {
	n := gatewayv1.Namespace(ns)
	return &n
}

func ptrGatewayKind(kind string) *gatewayv1.Kind {
	k := gatewayv1.Kind(kind)
	return &k
}
