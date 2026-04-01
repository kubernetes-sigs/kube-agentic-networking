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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewaylisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"
)

func TestHasGatewaysReferencingClass(t *testing.T) {
	className := "my-gateway-class"

	t.Run("no gateways", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		c := &Controller{
			gateway: gatewayResources{
				gatewayLister: gatewaylisters.NewGatewayLister(indexer),
			},
		}
		if hasGatewaysReferencingClass(c, className) {
			t.Error("expected false when no Gateways exist")
		}
	})

	t.Run("gateway references different class", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "gw-1", Namespace: "default"},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: gatewayv1.ObjectName("other-class"),
				Listeners:        []gatewayv1.Listener{{Name: "l1", Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
			},
		}
		if err := indexer.Add(gw); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
		c := &Controller{
			gateway: gatewayResources{
				gatewayLister: gatewaylisters.NewGatewayLister(indexer),
			},
		}
		if hasGatewaysReferencingClass(c, className) {
			t.Error("expected false when Gateway references a different class")
		}
	})

	t.Run("gateway references this class", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "gw-1", Namespace: "default"},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: gatewayv1.ObjectName(className),
				Listeners:        []gatewayv1.Listener{{Name: "l1", Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
			},
		}
		if err := indexer.Add(gw); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
		c := &Controller{
			gateway: gatewayResources{
				gatewayLister: gatewaylisters.NewGatewayLister(indexer),
			},
		}
		if !hasGatewaysReferencingClass(c, className) {
			t.Error("expected true when Gateway references this class")
		}
	})

	t.Run("multiple gateways one references this class", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		for i, gwcName := range []string{"other-class", className, "another-class"} {
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw-" + string(rune('a'+i)), Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: gatewayv1.ObjectName(gwcName),
					Listeners:        []gatewayv1.Listener{{Name: "l1", Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
				},
			}
			if err := indexer.Add(gw); err != nil {
				t.Fatalf("indexer.Add: %v", err)
			}
		}
		c := &Controller{
			gateway: gatewayResources{
				gatewayLister: gatewaylisters.NewGatewayLister(indexer),
			},
		}
		if !hasGatewaysReferencingClass(c, className) {
			t.Error("expected true when one Gateway references this class")
		}
	})
}

func TestEnqueueGatewaysForClass(t *testing.T) {
	className := "my-gateway-class"

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	for i, gwcName := range []string{"other-class", className, "another-class"} {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "gw-" + string(rune('a'+i)), Namespace: "default"},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: gatewayv1.ObjectName(gwcName),
				Listeners:        []gatewayv1.Listener{{Name: "l1", Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
			},
		}
		if err := indexer.Add(gw); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
	}

	queue := workqueue.NewTypedRateLimitingQueueWithConfig(
		workqueue.DefaultTypedControllerRateLimiter[string](),
		workqueue.TypedRateLimitingQueueConfig[string]{Name: "gateway"},
	)

	c := &Controller{
		gateway: gatewayResources{
			gatewayLister: gatewaylisters.NewGatewayLister(indexer),
		},
		gatewayqueue: queue,
	}

	c.enqueueGatewaysForClass(className)

	if c.gatewayqueue.Len() != 1 {
		t.Fatalf("expected queue length 1, got %d", c.gatewayqueue.Len())
	}

	key, _ := c.gatewayqueue.Get()
	expectedKey := "default/gw-b"
	if key != expectedKey {
		t.Errorf("expected key %q, got %q", expectedKey, key)
	}
	c.gatewayqueue.Done(key)
}
