package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayclientfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
	gatewaylisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"
)

func TestEnqueueGatewaysForHTTPRoute(t *testing.T) {
	c := &Controller{
		gatewayqueue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "gateway"},
		),
	}

	namespace := gatewayv1.Namespace("test-ns")
	group := gatewayv1.Group(gatewayv1.GroupName)
	kind := gatewayv1.Kind("Gateway")

	refs := []gatewayv1.ParentReference{
		{
			Namespace: &namespace,
			Name:      "gw-1",
			Group:     &group,
			Kind:      &kind,
		},
		{
			Name: "gw-2", // uses local namespace
		},
	}

	c.enqueueGatewaysForHTTPRoute(refs, "local-ns")

	expectedKeys := map[string]bool{
		"test-ns/gw-1":  true,
		"local-ns/gw-2": true,
	}

	for i := 0; i < len(expectedKeys); i++ {
		key, shutdown := c.gatewayqueue.Get()
		if shutdown {
			t.Fatal("queue unexpectedly shut down")
		}
		if !expectedKeys[key] {
			t.Errorf("unexpected key in queue: %s", key)
		}
		c.gatewayqueue.Done(key)
	}
}

func TestOnHTTPRouteAddUpdateDelete(t *testing.T) {
	c := &Controller{
		gatewayqueue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "gateway"},
		),
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "route-1",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name: "gw-1",
					},
				},
			},
		},
	}

	c.onHTTPRouteAdd(route)
	if c.gatewayqueue.Len() != 1 {
		t.Errorf("expected queue length 1, got %d", c.gatewayqueue.Len())
	}
	key, _ := c.gatewayqueue.Get()
	c.gatewayqueue.Done(key)

	newRoute := route.DeepCopy()
	newRoute.Generation = 2
	newRoute.Spec.ParentRefs = append(newRoute.Spec.ParentRefs, gatewayv1.ParentReference{
		Name: "gw-2",
	})

	c.onHTTPRouteUpdate(route, newRoute)
	if c.gatewayqueue.Len() != 2 {
		t.Errorf("expected queue length 2 after update, got %d", c.gatewayqueue.Len())
	}
	key1, _ := c.gatewayqueue.Get()
	key2, _ := c.gatewayqueue.Get()
	c.gatewayqueue.Done(key1)
	c.gatewayqueue.Done(key2)

	// test delete
	c.onHTTPRouteDelete(route)
	if c.gatewayqueue.Len() != 1 {
		t.Errorf("expected queue length 1 after delete, got %d", c.gatewayqueue.Len())
	}
}

func TestUpdateRouteStatuses(t *testing.T) {
	routeNS := "default"
	routeName := "my-route"

	baseRoute := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      routeName,
			Namespace: routeNS,
		},
		Status: gatewayv1.HTTPRouteStatus{
			RouteStatus: gatewayv1.RouteStatus{
				Parents: []gatewayv1.RouteParentStatus{},
			},
		},
	}

	t.Run("route not found", func(t *testing.T) {
		client := gatewayclientfake.NewClientset()
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		lister := gatewaylisters.NewHTTPRouteLister(indexer)

		c := &Controller{
			gateway: gatewayResources{
				client:          client,
				httprouteLister: lister,
			},
		}

		statuses := map[types.NamespacedName][]gatewayv1.RouteParentStatus{
			{Namespace: routeNS, Name: routeName}: {},
		}
		err := c.updateRouteStatuses(context.Background(), statuses, nil)
		if err != nil {
			t.Fatalf("expected no error when route is not found, got %v", err)
		}
	})

	t.Run("status unchanged avoids update", func(t *testing.T) {
		client := gatewayclientfake.NewClientset(baseRoute)
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		indexer.Add(baseRoute)
		lister := gatewaylisters.NewHTTPRouteLister(indexer)

		c := &Controller{
			gateway: gatewayResources{
				client:          client,
				httprouteLister: lister,
			},
		}

		// Empty statuses matches baseRoute.Status.Parents
		statuses := map[types.NamespacedName][]gatewayv1.RouteParentStatus{
			{Namespace: routeNS, Name: routeName}: {},
		}
		err := c.updateRouteStatuses(context.Background(), statuses, nil)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Client should not have recorded any actions because the status was unchanged
		actions := client.Actions()
		if len(actions) != 0 {
			t.Fatalf("expected 0 actions due to short-circuit, got %d", len(actions))
		}
	})

	t.Run("status changed performs update", func(t *testing.T) {
		client := gatewayclientfake.NewClientset(baseRoute)
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		indexer.Add(baseRoute)
		lister := gatewaylisters.NewHTTPRouteLister(indexer)

		c := &Controller{
			gateway: gatewayResources{
				client:          client,
				httprouteLister: lister,
			},
		}

		newStatus := []gatewayv1.RouteParentStatus{
			{
				ParentRef: gatewayv1.ParentReference{Name: "some-gw"},
			},
		}
		statuses := map[types.NamespacedName][]gatewayv1.RouteParentStatus{
			{Namespace: routeNS, Name: routeName}: newStatus,
		}
		err := c.updateRouteStatuses(context.Background(), statuses, nil)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		actions := client.Actions()
		if len(actions) != 1 {
			t.Fatalf("expected 1 action (update status), got %d", len(actions))
		}
		if actions[0].GetVerb() != "update" || actions[0].GetSubresource() != "status" {
			t.Errorf("expected update status action, got %v", actions[0])
		}
	})
}
