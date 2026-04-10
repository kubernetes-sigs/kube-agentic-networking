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
	"context"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
	gatewaylisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticlisters "sigs.k8s.io/kube-agentic-networking/k8s/client/listers/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
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

func TestHasAccessPoliciesTargetingGateway(t *testing.T) {
	gwNamespace := "default"
	gwName := "my-gateway"

	t.Run("no policies in namespace", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		c := &Controller{
			agentic: agenticNetResources{
				accessPolicyLister: agenticlisters.NewXAccessPolicyLister(indexer),
			},
		}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: gwName},
		}
		if hasAccessPoliciesTargetingGateway(c, gw) {
			t.Error("expected false when no AccessPolicies exist in namespace")
		}
	})

	t.Run("policy targets different gateway", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		policy := &agenticv0alpha0.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: "policy-1"},
			Spec: agenticv0alpha0.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
					{
						LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
							Group: gatewayv1.GroupName, Kind: "Gateway", Name: gatewayv1.ObjectName("other-gateway"),
						},
					},
				},
				Rules: []agenticv0alpha0.AccessRule{{Name: "r1", Source: agenticv0alpha0.Source{Type: agenticv0alpha0.AuthorizationSourceTypeSPIFFE}}},
			},
		}
		if err := indexer.Add(policy); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
		c := &Controller{
			agentic: agenticNetResources{
				accessPolicyLister: agenticlisters.NewXAccessPolicyLister(indexer),
			},
		}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: gwName},
		}
		if hasAccessPoliciesTargetingGateway(c, gw) {
			t.Error("expected false when policy targets a different gateway")
		}
	})

	t.Run("policy targets this gateway", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		policy := &agenticv0alpha0.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: "policy-1"},
			Spec: agenticv0alpha0.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
					{
						LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
							Group: gatewayv1.GroupName, Kind: "Gateway", Name: gatewayv1.ObjectName(gwName),
						},
					},
				},
				Rules: []agenticv0alpha0.AccessRule{{Name: "r1", Source: agenticv0alpha0.Source{Type: agenticv0alpha0.AuthorizationSourceTypeSPIFFE}}},
			},
		}
		if err := indexer.Add(policy); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
		c := &Controller{
			agentic: agenticNetResources{
				accessPolicyLister: agenticlisters.NewXAccessPolicyLister(indexer),
			},
		}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: gwName},
		}
		if !hasAccessPoliciesTargetingGateway(c, gw) {
			t.Error("expected true when policy targets this gateway")
		}
	})

	t.Run("policy with XBackend targetRef only", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		policy := &agenticv0alpha0.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: "policy-1"},
			Spec: agenticv0alpha0.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
					{
						LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
							Group: agenticv0alpha0.GroupName, Kind: "XBackend", Name: gatewayv1.ObjectName("some-backend"),
						},
					},
				},
				Rules: []agenticv0alpha0.AccessRule{{Name: "r1", Source: agenticv0alpha0.Source{Type: agenticv0alpha0.AuthorizationSourceTypeSPIFFE}}},
			},
		}
		if err := indexer.Add(policy); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
		c := &Controller{
			agentic: agenticNetResources{
				accessPolicyLister: agenticlisters.NewXAccessPolicyLister(indexer),
			},
		}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: gwName},
		}
		if hasAccessPoliciesTargetingGateway(c, gw) {
			t.Error("expected false when policy only targets XBackend, not Gateway")
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

type fakeQueue struct {
	workqueue.TypedRateLimitingInterface[string]
	addedAfter string
	delay      time.Duration
}

func (q *fakeQueue) AddAfter(item string, duration time.Duration) {
	q.addedAfter = item
	q.delay = duration
}

func (q *fakeQueue) Len() int {
	if q.addedAfter != "" {
		return 1
	}
	return 0
}

func TestSyncGateway_EnsureProxyExistError(t *testing.T) {
	gwNamespace := "default"
	gwName := "my-gateway"
	gwcName := "my-class"

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: gwName, Finalizers: []string{constants.GatewayFinalizer}},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(gwcName),
		},
	}

	gwc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: gwcName},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: constants.ControllerName,
		},
	}

	gwIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	if err := gwIndexer.Add(gw); err != nil {
		t.Fatalf("indexer.Add: %v", err)
	}

	gwcIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if err := gwcIndexer.Add(gwc); err != nil {
		t.Fatalf("indexer.Add: %v", err)
	}

	fakeK8sClient := fake.NewClientset()
	// Force error on SA creation
	fakeK8sClient.PrependReactor("create", "serviceaccounts", func(_ k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, fmt.Errorf("forced error")
	})

	fakeGwClient := gatewayfake.NewClientset(gw)

	queue := &fakeQueue{}

	c := &Controller{
		gateway: gatewayResources{
			gatewayLister:      gatewaylisters.NewGatewayLister(gwIndexer),
			gatewayClassLister: gatewaylisters.NewGatewayClassLister(gwcIndexer),
			client:             fakeGwClient,
		},
		core: coreResources{
			client: fakeK8sClient,
		},
		gatewayqueue: queue,
	}

	err := c.syncGateway(context.Background(), gwNamespace+"/"+gwName)
	if err != nil {
		t.Fatalf("syncGateway returned error: %v", err)
	}

	// Verify status was updated with error!
	actions := fakeGwClient.Actions()
	foundUpdateStatus := false
	for _, action := range actions {
		if action.GetVerb() == "update" && action.GetSubresource() == "status" {
			foundUpdateStatus = true
			break
		}
	}
	if !foundUpdateStatus {
		t.Error("expected gateway status update action, but none found")
	}

	// Verify item was requeued
	if queue.Len() != 1 {
		t.Errorf("expected 1 item in queue, got %d", queue.Len())
	}
}
