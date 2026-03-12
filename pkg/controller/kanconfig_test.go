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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewaylisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticfake "sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned/fake"
	agenticlisters "sigs.k8s.io/kube-agentic-networking/k8s/client/listers/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

// --------------------------------------------------------------------------
// mergeStringSlice
// --------------------------------------------------------------------------

// makeControllerForKANConfigTest builds a minimal *Controller suitable for
// testing applyKANConfig. It pre-populates the GatewayClass lister so that
// ReferencedBy computation works; gwcNames should list every GatewayClass that
// references kanConfigName via parametersRef.
func makeControllerForKANConfigTest(fakeClient *agenticfake.Clientset, kanConfigName string, gwcNames ...string) *Controller {
	gwcIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, name := range gwcNames {
		_ = gwcIndexer.Add(&gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: gatewayv1.GatewayClassSpec{
				ParametersRef: &gatewayv1.ParametersReference{
					Group: "agentic.prototype.x-k8s.io",
					Kind:  "KANConfig",
					Name:  kanConfigName,
				},
			},
		})
	}
	c := &Controller{
		workerCount: 2,
		gateway: gatewayResources{
			gatewayClassLister: gatewaylisters.NewGatewayClassLister(gwcIndexer),
		},
		agentic: agenticNetResources{
			client: fakeClient,
		},
	}
	c.config.Store(&controllerConfig{})
	return c
}

func TestMergeStringSlice(t *testing.T) {
	t.Run("empty slice gets value appended", func(t *testing.T) {
		result := mergeStringSlice(nil, "a")
		if len(result) != 1 || result[0] != "a" {
			t.Errorf("expected [a], got %v", result)
		}
	})

	t.Run("existing value is not duplicated", func(t *testing.T) {
		result := mergeStringSlice([]string{"a", "b"}, "a")
		if len(result) != 2 {
			t.Errorf("expected length 2 (no duplicate), got %v", result)
		}
	})

	t.Run("new value is appended", func(t *testing.T) {
		result := mergeStringSlice([]string{"a"}, "b")
		if len(result) != 2 || result[1] != "b" {
			t.Errorf("expected [a b], got %v", result)
		}
	})
}

// --------------------------------------------------------------------------
// applyKANConfig — controller fields
// --------------------------------------------------------------------------

func TestApplyKANConfig_ControllerFields(t *testing.T) {
	cfg := &agenticv0alpha0.KANConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "my-config", Generation: 3},
		Spec: agenticv0alpha0.KANConfigSpec{
			ProxyImage:                 "envoyproxy/envoy:v1.36-latest",
			WorkerCount:                8,
			AgenticIdentityTrustDomain: "example.com",
		},
	}

	fakeClient := agenticfake.NewSimpleClientset(cfg)
	c := makeControllerForKANConfigTest(fakeClient, "my-config", "my-gatewayclass")

	c.applyKANConfig(cfg, "my-gatewayclass")

	loaded := c.config.Load()
	if loaded.envoyImage != "envoyproxy/envoy:v1.36-latest" {
		t.Errorf("envoyImage not applied, got %q", loaded.envoyImage)
	}
	if loaded.agenticIdentityTrustDomain != "example.com" {
		t.Errorf("agenticIdentityTrustDomain not applied, got %q", loaded.agenticIdentityTrustDomain)
	}
	if c.workerCount != 8 {
		t.Errorf("workerCount not applied, got %d", c.workerCount)
	}
}

func TestApplyKANConfig_ZeroWorkerCountKeepsDefault(t *testing.T) {
	cfg := &agenticv0alpha0.KANConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "my-config"},
		Spec: agenticv0alpha0.KANConfigSpec{
			ProxyImage:  "envoyproxy/envoy:v1.36-latest",
			WorkerCount: 0, // unset — should not override default
		},
	}

	fakeClient := agenticfake.NewSimpleClientset(cfg)
	c := makeControllerForKANConfigTest(fakeClient, "my-config", "my-gatewayclass")

	c.applyKANConfig(cfg, "my-gatewayclass")

	if c.workerCount != 2 {
		t.Errorf("expected workerCount to remain 2, got %d", c.workerCount)
	}
}

// --------------------------------------------------------------------------
// applyKANConfig — KANConfig status written back
// --------------------------------------------------------------------------

func TestApplyKANConfig_StatusWriteback(t *testing.T) {
	cfg := &agenticv0alpha0.KANConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "my-config", Generation: 5},
		Spec: agenticv0alpha0.KANConfigSpec{
			ProxyImage:  "envoyproxy/envoy:v1.36-latest",
			WorkerCount: 4,
		},
	}

	fakeClient := agenticfake.NewSimpleClientset(cfg)
	c := makeControllerForKANConfigTest(fakeClient, "my-config", "gw-class-1")

	c.applyKANConfig(cfg, "gw-class-1")

	// Fetch the object as it was submitted to the fake API server.
	actions := fakeClient.Actions()
	var updatedCfg *agenticv0alpha0.KANConfig
	for i := len(actions) - 1; i >= 0; i-- {
		if ua, ok := actions[i].(interface {
			GetObject() runtime.Object
		}); ok {
			if kc, ok := ua.GetObject().(*agenticv0alpha0.KANConfig); ok {
				updatedCfg = kc
				break
			}
		}
	}
	if updatedCfg == nil {
		t.Fatal("no UpdateStatus action recorded for KANConfig")
	}

	if updatedCfg.Status.ObservedGeneration != 5 {
		t.Errorf("ObservedGeneration: want 5, got %d", updatedCfg.Status.ObservedGeneration)
	}
	if updatedCfg.Status.ActiveWorkerCount != 4 {
		t.Errorf("ActiveWorkerCount: want 4, got %d", updatedCfg.Status.ActiveWorkerCount)
	}
	if len(updatedCfg.Status.ReferencedBy) != 1 || updatedCfg.Status.ReferencedBy[0] != "gw-class-1" {
		t.Errorf("ReferencedBy: want [gw-class-1], got %v", updatedCfg.Status.ReferencedBy)
	}

	var acceptedCond, appliedCond *metav1.Condition
	for i := range updatedCfg.Status.Conditions {
		switch updatedCfg.Status.Conditions[i].Type {
		case "Accepted":
			c := updatedCfg.Status.Conditions[i]
			acceptedCond = &c
		case "Applied":
			c := updatedCfg.Status.Conditions[i]
			appliedCond = &c
		}
	}
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Accepted=True condition, got %v", acceptedCond)
	}
	if appliedCond == nil || appliedCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Applied=True condition, got %v", appliedCond)
	}
}

func TestApplyKANConfig_ReferencedByIsIdempotent(t *testing.T) {
	cfg := &agenticv0alpha0.KANConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "my-config"},
		Spec:       agenticv0alpha0.KANConfigSpec{ProxyImage: "envoyproxy/envoy:v1.36-latest"},
	}

	fakeClient := agenticfake.NewSimpleClientset(cfg)
	// One GatewayClass references "my-config" — calling applyKANConfig twice must
	// still produce ReferencedBy of length 1 (computed fresh from lister each call).
	c := makeControllerForKANConfigTest(fakeClient, "my-config", "gw-class-1")

	c.applyKANConfig(cfg, "gw-class-1")
	c.applyKANConfig(cfg, "gw-class-1") // second call — must not duplicate

	actions := fakeClient.Actions()
	var updatedCfg *agenticv0alpha0.KANConfig
	for i := len(actions) - 1; i >= 0; i-- {
		if ua, ok := actions[i].(interface {
			GetObject() runtime.Object
		}); ok {
			if kc, ok := ua.GetObject().(*agenticv0alpha0.KANConfig); ok {
				updatedCfg = kc
				break
			}
		}
	}
	if updatedCfg == nil {
		t.Fatal("no action recorded")
	}
	if len(updatedCfg.Status.ReferencedBy) != 1 {
		t.Errorf("expected ReferencedBy length 1 (idempotent), got %v", updatedCfg.Status.ReferencedBy)
	}
}

// --------------------------------------------------------------------------
// isGatewayOwnedByController
// --------------------------------------------------------------------------

func TestIsGatewayOwnedByController(t *testing.T) {
	gwcIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})

	ownedGwc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "owned-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: constants.ControllerName},
	}
	foreignGwc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "foreign-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "other.controller/name"},
	}
	for _, obj := range []runtime.Object{ownedGwc, foreignGwc} {
		if err := gwcIndexer.Add(obj); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
	}

	c := &Controller{
		gateway: gatewayResources{
			gatewayClassLister: gatewaylisters.NewGatewayClassLister(gwcIndexer),
		},
	}

	t.Run("gateway using our GatewayClass returns true", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-1"},
			Spec:       gatewayv1.GatewaySpec{GatewayClassName: "owned-class"},
		}
		if !c.isGatewayOwnedByController(gw) {
			t.Error("expected true for gateway using our GatewayClass")
		}
	})

	t.Run("gateway using foreign GatewayClass returns false", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-2"},
			Spec:       gatewayv1.GatewaySpec{GatewayClassName: "foreign-class"},
		}
		if c.isGatewayOwnedByController(gw) {
			t.Error("expected false for gateway using a foreign GatewayClass")
		}
	})

	t.Run("gateway referencing non-existent GatewayClass returns false", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-3"},
			Spec:       gatewayv1.GatewaySpec{GatewayClassName: "does-not-exist"},
		}
		if c.isGatewayOwnedByController(gw) {
			t.Error("expected false for gateway referencing a missing GatewayClass")
		}
	})
}

// --------------------------------------------------------------------------
// applyKANConfig — empty ProxyImage does not clear envoyImage
// --------------------------------------------------------------------------

func TestApplyKANConfig_EmptyProxyImageIgnored(t *testing.T) {
	cfg := &agenticv0alpha0.KANConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "my-config"},
		Spec:       agenticv0alpha0.KANConfigSpec{ProxyImage: ""}, // intentionally empty
	}

	fakeClient := agenticfake.NewSimpleClientset(cfg)
	c := makeControllerForKANConfigTest(fakeClient, "my-config", "gw-class-1")
	c.config.Store(&controllerConfig{envoyImage: "previous/image:latest"})

	c.applyKANConfig(cfg, "gw-class-1")

	if c.config.Load().envoyImage != "previous/image:latest" {
		t.Errorf("expected envoyImage to be unchanged, got %q", c.config.Load().envoyImage)
	}
}

// --------------------------------------------------------------------------
// KANConfig lister helper
// --------------------------------------------------------------------------

func newKANConfigListerWithObjects(objs ...*agenticv0alpha0.KANConfig) agenticlisters.KANConfigLister {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	for _, o := range objs {
		if err := indexer.Add(o); err != nil {
			panic(err)
		}
	}
	return agenticlisters.NewKANConfigLister(indexer)
}
