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
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	gatewayinformersv1beta1 "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions/apis/v1beta1"
)

func (c *Controller) setupReferenceGrantEventHandlers(referenceGrantInformer gatewayinformersv1beta1.ReferenceGrantInformer) error {
	_, err := referenceGrantInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onReferenceGrantAdd,
		UpdateFunc: c.onReferenceGrantUpdate,
		DeleteFunc: c.onReferenceGrantDelete,
	})
	return err
}

func (c *Controller) onReferenceGrantAdd(obj interface{}) {
	rg := obj.(*gatewayv1beta1.ReferenceGrant)
	klog.V(4).InfoS("Adding ReferenceGrant", "referencegrant", klog.KObj(rg))
	c.enqueueGatewaysForReferenceGrant(rg)
}

func (c *Controller) onReferenceGrantUpdate(old, newObj interface{}) {
	oldRG := old.(*gatewayv1beta1.ReferenceGrant)
	newRG := newObj.(*gatewayv1beta1.ReferenceGrant)
	if !reflect.DeepEqual(oldRG.Spec, newRG.Spec) {
		klog.V(4).InfoS("Updating ReferenceGrant", "referencegrant", klog.KObj(newRG))
		c.enqueueGatewaysForReferenceGrant(newRG)
	}
}

func (c *Controller) onReferenceGrantDelete(obj interface{}) {
	rg, ok := obj.(*gatewayv1beta1.ReferenceGrant)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			runtime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		rg, ok = tombstone.Obj.(*gatewayv1beta1.ReferenceGrant)
		if !ok {
			runtime.HandleError(fmt.Errorf("tombstone contained object that is not a ReferenceGrant %#v", obj))
			return
		}
	}
	klog.V(4).InfoS("Deleting ReferenceGrant", "referencegrant", klog.KObj(rg))
	c.enqueueGatewaysForReferenceGrant(rg)
}

// enqueueGatewaysForReferenceGrant finds all Gateways affected by a ReferenceGrant change.
// This includes Gateways referenced by HTTPRoutes that target the ReferenceGrant's namespace,
// and Gateways that reference Secrets in the ReferenceGrant's namespace.
func (c *Controller) enqueueGatewaysForReferenceGrant(rg *gatewayv1beta1.ReferenceGrant) {
	gatewaysToEnqueue := make(map[string]struct{})

	// 1. Process HTTPRoutes
	var routeObjs []interface{}
	fallbackToListingAllHTTPRoutes := false
	if c.gateway.httprouteIndexer != nil {
		var err error
		routeObjs, err = c.gateway.httprouteIndexer.ByIndex(HTTPRouteBackendRefNamespaceIndex, rg.Namespace)
		if err != nil {
			klog.Errorf("failed to get HTTPRoutes by index: %v", err)
			fallbackToListingAllHTTPRoutes = true
		}
	} else {
		fallbackToListingAllHTTPRoutes = true
	}

	if fallbackToListingAllHTTPRoutes {
		// Fallback to listing all HTTPRoutes
		routes, err := c.gateway.httprouteLister.List(labels.Everything())
		if err != nil {
			klog.Errorf("failed to list HTTPRoutes: %v", err)
			return
		}
		for _, r := range routes {
			routeObjs = append(routeObjs, r)
		}
	}

	for _, obj := range routeObjs {
		route := obj.(*gatewayv1.HTTPRoute)
		for _, rule := range route.Spec.Rules {
			for _, backendRef := range rule.BackendRefs {
				ns := route.Namespace
				if backendRef.Namespace != nil {
					ns = string(*backendRef.Namespace)
				}
				if ns != rg.Namespace {
					continue
				}

				for _, ref := range route.Spec.ParentRefs {
					if !isGatewayParentRef(ref) {
						continue
					}
					namespace := route.Namespace
					if ref.Namespace != nil {
						namespace = string(*ref.Namespace)
					}
					key := namespace + "/" + string(ref.Name)
					gatewaysToEnqueue[key] = struct{}{}
				}
			}
		}
	}

	// 2. Process Gateways referencing Secrets
	var gwObjs []interface{}
	fallbackToListingAllGateways := false
	if c.gateway.gatewayIndexer != nil {
		var err error
		gwObjs, err = c.gateway.gatewayIndexer.ByIndex(GatewaySecretRefNamespaceIndex, rg.Namespace)
		if err != nil {
			klog.Errorf("failed to get Gateways by index: %v", err)
			fallbackToListingAllGateways = true
		}
	} else {
		fallbackToListingAllGateways = true
	}

	if fallbackToListingAllGateways {
		// Fallback to listing all Gateways
		gws, err := c.gateway.gatewayLister.List(labels.Everything())
		if err != nil {
			klog.Errorf("failed to list Gateways: %v", err)
			return
		}
		for _, gw := range gws {
			gwObjs = append(gwObjs, gw)
		}
	}

	for _, obj := range gwObjs {
		gw := obj.(*gatewayv1.Gateway)
		for _, listener := range gw.Spec.Listeners {
			if listener.TLS != nil {
				for _, ref := range listener.TLS.CertificateRefs {
					ns := gw.Namespace
					if ref.Namespace != nil {
						ns = string(*ref.Namespace)
					}
					if ns == rg.Namespace {
						key := gw.Namespace + "/" + gw.Name
						gatewaysToEnqueue[key] = struct{}{}
					}
				}
			}
		}
	}

	for key := range gatewaysToEnqueue {
		c.gatewayqueue.Add(key)
	}
}
