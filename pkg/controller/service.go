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
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/runtime"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"sigs.k8s.io/kube-agentic-networking/pkg/translator"
)

// ServiceRefIndex is the name of the index that maps Service namespace/name to HTTPRoutes
// that reference that Service in their backendRefs (direct refs only, not XBackend).
const ServiceRefIndex = "serviceRef"

// HTTPRouteServiceRefIndexFunc returns index keys "namespace/name" for each Service
// referenced by an HTTPRoute's backendRefs (skips XBackend refs).
func HTTPRouteServiceRefIndexFunc(obj interface{}) ([]string, error) {
	route, ok := obj.(*gatewayv1.HTTPRoute)
	if !ok {
		return nil, nil
	}
	var keys []string
	for _, rule := range route.Spec.Rules {
		for _, backend := range rule.BackendRefs {
			if isXBackendRef(backend.BackendRef) {
				continue
			}
			backendNS := route.Namespace
			if backend.Namespace != nil {
				backendNS = string(*backend.Namespace)
			}
			keys = append(keys, backendNS+"/"+string(backend.Name))
		}
	}
	return keys, nil
}

func (c *Controller) setupServiceEventHandlers(informer corev1informers.ServiceInformer) error {
	_, err := informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onServiceAdd,
		UpdateFunc: c.onServiceUpdate,
		DeleteFunc: c.onServiceDelete,
	})
	return err
}

func (c *Controller) onServiceAdd(obj interface{}) {
	svc := obj.(*corev1.Service)
	klog.V(4).InfoS("Service added", "service", klog.KObj(svc))
	c.enqueueGatewaysForService(svc)
}

func (c *Controller) onServiceUpdate(old, newObj interface{}) {
	oldSvc := old.(*corev1.Service)
	newSvc := newObj.(*corev1.Service)

	if !reflect.DeepEqual(oldSvc.Spec.ClusterIPs, newSvc.Spec.ClusterIPs) ||
		newSvc.DeletionTimestamp != oldSvc.DeletionTimestamp ||
		!reflect.DeepEqual(newSvc.Annotations, oldSvc.Annotations) {
		klog.V(4).InfoS("Service updated", "service", klog.KObj(oldSvc))
		c.enqueueGatewaysForService(newSvc)
	}
}

func (c *Controller) onServiceDelete(obj interface{}) {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			runtime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		svc, ok = tombstone.Obj.(*corev1.Service)
		if !ok {
			runtime.HandleError(fmt.Errorf("tombstone contained object that is not a Service %#v", obj))
			return
		}
	}
	klog.V(4).InfoS("Deleting Service", "service", klog.KObj(svc))
	c.enqueueGatewaysForService(svc)
}

func (c *Controller) enqueueGatewaysForService(svc *corev1.Service) {
	// A change to a Service can affect multiple Gateways via Backends and HTTPRoutes.
	klog.V(4).InfoS(
		"Enqueueing Gateways for Service change",
		"service", klog.KObj(svc),
	)
	c.enqueueGatewaysForServiceDirectHTTPRouteRefs(svc)
	c.enqueueGatewaysForServiceViaXBackends(svc)
}

// enqueueGatewaysForServiceDirectHTTPRouteRefs enqueues Gateways for HTTPRoutes
// that reference this Service directly in their backendRefs. Uses the ServiceRef
// index so we only consider routes that reference this Service instead of listing all.
func (c *Controller) enqueueGatewaysForServiceDirectHTTPRouteRefs(svc *corev1.Service) {
	if c.gateway.httprouteIndexer == nil {
		c.enqueueGatewaysForServiceDirectHTTPRouteRefsList(svc)
		return
	}
	svcKey := svc.Namespace + "/" + svc.Name
	objs, err := c.gateway.httprouteIndexer.ByIndex(ServiceRefIndex, svcKey)
	if err != nil {
		runtime.HandleError(err)
		return
	}
	for _, obj := range objs {
		route := obj.(*gatewayv1.HTTPRoute)
		// Cross-namespace refs require a ReferenceGrant in the backend namespace.
		if !translator.AllowedByReferenceGrant(route.Namespace, gatewayv1.GroupName, "HTTPRoute", svc.Namespace, "", "Service", svc.Name, c.gateway.referenceGrantLister) {
			continue
		}
		klog.V(4).InfoS(
			"HTTPRoute references Service directly",
			"service", klog.KObj(svc),
			"httproute", klog.KObj(route),
		)
		c.enqueueGatewaysForHTTPRoute(route.Spec.ParentRefs, route.Namespace)
	}
}

// enqueueGatewaysForServiceDirectHTTPRouteRefsList is the list-based implementation
// used when the ServiceRef index is not available (e.g. in tests).
func (c *Controller) enqueueGatewaysForServiceDirectHTTPRouteRefsList(svc *corev1.Service) {
	routes, err := c.gateway.httprouteLister.List(labels.Everything())
	if err != nil {
		runtime.HandleError(err)
		return
	}
	for _, route := range routes {
		matched := false
		for _, rule := range route.Spec.Rules {
			for _, backend := range rule.BackendRefs {
				if isXBackendRef(backend.BackendRef) {
					continue
				}
				backendNS := route.Namespace
				if backend.Namespace != nil {
					backendNS = string(*backend.Namespace)
				}
				if backendNS == svc.Namespace && string(backend.Name) == svc.Name {
					if !translator.AllowedByReferenceGrant(route.Namespace, gatewayv1.GroupName, "HTTPRoute", backendNS, "", "Service", string(backend.Name), c.gateway.referenceGrantLister) {
						continue
					}
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if matched {
			c.enqueueGatewaysForHTTPRoute(route.Spec.ParentRefs, route.Namespace)
		}
	}
}

// enqueueGatewaysForServiceViaXBackends enqueues Gateways for HTTPRoutes that reference an XBackend
func (c *Controller) enqueueGatewaysForServiceViaXBackends(svc *corev1.Service) {
	backends, err := c.agentic.backendLister.XBackends(svc.Namespace).List(labels.Everything())
	if err != nil {
		runtime.HandleError(err)
		return
	}

	for _, backend := range backends {
		if backend.Spec.MCP.ServiceName == nil || *backend.Spec.MCP.ServiceName != svc.Name {
			continue
		}
		klog.V(4).InfoS(
			"XBackend references Service, enqueueing Gateways for HTTPRoutes using this backend",
			"service", klog.KObj(svc),
			"backend", klog.KObj(backend),
		)
		c.enqueueGatewaysForBackend(backend)
	}
}
