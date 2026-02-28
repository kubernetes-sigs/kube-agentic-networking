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
	"context"
	"fmt"
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

func (c *Controller) setupBackendEventHandlers(backendInformer agenticinformers.XBackendInformer) error {
	_, err := backendInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onBackendAdd,
		UpdateFunc: c.onBackendUpdate,
		DeleteFunc: c.onBackendDelete,
	})
	return err
}

func (c *Controller) onBackendAdd(obj interface{}) {
	backend := obj.(*agenticv0alpha0.XBackend)
	klog.V(4).InfoS("Adding Backend", "backend", klog.KObj(backend))
	c.enqueueBackendForFinalizer(backend)
	c.enqueueGatewaysForBackend(backend)
}

func (c *Controller) onBackendUpdate(old, new interface{}) {
	oldBackend := old.(*agenticv0alpha0.XBackend)
	newBackend := new.(*agenticv0alpha0.XBackend)
	if newBackend.Generation != oldBackend.Generation || newBackend.DeletionTimestamp != oldBackend.DeletionTimestamp || !reflect.DeepEqual(newBackend.Annotations, oldBackend.Annotations) {
		klog.V(4).InfoS("Updating Backend", "backend", klog.KObj(oldBackend))
		c.enqueueBackendForFinalizer(newBackend)
		c.enqueueGatewaysForBackend(newBackend)
	}
}

func (c *Controller) onBackendDelete(obj interface{}) {
	backend, ok := obj.(*agenticv0alpha0.XBackend)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			runtime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		backend, ok = tombstone.Obj.(*agenticv0alpha0.XBackend)
		if !ok {
			runtime.HandleError(fmt.Errorf("tombstone contained object that is not a Backend %#v", obj))
			return
		}
	}
	klog.V(4).InfoS("Deleting Backend", "backend", klog.KObj(backend))
	c.enqueueBackendForFinalizer(backend)
	c.enqueueGatewaysForBackend(backend)
}

// enqueueBackendForFinalizer enqueues the XBackend for finalizer sync only (add/remove finalizer based on XAccessPolicy targetRefs). It does not enqueue Gateways.
func (c *Controller) enqueueBackendForFinalizer(backend *agenticv0alpha0.XBackend) {
	key := backend.Namespace + "/" + backend.Name
	c.backendFinalizerQueue.Add(key)
}

// syncBackendFinalizer manages the XBackend finalizer.
func (c *Controller) syncBackendFinalizer(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid backend key %s: %w", key, err))
		return nil
	}
	backend, err := c.agentic.backendLister.XBackends(namespace).Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	newBackend := backend.DeepCopy()

	if backend.DeletionTimestamp != nil {
		if hasAccessPoliciesTargetingBackend(c, backend) {
			klog.V(4).InfoS("XBackend has XAccessPolicies still targeting it, blocking deletion", "backend", klog.KObj(backend))
			return nil
		}
		if removeFinalizer(&newBackend.ObjectMeta, constants.XBackendFinalizer) {
			if _, err := c.agentic.client.AgenticV0alpha0().XBackends(namespace).Update(ctx, newBackend, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("failed to remove finalizer from XBackend: %w", err)
			}
		}
		return nil
	}

	if ensureFinalizer(&newBackend.ObjectMeta, constants.XBackendFinalizer) {
		if _, err := c.agentic.client.AgenticV0alpha0().XBackends(namespace).Update(ctx, newBackend, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("failed to add finalizer to XBackend: %w", err)
		}
	}
	return nil
}

// hasAccessPoliciesTargetingBackend returns true if any XAccessPolicy has a targetRef to the given backend.
func hasAccessPoliciesTargetingBackend(c *Controller, backend *agenticv0alpha0.XBackend) bool {
	policies, err := c.agentic.accessPolicyLister.XAccessPolicies(backend.Namespace).List(labels.Everything())
	if err != nil {
		klog.V(4).ErrorS(err, "failed to list XAccessPolicies for XBackend finalizer")
		return true
	}
	for _, policy := range policies {
		for _, targetRef := range policy.Spec.TargetRefs {
			if !isXBackendTargetRef(targetRef) {
				// TODO: Set status condition on AccessPolicy to indicate unsupported targetRef.
				continue
			}
			if string(targetRef.Name) == backend.Name {
				return true
			}
		}
	}
	return false
}

// enqueueGatewaysForBackend enqueues Gateways that reference this backend
func (c *Controller) enqueueGatewaysForBackend(backend *agenticv0alpha0.XBackend) {
	routes, err := c.gateway.httprouteLister.List(labels.Everything())
	if err != nil {
		runtime.HandleError(fmt.Errorf("failed to list httproutes: %w", err))
		return
	}

	gatewaysToEnqueue := make(map[string]struct{})

	for _, route := range routes {
		referencesBackend := false
		for _, rule := range route.Spec.Rules {
			for _, ref := range rule.BackendRefs {
				if !isXBackendRef(ref.BackendRef) {
					continue
				}

				refNamespace := route.Namespace
				if ref.Namespace != nil {
					refNamespace = string(*ref.Namespace)
				}

				if string(ref.Name) == backend.Name && refNamespace == backend.Namespace {
					referencesBackend = true
					break
				}
			}
			if referencesBackend {
				break
			}
		}

		if referencesBackend {
			for _, parentRef := range route.Spec.ParentRefs {
				if !isGatewayParentRef(parentRef) {
					continue
				}

				namespace := route.Namespace
				if parentRef.Namespace != nil {
					namespace = string(*parentRef.Namespace)
				}
				key := namespace + "/" + string(parentRef.Name)
				gatewaysToEnqueue[key] = struct{}{}
			}
		}
	}

	for key := range gatewaysToEnqueue {
		klog.V(4).InfoS("Enqueuing gateway for backend change", "gateway", key, "backend", klog.KObj(backend))
		c.gatewayqueue.Add(key)
	}
}

// isXBackendRef checks if a given BackendRef refers to an XBackend resource.
func isXBackendRef(ref gatewayv1.BackendRef) bool {
	return ref.Group != nil && string(*ref.Group) == agenticv0alpha0.GroupName &&
		ref.Kind != nil && string(*ref.Kind) == "XBackend"
}

// isGatewayParentRef checks if a given ParentReference refers to a Gateway resource.
func isGatewayParentRef(parentRef gatewayv1.ParentReference) bool {
	return (parentRef.Group == nil || string(*parentRef.Group) == gatewayv1.GroupName) &&
		(parentRef.Kind == nil || string(*parentRef.Kind) == "Gateway")
}
