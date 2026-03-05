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
	"errors"
	"fmt"
	"reflect"

	"k8s.io/client-go/util/retry"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions/apis/v1"
)

var semanticIgnoreLastTransitionTime = conversion.EqualitiesOrDie(
	func(a, b metav1.Condition) bool {
		a.LastTransitionTime = metav1.Time{}
		b.LastTransitionTime = metav1.Time{}
		return a == b
	},
)

func (c *Controller) setupGatewayEventHandlers(gatewayInformer gatewayinformers.GatewayInformer) error {
	_, err := gatewayInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onGatewayAdd,
		UpdateFunc: c.onGatewayUpdate,
		DeleteFunc: c.onGatewayDelete,
	})
	return err
}

func (c *Controller) onGatewayAdd(obj interface{}) {
	gw := obj.(*gatewayv1.Gateway)
	if !c.isGatewayOwnedByController(gw) {
		return
	}
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		runtime.HandleError(fmt.Errorf("couldn't get key for Gateway: %w", err))
		return
	}
	c.gatewayqueue.Add(key)
	klog.V(4).InfoS("Gateway added", "gateway", key)
}

// onGatewayUpdate is called when a Gateway is updated.
// The function is designed to avoid unnecessary reconciliation loops.
// It enqueues the Gateway for processing only if its specification (generation),
// deletion timestamp, or annotations have changed. This prevents the
// controller from re-triggering a reconciliation in response to its own status
// updates or periodic informer resyncs.
func (c *Controller) onGatewayUpdate(old, new interface{}) {
	oldGW := old.(*gatewayv1.Gateway)
	newGW := new.(*gatewayv1.Gateway)
	if !c.isGatewayOwnedByController(newGW) {
		return
	}
	if newGW.Generation != oldGW.Generation || newGW.DeletionTimestamp != oldGW.DeletionTimestamp || !reflect.DeepEqual(newGW.Annotations, oldGW.Annotations) {
		key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(new)
		if err == nil {
			c.gatewayqueue.Add(key)
		}
		klog.V(4).InfoS("Gateway updated", "gateway", key)
	}
}

func (c *Controller) onGatewayDelete(obj interface{}) {
	gw, ok := obj.(*gatewayv1.Gateway)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			runtime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		gw, ok = tombstone.Obj.(*gatewayv1.Gateway)
		if !ok {
			runtime.HandleError(fmt.Errorf("tombstone contained object that is not a Gateway %#v", obj))
			return
		}
	}

	if !c.isGatewayOwnedByController(gw) {
		return
	}
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err == nil {
		c.gatewayqueue.Add(key)
	}
	klog.V(4).InfoS("Gateway deleted", "gateway", key)

	// Trigger GatewayClass sync to allow it to remove finalizer if it was waiting on this Gateway.
	c.syncGatewayClass(string(gw.Spec.GatewayClassName))
}

// setGatewayConditions calculates and sets the final status conditions for the Gateway
// based on the results of the reconciliation loop.
func setGatewayConditions(newGw *gatewayv1.Gateway, listenerStatuses []gatewayv1.ListenerStatus, err error) {
	programmedCondition := metav1.Condition{
		Type:               string(gatewayv1.GatewayConditionProgrammed),
		ObservedGeneration: newGw.Generation,
	}
	if err != nil {
		// If the Envoy update fails, the Gateway is not programmed.
		programmedCondition.Status = metav1.ConditionFalse
		programmedCondition.Reason = "ReconciliationError"
		programmedCondition.Message = fmt.Sprintf("Failed to program envoy config: %s", err.Error())
	} else {
		// If the Envoy update succeeds, check if all individual listeners were programmed.
		listenersProgrammed := 0
		for _, listenerStatus := range listenerStatuses {
			if meta.IsStatusConditionTrue(listenerStatus.Conditions, string(gatewayv1.ListenerConditionProgrammed)) {
				listenersProgrammed++
			}
		}

		if listenersProgrammed == len(listenerStatuses) {
			// The Gateway is only fully programmed if all listeners are programmed.
			programmedCondition.Status = metav1.ConditionTrue
			programmedCondition.Reason = string(gatewayv1.GatewayReasonProgrammed)
			programmedCondition.Message = "Envoy configuration updated successfully"
		} else {
			// If any listener failed, the Gateway as a whole is not fully programmed.
			programmedCondition.Status = metav1.ConditionFalse
			programmedCondition.Reason = "ListenersNotProgrammed"
			programmedCondition.Message = fmt.Sprintf("%d out of %d listeners failed to be programmed", listenersProgrammed, len(listenerStatuses))
		}
	}
	klog.V(2).InfoS("Setting gateway conditions", "gateway", klog.KObj(newGw), "conditions", programmedCondition)
	changed := meta.SetStatusCondition(&newGw.Status.Conditions, programmedCondition)
	klog.V(2).InfoS("Gateway conditions changed", "gateway", klog.KObj(newGw), "changed", changed)

	meta.SetStatusCondition(&newGw.Status.Conditions, metav1.Condition{
		Type:               string(gatewayv1.GatewayConditionAccepted),
		Status:             metav1.ConditionTrue,
		Reason:             string(gatewayv1.GatewayReasonAccepted),
		Message:            "Gateway is accepted",
		ObservedGeneration: newGw.Generation,
	})
}

func (c *Controller) updateRouteStatuses(
	ctx context.Context,
	httpRouteStatuses map[types.NamespacedName][]gatewayv1.RouteParentStatus,
	grpcRouteStatuses map[types.NamespacedName][]gatewayv1.RouteParentStatus,
) error {
	var errGroup []error

	// --- Process HTTPRoutes ---
	for key, desiredParentStatuses := range httpRouteStatuses {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			// GET the latest version of the route from the cache.
			originalRoute, err := c.gateway.httprouteLister.HTTPRoutes(key.Namespace).Get(key.Name)
			if apierrors.IsNotFound(err) {
				// Route has been deleted, nothing to do.
				return nil
			} else if err != nil {
				return err
			}

			// Create a mutable copy to work with.
			routeToUpdate := originalRoute.DeepCopy()
			routeToUpdate.Status.Parents = desiredParentStatuses

			// Only make an API call if the status has actually changed.
			if !semanticIgnoreLastTransitionTime.DeepEqual(originalRoute.Status, routeToUpdate.Status) {
				_, updateErr := c.gateway.client.GatewayV1().HTTPRoutes(routeToUpdate.Namespace).UpdateStatus(ctx, routeToUpdate, metav1.UpdateOptions{})
				return updateErr
			}

			// Status is already up-to-date.
			return nil
		})

		if err != nil {
			errGroup = append(errGroup, fmt.Errorf("failed to update status for HTTPRoute %s: %w", key, err))
		}
	}

	// TODO: Process GRPCRoutes (repeat the same logic)

	return errors.Join(errGroup...)
}
