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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions/apis/v1"
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
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err == nil {
		c.gatewayqueue.Add(key)
	}
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
	if newGW.Generation != oldGW.Generation || newGW.DeletionTimestamp != oldGW.DeletionTimestamp || !reflect.DeepEqual(newGW.Annotations, oldGW.Annotations) {
		key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(new)
		if err == nil {
			c.gatewayqueue.Add(key)
		}
		klog.V(4).InfoS("Gateway updated", "gateway", key)
	}
}

func (c *Controller) onGatewayDelete(obj interface{}) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err == nil {
		c.gatewayqueue.Add(key)
	}
	klog.V(4).InfoS("Gateway deleted", "gateway", key)
}

func (c *Controller) updateGatewayStatus(ctx context.Context, gateway *gatewayv1.Gateway, ip string) error {
	if ip == "" {
		return nil
	}

	// Check if the IP is already present in the status to avoid redundant updates.
	for _, addr := range gateway.Status.Addresses {
		if addr.Type != nil && *addr.Type == gatewayv1.IPAddressType && addr.Value == ip {
			return nil
		}
	}

	gatewayCopy := gateway.DeepCopy()
	gatewayCopy.Status.Addresses = []gatewayv1.GatewayStatusAddress{
		{
			Type:  ptr.To(gatewayv1.IPAddressType),
			Value: ip,
		},
	}

	_, err := c.gateway.client.GatewayV1().Gateways(gateway.Namespace).UpdateStatus(ctx, gatewayCopy, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update gateway status: %w", err)
	}

	klog.V(2).InfoS("Updated gateway status with proxy IP", "gateway", klog.KObj(gateway), "ip", ip)
	return nil
}
