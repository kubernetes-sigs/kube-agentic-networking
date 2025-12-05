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
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions/apis/v1"
)

func (c *Controller) setupGatewayEventHandlers(gatewayInformer gatewayinformers.GatewayInformer) error {
	_, err := gatewayInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err == nil {
				c.gatewayqueue.Add(key)
			}
			klog.V(4).InfoS("Gateway added", "gateway", key)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(newObj)
			if err == nil {
				c.gatewayqueue.Add(key)
			}
			klog.V(4).InfoS("Gateway updated", "gateway", key)
		},
		DeleteFunc: func(obj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err == nil {
				c.gatewayqueue.Add(key)
			}
			klog.V(4).InfoS("Gateway deleted", "gateway", key)
		},
	})
	return err
}
