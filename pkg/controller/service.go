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
	"k8s.io/apimachinery/pkg/util/runtime"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

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

func (c *Controller) onServiceUpdate(old, new interface{}) {
	oldSvc := old.(*corev1.Service)
	newSvc := new.(*corev1.Service)

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
}
