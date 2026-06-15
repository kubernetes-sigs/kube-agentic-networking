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

	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	discoveryinformers "k8s.io/client-go/informers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

func (c *Controller) setupEndpointSliceEventHandlers(informer discoveryinformers.EndpointSliceInformer) error {
	_, err := informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onEndpointSliceAdd,
		UpdateFunc: c.onEndpointSliceUpdate,
		DeleteFunc: c.onEndpointSliceDelete,
	})
	return err
}

func (c *Controller) onEndpointSliceAdd(obj interface{}) {
	slice := obj.(*discoveryv1.EndpointSlice)
	klog.V(4).InfoS("EndpointSlice added", "endpointslice", klog.KObj(slice))
	c.enqueueGatewaysForEndpointSlice(slice)
}

func (c *Controller) onEndpointSliceUpdate(old, newObj interface{}) {
	oldSlice := old.(*discoveryv1.EndpointSlice)
	newSlice := newObj.(*discoveryv1.EndpointSlice)
	if oldSlice.ResourceVersion == newSlice.ResourceVersion {
		return
	}
	klog.V(4).InfoS("EndpointSlice updated", "endpointslice", klog.KObj(oldSlice))
	c.enqueueGatewaysForEndpointSlice(newSlice)
}

func (c *Controller) onEndpointSliceDelete(obj interface{}) {
	slice, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			runtime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		slice, ok = tombstone.Obj.(*discoveryv1.EndpointSlice)
		if !ok {
			runtime.HandleError(fmt.Errorf("tombstone contained object that is not an EndpointSlice %#v", obj))
			return
		}
	}
	klog.V(4).InfoS("EndpointSlice deleted", "endpointslice", klog.KObj(slice))
	c.enqueueGatewaysForEndpointSlice(slice)
}

func (c *Controller) enqueueGatewaysForEndpointSlice(slice *discoveryv1.EndpointSlice) {
	serviceName, ok := slice.Labels[discoveryv1.LabelServiceName]
	if !ok || serviceName == "" {
		return
	}
	svc, err := c.core.svcLister.Services(slice.Namespace).Get(serviceName)
	if err != nil {
		klog.V(4).InfoS(
			"EndpointSlice references unknown Service, skipping gateway enqueue",
			"endpointslice", klog.KObj(slice),
			"service", serviceName,
		)
		return
	}
	c.enqueueGatewaysForService(svc)
}
