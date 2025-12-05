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

	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions/api/v0alpha0"
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
	c.enqueueGatewaysForBackend(backend)
}

func (c *Controller) onBackendUpdate(old, new interface{}) {
	oldBackend := old.(*agenticv0alpha0.XBackend)
	newBackend := new.(*agenticv0alpha0.XBackend)
	klog.V(4).InfoS("Updating Backend", "backend", klog.KObj(oldBackend))
	c.enqueueGatewaysForBackend(newBackend)
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
	c.enqueueGatewaysForBackend(backend)
}

func (c *Controller) enqueueGatewaysForBackend(backend *agenticv0alpha0.XBackend) {
	// TODO: Find the HTTPRoutes that reference this Backend, then find the Gateways that reference those HTTPRoutes, and enqueue them.
}
