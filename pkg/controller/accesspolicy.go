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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions/api/v0alpha0"
)

func (c *Controller) setupAccessPolicyEventHandlers(accessPolicyInformer agenticinformers.XAccessPolicyInformer) error {
	_, err := accessPolicyInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onAccessPolicyAdd,
		UpdateFunc: c.onAccessPolicyUpdate,
		DeleteFunc: c.onAccessPolicyDelete,
	})
	return err
}

func (c *Controller) onAccessPolicyAdd(obj interface{}) {
	policy := obj.(*agenticv0alpha0.XAccessPolicy)
	klog.V(4).InfoS("Adding AccessPolicy", "accesspolicy", klog.KObj(policy))
	c.enqueueGatewaysForAccessPolicy(policy)
}

func (c *Controller) onAccessPolicyUpdate(old, new interface{}) {
	oldPolicy := old.(*agenticv0alpha0.XAccessPolicy)
	newPolicy := new.(*agenticv0alpha0.XAccessPolicy)
	if newPolicy.Generation != oldPolicy.Generation || newPolicy.DeletionTimestamp != oldPolicy.DeletionTimestamp || !reflect.DeepEqual(newPolicy.Annotations, oldPolicy.Annotations) {
		klog.V(4).InfoS("Updating AccessPolicy", "accesspolicy", klog.KObj(oldPolicy))
		c.enqueueGatewaysForAccessPolicy(newPolicy)
	}
}

func (c *Controller) onAccessPolicyDelete(obj interface{}) {
	policy, ok := obj.(*agenticv0alpha0.XAccessPolicy)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			runtime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		policy, ok = tombstone.Obj.(*agenticv0alpha0.XAccessPolicy)
		if !ok {
			runtime.HandleError(fmt.Errorf("tombstone contained object that is not a AccessPolicy %#v", obj))
			return
		}
	}
	klog.V(4).InfoS("Deleting AccessPolicy", "accesspolicy", klog.KObj(policy))
	c.enqueueGatewaysForAccessPolicy(policy)
}

// TODO: When an AccessPolicy is deleted, we need to consider how to handle the gateway reconcile
// i.e. recalculating the xDS configuration without this AccessPolicy.
func (c *Controller) enqueueGatewaysForAccessPolicy(policy *agenticv0alpha0.XAccessPolicy) {
	for _, targetRef := range policy.Spec.TargetRefs {
		if !isXBackendTargetRef(targetRef) {
			// TODO: Set status condition on AccessPolicy to indicate unsupported targetRef
			klog.InfoS("AccessPolicy targets an unsupported resource", "accesspolicy", klog.KObj(policy), "targetRef", targetRef)
			continue
		}

		backend, err := c.agentic.backendLister.XBackends(policy.Namespace).Get(string(targetRef.Name))
		if err != nil {
			if apierrors.IsNotFound(err) {
				// TODO: Set status condition on AccessPolicy to indicate missing backend
				klog.InfoS("AccessPolicy targets a non-existent Backend", "accesspolicy", klog.KObj(policy), "backend", types.NamespacedName{Namespace: policy.Namespace, Name: string(targetRef.Name)})
			} else {
				runtime.HandleError(fmt.Errorf("failed to get backend %s/%s targeted by access policy %s: %w", policy.Namespace, targetRef.Name, policy.Name, err))
			}
			continue
		}
		c.enqueueGatewaysForBackend(backend)
	}
}

func isXBackendTargetRef(targetRef gwapiv1.LocalPolicyTargetReferenceWithSectionName) bool {
	return targetRef.Group == v0alpha0.GroupName && targetRef.Kind == "XBackend"
}
