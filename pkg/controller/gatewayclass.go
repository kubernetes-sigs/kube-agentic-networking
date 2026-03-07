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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions/apis/v1"
	"sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

func (c *Controller) setupGatewayClassEventHandlers(gatewayClassInformer gatewayinformers.GatewayClassInformer) error {
	_, err := gatewayClassInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err == nil {
				c.syncGatewayClass(key)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(newObj)
			if err == nil {
				c.syncGatewayClass(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err == nil {
				c.syncGatewayClass(key)
			}
		},
	})
	return err
}

func (c *Controller) syncGatewayClass(key string) {
	startTime := time.Now()
	klog.V(2).Infof("Started syncing gatewayclass %q (%v)", key, time.Since(startTime))
	defer func() {
		klog.V(2).Infof("Finished syncing gatewayclass %q (%v)", key, time.Since(startTime))
	}()

	gwc, err := c.gateway.gatewayClassLister.Get(key)
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.InfoS("GatewayClass deleted", "gatewayclass", key)
		}
		return
	}

	// We only care about the GatewayClass that matches our controller name.
	if gwc.Spec.ControllerName != constants.ControllerName {
		return
	}

	newGwc := gwc.DeepCopy()

	if newGwc.DeletionTimestamp != nil {
		if hasGatewaysReferencingClass(c, string(newGwc.Name)) {
			klog.V(4).InfoS("GatewayClass has Gateways still referencing it, blocking deletion", "gatewayclass", key)
			return
		}
		if removeFinalizer(&newGwc.ObjectMeta, constants.GatewayClassFinalizer) {
			if _, err := c.gateway.client.GatewayV1().GatewayClasses().Update(context.Background(), newGwc, metav1.UpdateOptions{}); err != nil {
				klog.Errorf("failed to remove finalizer from GatewayClass: %v", err)
			}
		}
		return
	}

	if ensureFinalizer(&newGwc.ObjectMeta, constants.GatewayClassFinalizer) {
		if _, err := c.gateway.client.GatewayV1().GatewayClasses().Update(context.Background(), newGwc, metav1.UpdateOptions{}); err != nil {
			klog.Errorf("failed to add finalizer to GatewayClass: %v", err)
			return
		}
		return
	}

	// Resolve and apply parametersRef if present.
	if newGwc.Spec.ParametersRef != nil {
		ref := newGwc.Spec.ParametersRef
		if string(ref.Group) != "agentic.prototype.x-k8s.io" || string(ref.Kind) != "KANConfig" {
			klog.Warningf(
				"GatewayClass %q parametersRef has unexpected group/kind: %s/%s — expected agentic.prototype.x-k8s.io/KANConfig",
				key, ref.Group, ref.Kind,
			)
			meta.SetStatusCondition(&newGwc.Status.Conditions, metav1.Condition{
				Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
				Status:             metav1.ConditionFalse,
				Reason:             string(gatewayv1.GatewayClassReasonInvalidParameters),
				Message:            fmt.Sprintf("parametersRef must point to a KANConfig (agentic.prototype.x-k8s.io), got %s/%s", ref.Group, ref.Kind),
				ObservedGeneration: gwc.Generation,
			})
			if _, err := c.gateway.client.GatewayV1().GatewayClasses().UpdateStatus(
				context.Background(), newGwc, metav1.UpdateOptions{},
			); err != nil {
				klog.Errorf("failed to update GatewayClass status with InvalidParameters: %v", err)
			}
			return
		}

		kanCfg, err := c.agentic.kanConfigLister.KANConfigs("").Get(string(ref.Name))
		if err != nil {
			if apierrors.IsNotFound(err) {
				klog.Warningf(
					"KANConfig %q referenced by GatewayClass %q not found in cluster",
					ref.Name, key,
				)
				meta.SetStatusCondition(&newGwc.Status.Conditions, metav1.Condition{
					Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
					Status:             metav1.ConditionFalse,
					Reason:             string(gatewayv1.GatewayClassReasonInvalidParameters),
					Message:            fmt.Sprintf("referenced KANConfig %q not found", ref.Name),
					ObservedGeneration: gwc.Generation,
				})
				if _, err := c.gateway.client.GatewayV1().GatewayClasses().UpdateStatus(
					context.Background(), newGwc, metav1.UpdateOptions{},
				); err != nil {
					klog.Errorf("failed to update GatewayClass status: %v", err)
				}
			} else {
				// Transient error — log it, don't update status, let requeue handle it.
				klog.Errorf("failed to fetch KANConfig %q: %v", ref.Name, err)
			}
			return
		}

		klog.V(4).InfoS(
			"Applying KANConfig to controller",
			"gatewayclass", key,
			"kanconfig", kanCfg.Name,
			"proxyImage", kanCfg.Spec.ProxyImage,
		)
		c.applyKANConfig(kanCfg, key)
	}

	// Set the "Accepted" condition to True and update the observedGeneration.
	meta.SetStatusCondition(&newGwc.Status.Conditions, metav1.Condition{
		Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
		Status:             metav1.ConditionTrue,
		Reason:             string(gatewayv1.GatewayClassReasonAccepted),
		Message:            "GatewayClass is accepted by this controller.",
		ObservedGeneration: gwc.Generation,
	})

	// Update the GatewayClass status
	if _, err := c.gateway.client.GatewayV1().GatewayClasses().UpdateStatus(context.Background(), newGwc, metav1.UpdateOptions{}); err != nil {
		klog.Errorf("failed to update gatewayclass status: %v", err)
	} else {
		klog.InfoS("GatewayClass status updated", "gatewayclass", key)
	}
}

// hasGatewaysReferencingClass returns true if any Gateway exists with spec.gatewayClassName equal to className.
func hasGatewaysReferencingClass(c *Controller, className string) bool {
	gateways, err := c.gateway.gatewayLister.List(labels.Everything())
	if err != nil {
		klog.V(4).ErrorS(err, "failed to list Gateways for GatewayClass finalizer")
		return true // conservatively block
	}
	for _, gw := range gateways {
		if string(gw.Spec.GatewayClassName) == className {
			return true
		}
	}
	return false
}

// gateway class validation
func (c *Controller) isGatewayOwnedByController(gateway *gatewayv1.Gateway) bool {
	gwc, err := c.gateway.gatewayClassLister.Get(string(gateway.Spec.GatewayClassName))
	if err != nil || gwc == nil {
		if err != nil {
			klog.V(4).ErrorS(err, "GatewayClass lookup failed for Gateway",
				"gateway", klog.KObj(gateway),
				"gatewayClassName", string(gateway.Spec.GatewayClassName))
		}
		return false
	}
	return gwc.Spec.ControllerName == constants.ControllerName
}

// applyKANConfig copies fields from the KANConfig spec into the live controller
// and writes back the observed status on the KANConfig resource.
// It is safe to call on every reconcile — it is fully idempotent.
func (c *Controller) applyKANConfig(cfg *v0alpha0.KANConfig, referencingGatewayClass string) {
	if cfg.Spec.ProxyImage != "" {
		c.envoyImage = cfg.Spec.ProxyImage
	}
	if cfg.Spec.AgenticIdentityTrustDomain != "" {
		c.agenticIdentityTrustDomain = cfg.Spec.AgenticIdentityTrustDomain
	}
	if cfg.Spec.WorkerCount > 0 {
		c.workerCount = cfg.Spec.WorkerCount
	}
	// Add more fields here as KANConfigSpec grows

	// Update KANConfig status to reflect what was applied.
	newCfg := cfg.DeepCopy()
	newCfg.Status.ObservedGeneration = cfg.Generation
	newCfg.Status.ActiveWorkerCount = c.workerCount
	newCfg.Status.ReferencedBy = mergeStringSlice(cfg.Status.ReferencedBy, referencingGatewayClass)
	meta.SetStatusCondition(&newCfg.Status.Conditions, metav1.Condition{
		Type:               "Accepted",
		Status:             metav1.ConditionTrue,
		Reason:             "Accepted",
		Message:            "KANConfig is valid and has been accepted by the controller.",
		ObservedGeneration: cfg.Generation,
	})
	meta.SetStatusCondition(&newCfg.Status.Conditions, metav1.Condition{
		Type:               "Applied",
		Status:             metav1.ConditionTrue,
		Reason:             "Applied",
		Message:            fmt.Sprintf("KANConfig has been applied to GatewayClass %q.", referencingGatewayClass),
		ObservedGeneration: cfg.Generation,
	})
	if _, err := c.agentic.client.AgenticV0alpha0().KANConfigs("").UpdateStatus(
		context.Background(), newCfg, metav1.UpdateOptions{},
	); err != nil {
		klog.Errorf("failed to update KANConfig %q status: %v", cfg.Name, err)
	}
}

// mergeStringSlice returns slice with val added if not already present.
func mergeStringSlice(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

// setupKANConfigEventHandlers watches KANConfig resources and re-syncs all
// GatewayClasses whenever a KANConfig changes, so config reloads without
// restarting the controller pod.
func (c *Controller) setupKANConfigEventHandlers(
    kanConfigInformer agenticinformers.KANConfigInformer,
) error {
    _, err := kanConfigInformer.Informer().AddEventHandler(
        cache.ResourceEventHandlerFuncs{
            AddFunc: func(obj interface{}) {
                c.enqueueAllOwnedGatewayClasses()
            },
            UpdateFunc: func(oldObj, newObj interface{}) {
                c.enqueueAllOwnedGatewayClasses()
            },
            DeleteFunc: func(obj interface{}) {
                // KANConfig deleted — GatewayClasses will get InvalidParameters
                // on next sync because the lister.Get will return NotFound
                c.enqueueAllOwnedGatewayClasses()
            },
        },
    )
    return err
}

// enqueueAllOwnedGatewayClasses re-queues every GatewayClass controlled by us.
// Called when KANConfig changes so all GatewayClasses reload their config.
func (c *Controller) enqueueAllOwnedGatewayClasses() {
    gwClasses, err := c.gateway.gatewayClassLister.List(labels.Everything())
    if err != nil {
        klog.Errorf("failed to list GatewayClasses for KANConfig re-sync: %v", err)
        return
    }
    for _, gwc := range gwClasses {
        if gwc.Spec.ControllerName == constants.ControllerName {
            key, err := cache.MetaNamespaceKeyFunc(gwc)
            if err == nil {
                klog.V(4).InfoS("Re-syncing GatewayClass due to KANConfig change", "gatewayclass", key)
                c.syncGatewayClass(key)
            }
        }
    }
}
