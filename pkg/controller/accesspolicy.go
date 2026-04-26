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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/api/v0alpha0/helpers"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

// AccessPolicyTargetRefIndex is the index name for looking up AccessPolicies by target ref (namespace/name of XBackend).
const AccessPolicyTargetRefIndex = "targetRef"

// accessPolicyTargetRefIndexFunc indexes AccessPolicies by each XBackend targetRef (namespace/name).
// Used by the informer cache to support O(1) lookup of policies targeting a given backend.
func accessPolicyTargetRefIndexFunc(obj interface{}) ([]string, error) {
	policy, ok := obj.(*agenticv0alpha0.XAccessPolicy)
	if !ok {
		return nil, nil
	}
	var keys []string
	for _, targetRef := range policy.Spec.TargetRefs {
		if !isXBackendTargetRef(targetRef) {
			continue
		}
		keys = append(keys, policy.Namespace+"/"+string(targetRef.Name))
	}
	return keys, nil
}

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

	// Initial check for policy limit per target.
	if !c.isPolicyUnderTargetLimit(context.Background(), policy) {
		return
	}

	// Validate CEL expressions.
	if !c.validateCELSpec(context.Background(), policy) {
		return
	}

	c.enqueueGatewaysForAccessPolicy(policy)
}

func (c *Controller) onAccessPolicyUpdate(old, newObj interface{}) {
	oldPolicy := old.(*agenticv0alpha0.XAccessPolicy)
	newPolicy := newObj.(*agenticv0alpha0.XAccessPolicy)

	if hasAccessPolicyChanged(oldPolicy, newPolicy) {
		klog.V(4).InfoS("Updating AccessPolicy", "accesspolicy", klog.KObj(oldPolicy))

		// If targets changed, we must re-evaluate the limit as it's equivalent to an 'Add' for the new target.
		if !reflect.DeepEqual(oldPolicy.Spec.TargetRefs, newPolicy.Spec.TargetRefs) {
			if !c.isPolicyUnderTargetLimit(context.Background(), newPolicy) {
				return
			}
		}

		// Validate CEL expressions.
		if !c.validateCELSpec(context.Background(), newPolicy) {
			return
		}

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

	// TODO: When a policy is deleted, we should re-enqueue all other AccessPolicies
	// that were targeting the same resources. This allows a previously rejected
	// policy to be accepted if a "senior" policy has been removed.
	c.enqueueGatewaysForAccessPolicy(policy)
}

// enqueueGatewaysForAccessPolicy enqueues all Gateways that are affected by the given AccessPolicy.
// It also enqueues the targeted XBackend for finalizer reconciliation.
// When an AccessPolicy targets a Gateway, that Gateway is enqueued so its finalizer can be re-evaluated on AccessPolicy delete (avoids deadlock).
func (c *Controller) enqueueGatewaysForAccessPolicy(policy *agenticv0alpha0.XAccessPolicy) {
	isAccepted := helpers.IsXAccessPolicyAccepted(policy)
	isDeleting := policy.DeletionTimestamp != nil
	shouldEnqueueGW := isAccepted || isDeleting

	for _, targetRef := range policy.Spec.TargetRefs {
		if isGatewayTargetRef(targetRef) {
			// Always enqueue targeted Gateways so syncGateway can add/maintain the Gateway finalizer
			// and re-evaluate hasAccessPoliciesTargetingGateway when this policy changes or is removed.
			// This matches the "wake parent on dependent delete" pattern from
			// https://github.com/kubernetes-sigs/kube-agentic-networking/pull/148 (see also #150).
			// Unlike XBackend→Gateway fan-out, we do not gate on policy acceptance: rejected policies
			// still block Gateway deletion via hasAccessPoliciesTargetingGateway until removed.
			gatewayKey := policy.Namespace + "/" + string(targetRef.Name)
			c.gatewayqueue.Add(gatewayKey)
			continue
		}

		if isXBackendTargetRef(targetRef) {
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

			// Always enqueue backend for finalizer reconciliation.
			// This ensures that if a policy (even a rejected one) is deleted,
			// the targeted backend can re-evaluate its finalizer.
			c.enqueueBackendForFinalizer(backend)

			// We only reconcile Gateways/Envoy for accepted policies.
			if shouldEnqueueGW {
				c.enqueueGatewaysForBackend(backend)
			}
			continue
		}

		klog.InfoS("AccessPolicy targets an unsupported resource", "accesspolicy", klog.KObj(policy), "targetRef", targetRef)
	}
}

func isXBackendTargetRef(targetRef gwapiv1.LocalPolicyTargetReferenceWithSectionName) bool {
	return targetRef.Group == agenticv0alpha0.GroupName && targetRef.Kind == "XBackend"
}

func isGatewayTargetRef(targetRef gwapiv1.LocalPolicyTargetReferenceWithSectionName) bool {
	return targetRef.Group == gwapiv1.GroupName && targetRef.Kind == "Gateway"
}

func hasAccessPolicyChanged(oldPolicy, newPolicy *agenticv0alpha0.XAccessPolicy) bool {
	specChanged := newPolicy.Generation != oldPolicy.Generation || !reflect.DeepEqual(newPolicy.Annotations, oldPolicy.Annotations)
	deletionTimestampChanged := newPolicy.DeletionTimestamp != oldPolicy.DeletionTimestamp
	acceptanceChanged := helpers.IsXAccessPolicyAccepted(newPolicy) != helpers.IsXAccessPolicyAccepted(oldPolicy)

	return specChanged || deletionTimestampChanged || acceptanceChanged
}

// isMoreSenior returns true if p1 is "more senior" (established earlier) than p2.
// Seniority is determined by CreationTimestamp, with Name as a deterministic tie-breaker.
func isMoreSenior(p1, p2 *agenticv0alpha0.XAccessPolicy) bool {
	if !p1.CreationTimestamp.Equal(&p2.CreationTimestamp) {
		return p1.CreationTimestamp.Before(&p2.CreationTimestamp)
	}
	return p1.Name < p2.Name
}

// isPolicyUnderTargetLimit determines if the policy is within the maximum allowed policies per target.
// It returns true if accepted for ALL targets, false otherwise.
// It also updates the policy status accordingly.
func (c *Controller) isPolicyUnderTargetLimit(ctx context.Context, policy *agenticv0alpha0.XAccessPolicy) bool {
	// TODO: Index AccessPolicies by their target refs for more efficient lookups.
	// https://github.com/kubernetes-sigs/kube-agentic-networking/issues/168
	allPolicies, err := c.agentic.accessPolicyLister.XAccessPolicies(policy.Namespace).List(labels.Everything())
	if err != nil {
		runtime.HandleError(fmt.Errorf("failed to list AccessPolicies: %w", err))
		return false
	}

	// 1. Group all policies by their target resource.
	targetToPolicies := make(map[string][]*agenticv0alpha0.XAccessPolicy)
	for _, p := range allPolicies {
		for _, ref := range p.Spec.TargetRefs {
			id := getTargetID(ref)
			targetToPolicies[id] = append(targetToPolicies[id], p)
		}
	}

	// 2. Evaluate each target of the current policy.
	shouldAccept := true
	var failureMessage string

	for _, targetRef := range policy.Spec.TargetRefs {
		id := getTargetID(targetRef)
		policies := targetToPolicies[id]

		if c.seniorPoliciesAtLimit(policy, policies) {
			shouldAccept = false
			failureMessage = fmt.Sprintf("Maximum number of AccessPolicies (%d) exceeded for target %s", constants.MaxAccessPoliciesPerTarget, targetRef.Name)
			klog.InfoS("Rejecting AccessPolicy: exceeded limit for target", "accesspolicy", klog.KObj(policy), "target", targetRef.Name, "limit", constants.MaxAccessPoliciesPerTarget)
			break
		}
	}

	// 3. Update status for all targets based on the overall result.
	for _, targetRef := range policy.Spec.TargetRefs {
		reason := agenticv0alpha0.PolicyReasonAccepted
		message := "AccessPolicy accepted for target"

		if !shouldAccept {
			reason = agenticv0alpha0.PolicyLimitPerTargetExceeded
			message = failureMessage
		}

		if err := c.updateAccessPolicyStatus(ctx, policy, targetRef, shouldAccept, reason, message); err != nil {
			runtime.HandleError(fmt.Errorf("failed to update AccessPolicy status: %w", err))
		}
	}

	return shouldAccept
}

// validateCELSpec validates that all CEL expressions in the policy are syntactically valid.
// It returns true if all expressions are valid, false otherwise.
// It also updates the policy status accordingly.
func (c *Controller) validateCELSpec(ctx context.Context, policy *agenticv0alpha0.XAccessPolicy) bool {
	if policy.Spec.Rules == nil {
		return true
	}

	env, err := cel.NewEnv(
		cel.Variable("request", cel.MapType(cel.StringType, cel.AnyType)),
		ext.Strings(),
	)
	if err != nil {
		c.rejectPolicyForAllTargets(ctx, policy, fmt.Sprintf("Failed to create CEL environment: %v", err))
		return false
	}

	for _, rule := range policy.Spec.Rules {
		if rule.Authorization != nil && rule.Authorization.Type == agenticv0alpha0.AuthorizationRuleTypeCEL && rule.Authorization.CEL != nil {
			if _, issues := env.Compile(rule.Authorization.CEL.Expression); issues != nil && issues.Err() != nil {
				msg := fmt.Sprintf("Failed to compile CEL expression %q: %v", rule.Authorization.CEL.Expression, issues.Err())
				c.rejectPolicyForAllTargets(ctx, policy, msg)
				return false
			}
		}
	}

	return true
}

func (c *Controller) rejectPolicyForAllTargets(ctx context.Context, policy *agenticv0alpha0.XAccessPolicy, message string) {
	for _, targetRef := range policy.Spec.TargetRefs {
		if err := c.updateAccessPolicyStatus(ctx, policy, targetRef, false, agenticv0alpha0.PolicyReasonInvalidCEL, message); err != nil {
			runtime.HandleError(fmt.Errorf("failed to update AccessPolicy status: %w", err))
		}
	}
}

// seniorPoliciesAtLimit returns true if the number of policies with higher seniority
// targeting the same resource has already reached the configured maximum limit.
func (c *Controller) seniorPoliciesAtLimit(policy *agenticv0alpha0.XAccessPolicy, allPoliciesForTarget []*agenticv0alpha0.XAccessPolicy) bool {
	if len(allPoliciesForTarget) <= constants.MaxAccessPoliciesPerTarget {
		return false
	}

	// To avoid sorting on every reconciliation event, we simply count how many
	// policies for this target have higher seniority than the current one.
	seniorCount := 0
	for _, p := range allPoliciesForTarget {
		if p.Name == policy.Name {
			continue
		}
		if isMoreSenior(p, policy) {
			seniorCount++
		}
	}

	// If there are already 'max' policies more senior than us, we are over the limit.
	return seniorCount >= constants.MaxAccessPoliciesPerTarget
}

func getTargetID(ref gwapiv1.LocalPolicyTargetReferenceWithSectionName) string {
	return fmt.Sprintf("%s/%s/%s", ref.Group, ref.Kind, ref.Name)
}

func (c *Controller) updateAccessPolicyStatus(ctx context.Context, policy *agenticv0alpha0.XAccessPolicy, targetRef gwapiv1.LocalPolicyTargetReferenceWithSectionName, accepted bool, reason gwapiv1.PolicyConditionReason, message string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh, err := c.agentic.accessPolicyLister.XAccessPolicies(policy.Namespace).Get(policy.Name)
		if err != nil {
			return err
		}
		policyCopy := fresh.DeepCopy()

		status := metav1.ConditionTrue
		if !accepted {
			status = metav1.ConditionFalse
		}

		newCondition := metav1.Condition{
			Type:               string(agenticv0alpha0.PolicyConditionAccepted),
			Status:             status,
			Reason:             string(reason),
			Message:            message,
			ObservedGeneration: fresh.Generation,
		}

		parentRef := gwapiv1.ParentReference{
			Group:     ptr.To(targetRef.Group),
			Kind:      ptr.To(targetRef.Kind),
			Namespace: ptr.To(gwapiv1.Namespace(policy.Namespace)),
			Name:      targetRef.Name,
		}

		var ancestorStatus *gwapiv1.PolicyAncestorStatus
		for i := range policyCopy.Status.Ancestors {
			if reflect.DeepEqual(policyCopy.Status.Ancestors[i].AncestorRef, parentRef) {
				ancestorStatus = &policyCopy.Status.Ancestors[i]
				break
			}
		}

		if ancestorStatus == nil {
			policyCopy.Status.Ancestors = append(policyCopy.Status.Ancestors, gwapiv1.PolicyAncestorStatus{
				AncestorRef:    parentRef,
				ControllerName: gwapiv1.GatewayController(constants.ControllerName),
			})
			ancestorStatus = &policyCopy.Status.Ancestors[len(policyCopy.Status.Ancestors)-1]
		}

		meta.SetStatusCondition(&ancestorStatus.Conditions, newCondition)

		if reflect.DeepEqual(fresh.Status, policyCopy.Status) {
			return nil
		}

		_, err = c.agentic.client.AgenticV0alpha0().XAccessPolicies(policy.Namespace).UpdateStatus(ctx, policyCopy, metav1.UpdateOptions{})
		return err
	})
}
