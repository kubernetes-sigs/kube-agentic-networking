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

package translator

import (
	"k8s.io/client-go/tools/cache"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	agenticv1alpha1 "sigs.k8s.io/kube-agentic-networking/api/v1alpha1"
)

const (
	// AccessPolicyBackendTargetIndex indexes XAccessPolicies by XBackend target key "namespace/name"
	// (policy namespace + backend name). Must stay aligned with the controller informer registration.
	AccessPolicyBackendTargetIndex = "backendTarget"
	// AccessPolicyGatewayTargetIndex indexes XAccessPolicies by Gateway targetRef key "namespace/name"
	// (policy namespace + gateway name) for LocalPolicyTargetReference Gateway targets.
	AccessPolicyGatewayTargetIndex = "gatewayTarget"
)

// NewAccessPolicyIndexers returns indexers for XAccessPolicy informers (backendTarget, gatewayTarget).
// Register with AddIndexers; index keys must stay aligned with isAccessPolicyAttachedToGateway
// and listAccessPoliciesAttachedToGatewayIndexed.
func NewAccessPolicyIndexers() cache.Indexers {
	return cache.Indexers{
		AccessPolicyBackendTargetIndex: xAccessPolicyByBackendTarget,
		AccessPolicyGatewayTargetIndex: xAccessPolicyByGatewayTarget,
	}
}

// xAccessPolicyByBackendTarget implements cache.IndexFunc for AccessPolicyBackendTargetIndex.
func xAccessPolicyByBackendTarget(obj interface{}) ([]string, error) {
	policy, ok := obj.(*agenticv1alpha1.XAccessPolicy)
	if !ok {
		return nil, nil
	}
	var keys []string
	for _, targetRef := range policy.Spec.TargetRefs {
		if targetRef.Group != agenticv1alpha1.GroupName || targetRef.Kind != "XBackend" {
			continue
		}
		keys = append(keys, policy.Namespace+"/"+string(targetRef.Name))
	}
	return keys, nil
}

// xAccessPolicyByGatewayTarget implements cache.IndexFunc for AccessPolicyGatewayTargetIndex.
// Keys match isAccessPolicyAttachedToGateway for direct Gateway targets (local ref → policy namespace).
func xAccessPolicyByGatewayTarget(obj interface{}) ([]string, error) {
	policy, ok := obj.(*agenticv1alpha1.XAccessPolicy)
	if !ok {
		return nil, nil
	}
	var keys []string
	for _, targetRef := range policy.Spec.TargetRefs {
		if targetRef.Kind != "Gateway" {
			continue
		}
		g := targetRef.Group
		if g != "" && g != gwapiv1.GroupName {
			continue
		}
		keys = append(keys, policy.Namespace+"/"+string(targetRef.Name))
	}
	return keys, nil
}
