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
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
)

const (
	// AccessPolicyTargetRefIndex indexes XAccessPolicies by XBackend targetRef key "namespace/name"
	// (policy namespace + backend name). Must stay aligned with the controller informer registration.
	AccessPolicyTargetRefIndex = "targetRef"
	// AccessPolicyGatewayTargetIndex indexes XAccessPolicies by Gateway targetRef key "namespace/name"
	// (policy namespace + gateway name) for LocalPolicyTargetReference Gateway targets.
	AccessPolicyGatewayTargetIndex = "gatewayTarget"
)

// AccessPolicyXBackendTargetRefIndexFunc is the cache indexer for AccessPolicyTargetRefIndex.
func AccessPolicyXBackendTargetRefIndexFunc(obj interface{}) ([]string, error) {
	policy, ok := obj.(*agenticv0alpha0.XAccessPolicy)
	if !ok {
		return nil, nil
	}
	var keys []string
	for _, targetRef := range policy.Spec.TargetRefs {
		if targetRef.Group != agenticv0alpha0.GroupName || targetRef.Kind != "XBackend" {
			continue
		}
		keys = append(keys, policy.Namespace+"/"+string(targetRef.Name))
	}
	return keys, nil
}

// AccessPolicyGatewayTargetRefIndexFunc is the cache indexer for AccessPolicyGatewayTargetIndex.
// Keys match isAccessPolicyAttachedToGateway for direct Gateway targets (local ref → policy namespace).
func AccessPolicyGatewayTargetRefIndexFunc(obj interface{}) ([]string, error) {
	policy, ok := obj.(*agenticv0alpha0.XAccessPolicy)
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
