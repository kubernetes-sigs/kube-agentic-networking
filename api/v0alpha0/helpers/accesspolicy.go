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

package helpers

import (
	"k8s.io/apimachinery/pkg/api/meta"

	v0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
)

// IsAccepted returns true if the policy has been explicitly accepted for all its targets.
// A policy is considered accepted only if it has at least one ancestor status populated
// and ALL ancestors have the 'Accepted' condition set to 'True'.
func IsAccepted(p *v0alpha0.XAccessPolicy) bool {
	if len(p.Status.Ancestors) == 0 {
		return false
	}
	for _, ancestor := range p.Status.Ancestors {
		if !meta.IsStatusConditionTrue(ancestor.Conditions, string(v0alpha0.PolicyConditionAccepted)) {
			return false
		}
	}
	return true
}
