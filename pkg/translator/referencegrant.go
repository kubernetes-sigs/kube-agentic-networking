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

package translator

import (
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"

	gatewaylistersv1beta1 "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1beta1"
)

// AllowedByReferenceGrant returns true if a resource of fromGroup/fromKind in fromNamespace is allowed
// to reference a resource of toGroup/toKind in toNamespace per the Gateway API ReferenceGrant spec.
// See https://gateway-api.sigs.k8s.io/api-types/referencegrant/
func AllowedByReferenceGrant(
	fromNamespace, fromGroup, fromKind string,
	toNamespace, toGroup, toKind, toName string,
	referenceGrantLister gatewaylistersv1beta1.ReferenceGrantLister,
) bool {
	if fromNamespace == toNamespace {
		return true
	}

	grants, err := referenceGrantLister.ReferenceGrants(toNamespace).List(labels.Everything())
	if err != nil {
		klog.V(4).ErrorS(err, "Failed to list ReferenceGrants", "toNamespace", toNamespace)
		return false
	}

	for _, g := range grants {
		for _, from := range g.Spec.From {
			if string(from.Namespace) != fromNamespace {
				continue
			}
			if string(from.Group) != fromGroup {
				continue
			}
			if string(from.Kind) != fromKind {
				continue
			}

			for _, to := range g.Spec.To {
				if string(to.Group) != toGroup {
					continue
				}
				if string(to.Kind) != toKind {
					continue
				}
				if to.Name != nil && string(*to.Name) != toName {
					continue
				}
				return true
			}
		}
	}
	return false
}
