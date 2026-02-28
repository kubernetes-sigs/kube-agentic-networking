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

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewaylistersv1beta1 "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1beta1"
)

// AllowedByReferenceGrant returns true if an HTTPRoute in routeNamespace is allowed
// to reference a Service in backendNamespace per the Gateway API ReferenceGrant spec.
// See https://gateway-api.sigs.k8s.io/api-types/referencegrant/
func AllowedByReferenceGrant(
	routeNamespace, backendNamespace string,
	referenceGrantLister gatewaylistersv1beta1.ReferenceGrantLister,
) bool {
	if routeNamespace == backendNamespace {
		return true
	}
	grants, err := referenceGrantLister.ReferenceGrants(backendNamespace).List(labels.Everything())
	if err != nil {
		return false
	}
	for _, g := range grants {
		for _, from := range g.Spec.From {
			if string(from.Namespace) != routeNamespace {
				continue
			}
			if string(from.Group) != gatewayv1.GroupName {
				continue
			}
			if string(from.Kind) != "HTTPRoute" {
				continue
			}
			for _, to := range g.Spec.To {
				// Core Services: empty group
				if string(to.Group) != "" {
					continue
				}
				if string(to.Kind) != "Service" {
					continue
				}
				return true
			}
		}
	}
	return false
}
