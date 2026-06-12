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

package features

import (
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/gateway-api/pkg/features"
)

const (
	// SupportAccessPolicyGateway indicates that the implementation supports
	// AccessPolicy targeting Gateway resources.
	SupportAccessPolicyGateway features.FeatureName = "SupportAccessPolicyGateway"

	// SupportAccessPolicySPIFFESource indicates that the implementation supports
	// AccessPolicy rules with SPIFFE source.
	SupportAccessPolicySPIFFESource features.FeatureName = "SupportAccessPolicySPIFFESource"

	// SupportAccessPolicyExternalAuth indicates that the implementation supports
	// AccessPolicy with ExternalAuth action.
	SupportAccessPolicyExternalAuth features.FeatureName = "SupportAccessPolicyExternalAuth"
)

// AgenticCoreFeatures includes all SupportedFeatures needed to be
// conformant with the AccessPolicy resource.
var AgenticCoreFeatures = sets.New(
	SupportAccessPolicyGateway,
	features.SupportGateway,
	features.SupportHTTPRoute,
	features.SupportReferenceGrant,
)
