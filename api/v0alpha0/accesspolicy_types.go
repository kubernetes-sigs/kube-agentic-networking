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

// IMPORTANT: Run "make generate" to regenerate code after modifying this file

package v0alpha0

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// AccessPolicySpec defines the desired state of AccessPolicy.
type AccessPolicySpec struct {
	// TargetRefs specifies the targets of the AccessPolicy.
	// An AccessPolicy must target at least one resource.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	// +kubebuilder:validation:XValidation:rule="self.all(x, x.group == 'agentic.prototype.x-k8s.io' && x.kind == 'XBackend')",message="TargetRef must have group agentic.prototype.x-k8s.io group and kind XBackend"
	TargetRefs []gwapiv1.LocalPolicyTargetReferenceWithSectionName `json:"targetRefs"`
	// Rules defines a list of rules to be applied to the target.
	// An AccessPolicy must have at least one rule.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	Rules []AccessRule `json:"rules"`
}

// AccessRule specifies an authorization rule for the targeted backend.
// If the tool list is empty, the rule denies access to all tools from Source.
type AccessRule struct {
	// Source specifies the source of the request.
	// +required
	Source Source `json:"source"`
	// Authorization specifies the authorization rule to be applied to requests from the source.
	// +optional
	Authorization AuthorizationRule `json:"authorization,omitempty"`
}

// Source specifies the source of a request.
//
// Type must be set to indicate the type of source type.
// Similarly, either SPIFFE or Serviceaccount can be set based on the type.
type Source struct {

	// +unionDiscriminator
	// +required
	Type AuthorizationSourceType `json:"type"`

	// spiffe specifies an identity that is matched by this rule.
	//
	// spiffe identities must be specified as SPIFFE-formatted URIs following the pattern:
	//   spiffe://<trust_domain>/<workload-identifier>
	//
	// The exact workload identifier structure is implementation-specific.
	//
	// spiffe identities for authorization can be derived in various ways by the underlying
	// implementation. Common methods include:
	// - From peer mTLS certificates: The identity is extracted from the client's
	//   mTLS certificate presented during connection establishment.
	// - From IP-to-identity mappings: The implementation might maintain a dynamic
	//   mapping between source IP addresses (pod IPs) and their associated
	//   identities (e.g., Service Account, SPIFFE IDs).
	// - From JWTs or other request-level authentication tokens.
	//
	// Note for reviewers: While this GEP primarily focuses on identity-based
	// authorization where identity is often established at the transport layer,
	// some implementations might derive identity from authenticated tokens or sources
	// within the request itself.
	//
	// +optional
	SPIFFE *AuthorizationSourceSPIFFE `json:"spiffe,omitempty"`

	// ServiceAccount specifies a Kubernetes Service Account that is
	// matched by this rule. A request originating from a pod associated with
	// this serviceaccount will match the rule.
	//
	// The ServiceAccount listed here is expected to exist within the same
	// trust domain as the targeted workload. Cross-trust-domain access should
	// instead be expressed using the `SPIFFE` field.
	// +optional
	ServiceAccount *AuthorizationSourceServiceAccount `json:"serviceAccount,omitempty"`
}

// AuthorizationSourceType identifies a type of source for authorization.
// +kubebuilder:validation:Enum=ServiceAccount;SPIFFE
type AuthorizationSourceType string

const (
	// AuthorizationSourceTypeSPIFFE is used to identify a request matches a SPIFFE Identity.
	AuthorizationSourceTypeSPIFFE AuthorizationSourceType = "SPIFFE"

	// AuthorizationSourceTypeServiceAccount is used to identify a request matches a ServiceAccount from within the cluster.
	AuthorizationSourceTypeServiceAccount AuthorizationSourceType = "ServiceAccount"
)

// +kubebuilder:validation:Pattern=`^spiffe://[a-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$`
type AuthorizationSourceSPIFFE string

type AuthorizationSourceServiceAccount struct {
	// Namespace is the namespace of the ServiceAccount
	// If not specified, current namespace (the namespace of the policy) is used.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Name is the name of the ServiceAccount.
	// +required
	Name string `json:"name"`
}

type AuthorizationRule struct {
	// +unionDiscriminator
	// +required
	Type AuthorizationRuleType `json:"type"`

	// Tools specifies a list of tools inline.
	// +listType=set
	// +optional
	Tools []string `json:"tools,omitempty"`
}

// AuthorizationRuleType identifies a type of authorization rule.
// +kubebuilder:validation:Enum=InlineTools
type AuthorizationRuleType string

const (
	// AuthorizationRuleTypeInlineTools is used to identify authorization rules
	// declared as an inline list of authorized tools.
	AuthorizationRuleTypeInlineTools AuthorizationRuleType = "InlineTools"
)

// AccessPolicyStatus defines the observed state of AccessPolicy.
type AccessPolicyStatus struct {
	// Ancestors is a list of ancestor resources (usually Backend) that are
	// associated with the policy, and the status of the policy with respect to
	// each ancestor.
	//
	// This field is inherited from the Gateway API Policy status definition.
	// For more details, see the upstream documentation:
	// https://gateway-api.sigs.k8s.io/reference/spec/#policyancestorstatus
	//
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	Ancestors []gwapiv1.PolicyAncestorStatus `json:"ancestors"`
}

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// XAccessPolicy is the Schema for the accesspolicies API.
type XAccessPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of AccessPolicy.
	// +required
	Spec AccessPolicySpec `json:"spec"`

	// status defines the observed state of AccessPolicy.
	// +optional
	Status AccessPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// XAccessPolicyList contains a list of AccessPolicy.
type XAccessPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// metadata is a standard list metadata.
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []XAccessPolicy `json:"items"`
}
