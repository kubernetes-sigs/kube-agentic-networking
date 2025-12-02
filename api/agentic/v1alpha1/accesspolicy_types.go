/*
Copyright 2025.

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

// IMPORTANT: Run "make generate-all" to regenerate code after modifying this file

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// AccessPolicySpec defines the desired state of AccessPolicy.
type AccessPolicySpec struct {
	// TargetRefs specifies the targets of the AccessPolicy.
	// Currently, only Backend can be used as a target.
	// +required
	TargetRefs []gwapiv1.LocalPolicyTargetReference `json:"targetRefs"`
	// Rules defines a list of rules to be applied to the target.
	// +required
	Rules []AccessRule `json:"rules"`
}

// AccessRule specifies an authorization rule for the targeted backend.
// If the tool list is empty, the rule denies access to all tools from Source.
type AccessRule struct {
	// Source specifies the source of the request.
	// +required
	Source Source `json:"source"`
	// Tools specifies a list of tools.
	// +optional
	Tools []string `json:"tools,omitempty"`
}

// Source specifies the source of a request.
// This struct is same as the Source struct defined in https://github.com/kubernetes-sigs/gateway-api/blob/950c6639afd099b7bba4236f8b894ae4b891d26a/geps/gep-3779/index.md#api-design.
//
// At least one field may be set. If multiple fields are set,
// a request matches this Source if it matches
// **any** of the specified criteria (logical OR across fields).
//
// For example, if both `Identities` and `ServiceAccounts` are provided,
// the rule matches a request if either:
// - the request's identity is in `Identities`
// - OR the request's Serviceaccount matches an entry in `ServiceAccounts`.
//
// Each list within the fields (e.g. `Identities`) is itself an OR list.
//
// If this struct is omitted in a rule, it matches any source.
//
// <gateway:util:excludeFromCRD> NOTE: In the future, if there’s a need to express more complex
// logical conditions (e.g. requiring a request to match multiple
// criteria simultaneously—logical AND), we may evolve this API
// to support richer match expressions or logical operators. </gateway:util:excludeFromCRD>
type Source struct {

	// Identities specifies a list of identities that are matched by this rule.
	// A request's identity must be present in this list to match the rule.
	//
	// Identities must be specified as SPIFFE-formatted URIs following the pattern:
	//   spiffe://<trust_domain>/<workload-identifier>
	//
	// While the exact workload identifier structure is implementation-specific,
	// implementations are encouraged to follow the convention of
	// `spiffe://<trust_domain>/ns/<namespace>/sa/<serviceaccount>`
	// when representing Kubernetes workload identities.
	//
	// +optional
	Identities []string `json:"identities,omitempty"`

	// ServiceAccounts specifies a list of Kubernetes Service Accounts that are
	// matched by this rule. A request originating from a pod associated with
	// one of these Serviceaccounts will match the rule.
	//
	// Values must be in one of the following formats:
	//   - "<namespace>/<serviceaccount-name>": A specific Serviceaccount in a namespace.
	//   - "<namespace>/*": All Serviceaccounts in the given namespace.
	//   - "<serviceaccount-name>": a Serviceaccount in the same namespace as the policy.
	//
	// Use of "*" alone (i.e., all Serviceaccounts in all namespaces) is not allowed.
	// To select all Serviceaccounts in the current namespace, use "<namespace>/*" explicitly.
	//
	// Example:
	//   - "default/bookstore" → Matches Serviceaccount "bookstore" in namespace "default"
	//   - "payments/*" → Matches any Serviceaccount in namespace "payments"
	//   - "frontend" → Matches "frontend" Serviceaccount in the same namespace as the policy
	//
	// The ServiceAccounts listed here are expected to exist within the same
	// trust domain as the targeted workload, which in many environments means
	// the same Kubernetes cluster. Cross-cluster or cross-trust-domain access
	// should instead be expressed using the `Identities` field.
	//
	// +optional
	ServiceAccounts []string `json:"serviceAccounts,omitempty"`
}

// AccessPolicyStatus defines the observed state of AccessPolicy.
type AccessPolicyStatus struct {
	// For Policy Status API conventions, see:
	// https://gateway-api.sigs.k8s.io/geps/gep-713/#the-status-stanza-of-policy-objects
	//
	// Ancestors is a list of ancestor resources (usually Backend) that are
	// associated with the policy, and the status of the policy with respect to
	// each ancestor. When this policy attaches to a parent, the controller that
	// manages the parent and the ancestors MUST add an entry to this list when
	// the controller first sees the policy and SHOULD update the entry as
	// appropriate when the relevant ancestor is modified.
	//
	// Note that choosing the relevant ancestor is left to the Policy designers;
	// an important part of Policy design is designing the right object level at
	// which to namespace this status.
	//
	// Note also that implementations MUST ONLY populate ancestor status for
	// the Ancestor resources they are responsible for. Implementations MUST
	// use the ControllerName field to uniquely identify the entries in this list
	// that they are responsible for.
	//
	// Note that to achieve this, the list of PolicyAncestorStatus structs
	// MUST be treated as a map with a composite key, made up of the AncestorRef
	// and ControllerName fields combined.
	//
	// A maximum of 16 ancestors will be represented in this list. An empty list
	// means the Policy is not relevant for any ancestors.
	//
	// If this slice is full, implementations MUST NOT add further entries.
	// Instead they MUST consider the policy unimplementable and signal that
	// on any related resources such as the ancestor that would be referenced
	// here.
	//
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	Ancestors []gwapiv1.PolicyAncestorStatus `json:"ancestors"`
}

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// AccessPolicy is the Schema for the accesspolicies API.
type AccessPolicy struct {
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

// AccessPolicyList contains a list of AccessPolicy.
type AccessPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// metadata is a standard list metadata.
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccessPolicy `json:"items"`
}
