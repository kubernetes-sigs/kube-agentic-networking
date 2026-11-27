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

// IMPORTANT: Run "make generate" to regenerate code after modifying this file

package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// AccessPolicySpec defines the desired state of AccessPolicy.
//
// Implementations SHOULD return a regular HTTP formatted response when the policy denies a request.
// +kubebuilder:validation:XValidation:rule="self.action == 'ExternalAuth' ? has(self.externalAuth) : true",message="externalAuth must be specified when action is set to 'ExternalAuth'"
// +kubebuilder:validation:XValidation:rule="self.action != 'ExternalAuth' ? !has(self.externalAuth) : true",message="externalAuth must not be specified when action is not 'ExternalAuth'"
type AccessPolicySpec struct {
	// TargetRefs specifies the targets of the AccessPolicy.
	// An AccessPolicy must target at least one resource.
	// There is one kind of TargetRef with "Core" support:
	//
	// * Gateway
	//
	// This API may be extended in the future to support additional kinds of targetRefs.
	// Implementations may support additional kinds in an implementation specific manner.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	// +listType=atomic
	// +kubebuilder:validation:XValidation:rule="self.all(ref, ref.kind == self[0].kind)",message="All targetRefs must have the same Kind"
	TargetRefs []gwapiv1.LocalPolicyTargetReferenceWithSectionName `json:"targetRefs"`

	// Action specifies the action to be taken when rules match.
	// Evaluation logic:
	// 1. ExternalAuth runs before all other Allow policies.
	// 2. If an ExternalAuth server denies the request, the request is denied.
	// 3. If it allows the request, processing continues for all other allow policies for that target.
	// 4. The request is allowed only if all allow policies allow it.
	// +required
	Action AccessPolicyActionType `json:"action"`

	// ExternalAuth specifies an external auth filter to be used for authorization.
	// Core support is limited to 1 ExternalAuth callout per target.
	// +optional
	ExternalAuth *gwapiv1.HTTPExternalAuthFilter `json:"externalAuth,omitempty"`

	// Rules defines a list of rules to be applied to the target.
	// The interpretation of these rules depends on the Action:
	// - For ActionTypeAllow: A request is allowed if it matches any of the rules.
	// - For ActionTypeExternalAuth: A request is delegated to the external authorizer if it matches any of the rules.
	// If omitted, the policy applies to all traffic (equivalent to matching any request).
	// +optional
	// +kubebuilder:validation:MaxItems=10
	// +listType=atomic
	// +kubebuilder:validation:XValidation:rule="self.all(r, self.filter(x, x.name == r.name).size() == 1)",message="AccessRule names must be unique"
	Rules []AccessRule `json:"rules,omitempty"`
}

// AccessPolicyActionType identifies a type of action for access policy.
// +kubebuilder:validation:Enum=Allow;ExternalAuth
type AccessPolicyActionType string

const (
	// ActionTypeAllow is used to identify that the request should be allowed if rules match.
	ActionTypeAllow AccessPolicyActionType = "Allow"

	// ActionTypeExternalAuth is used to identify that the request should be delegated to an external auth service if rules match.
	ActionTypeExternalAuth AccessPolicyActionType = "ExternalAuth"
)

// AccessRule specifies an authorization rule for a specified target.
type AccessRule struct {
	// Name specifies the name of the rule.
	// This follows the DNS Subdomain naming convention.
	// See: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names
	// +required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`
	// Source specifies the source of the request.
	// If omitted, requests from any source are allowed.
	// +optional
	Source *AccessRuleSource `json:"source,omitempty"`
	// Authorization specifies the authorization rule to be applied to requests matching the source criteria.
	// If omitted, all access matching the source criteria is allowed.
	// +optional
	Authorization *AuthorizationRule `json:"authorization,omitempty"`
}

// AccessRuleSource specifies the source of a request.
//
// Type must be set to indicate the source type.
// Similarly, either SPIFFE or ServiceAccount can be set based on the type.
// +kubebuilder:validation:XValidation:rule="self.type == 'SPIFFE' ? has(self.spiffe) : !has(self.spiffe)",message="spiffe must be specified when type is 'SPIFFE' and must not be specified otherwise"
// +kubebuilder:validation:XValidation:rule="self.type == 'ServiceAccount' ? has(self.serviceAccount) : !has(self.serviceAccount)",message="serviceAccount must be specified when type is 'ServiceAccount' and must not be specified otherwise"
type AccessRuleSource struct {
	// Type identifies which source field is set.
	// +unionDiscriminator
	// +required
	Type AuthorizationSourceType `json:"type"`

	// SPIFFE specifies an identity that is matched by this rule.
	//
	// spiffe identities must be specified as SPIFFE-formatted URIs following the pattern:
	//   spiffe://<trust_domain>/<workload-identifier>
	//
	// The exact workload identifier structure is implementation-specific.
	// This will likely change in the future.
	//
	// SPIFFE identities for authorization can be derived in various ways by the underlying
	// implementation. Common methods include:
	// - From peer mTLS certificates: The identity is extracted from the client's
	//   mTLS certificate presented during connection establishment.
	// - From IP-to-identity mappings: The implementation might maintain a dynamic
	//   mapping between source IP addresses (pod IPs) and their associated
	//   identities (e.g., Service Account, SPIFFE IDs).
	// - From JWTs or other request-level authentication tokens.
	//
	// +optional
	SPIFFE *AuthorizationSourceSPIFFE `json:"spiffe,omitempty"`

	// ServiceAccount specifies a Kubernetes Service Account that is
	// matched by this rule. A request originating from a pod associated with
	// this Service Account will match the rule.
	//
	// The Service Account listed here is expected to exist within the same
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

// AuthorizationSourceSPIFFE is a SPIFFE ID of the form spiffe://<trust_domain>/<workload-identifier>.
// +kubebuilder:validation:MaxLength=2048
// +kubebuilder:validation:Pattern=`^spiffe://[a-z0-9._-]+(?:/[A-Za-z0-9._-]+)+$`
type AuthorizationSourceSPIFFE string

// AuthorizationSourceServiceAccount identifies a Kubernetes ServiceAccount.
type AuthorizationSourceServiceAccount struct {
	// Namespace is the namespace of the ServiceAccount.
	// If not specified, the namespace of the policy is used.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Namespace string `json:"namespace,omitempty"`

	// Name is the name of the ServiceAccount.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name"`
}

// +kubebuilder:validation:XValidation:message="cel must be specified when type is set to 'CEL'",rule="self.type == 'CEL' ? has(self.cel) : true"
// +kubebuilder:validation:XValidation:message="cel must not be specified when type is set to 'Inline'",rule="self.type == 'Inline' ? !has(self.cel) : true"
// +kubebuilder:validation:XValidation:message="Inline authorization must specify at least one matcher (methods, paths, headers, hosts, or ports)",rule="self.type == 'Inline' ? (has(self.methods) || has(self.paths) || has(self.headers) || has(self.hosts) || has(self.ports)) : true"
// +kubebuilder:validation:XValidation:message="methods, paths, headers, hosts and ports must not be specified when type is set to 'CEL'",rule="self.type == 'CEL' ? (!has(self.methods) && !has(self.paths) && !has(self.headers) && !has(self.hosts) && !has(self.ports)) : true"
// AuthorizationRule defines the specific authorization criteria that requests must meet.
type AuthorizationRule struct {
	// +unionDiscriminator
	// +required
	Type AuthorizationRuleType `json:"type"`

	// Methods is a list of HTTP methods to match against.
	// If specified, the request method must match one of the items in the list (OR semantics across list items).
	// If empty or omitted, any HTTP method is allowed.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=9
	// +listType=set
	// +optional
	Methods []gwapiv1.HTTPMethod `json:"methods,omitempty"`

	// Paths is a list of HTTP request path matchers to match against.
	// If specified, the request path must match one of the items in the list (OR semantics across list items).
	// If empty or omitted, any request path is allowed.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	// +listType=atomic
	// +optional
	Paths []gwapiv1.HTTPPathMatch `json:"paths,omitempty"`

	// Headers is a list of HTTP request header matchers to match against.
	// All specified headers must match (AND semantics across list items).
	// If empty or omitted, no header checking is applied.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	// +listType=atomic
	// +optional
	Headers []gwapiv1.HTTPHeaderMatch `json:"headers,omitempty"`

	// Hosts is a list of HTTP request host matchers to match against.
	// If specified, the request host / authority header must match one of the items in the list (OR semantics across list items).
	// If empty or omitted, any host is allowed.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	// +listType=set
	// +optional
	Hosts []gwapiv1.Hostname `json:"hosts,omitempty"`

	// Ports is a list of destination ports to match against.
	// If specified, the request destination port must match one of the items in the list (OR semantics across list items).
	// If empty or omitted, any destination port is allowed.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	// +kubebuilder:validation:XValidation:rule="self.all(p, p >= 1 && p <= 65535)",message="ports must be between 1 and 65535"
	// +listType=set
	// +optional
	Ports []gwapiv1.PortNumber `json:"ports,omitempty"`

	// CEL specifies a CEL expression for authorization.
	// +optional
	CEL *AccessPolicyCELRule `json:"cel,omitempty"`
}

// AccessPolicyCELRule specifies a CEL expression for authorization.
type AccessPolicyCELRule struct {
	// Expression is the CEL expression to evaluate.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	Expression string `json:"expression"`
}

// AuthorizationRuleType identifies a type of authorization rule.
// +kubebuilder:validation:Enum=Inline;CEL
type AuthorizationRuleType string

const (
	// AuthorizationRuleTypeInline is used to identify authorization rules
	// declared as attributes inside the policy (inline).
	AuthorizationRuleTypeInline AuthorizationRuleType = "Inline"

	// AuthorizationRuleTypeCEL is used to identify authorization rules
	// evaluated by a CEL expression.
	AuthorizationRuleTypeCEL AuthorizationRuleType = "CEL"
)

const (
	// PolicyConditionAccepted indicates whether the policy has been accepted by the controller.
	//
	// Possible reasons for this condition to be True are:
	//
	// * "Accepted"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "LimitPerTargetExceeded"
	// * "InvalidCEL"
	//
	PolicyConditionAccepted gwapiv1.PolicyConditionType = "Accepted"

	// PolicyReasonAccepted is used with the "Accepted" condition when the policy
	// has been accepted by the controller.
	PolicyReasonAccepted gwapiv1.PolicyConditionReason = "Accepted"

	// PolicyReasonLimitPerTargetExceeded is used with the "Accepted" condition when the policy
	// was rejected because the maximum number of policies per target was exceeded.
	PolicyReasonLimitPerTargetExceeded gwapiv1.PolicyConditionReason = "LimitPerTargetExceeded"

	// PolicyReasonInvalidCEL is used with the "Accepted" condition when the policy
	// was rejected because it contains an invalid CEL expression.
	PolicyReasonInvalidCEL gwapiv1.PolicyConditionReason = "InvalidCEL"
)

// AccessPolicyStatus defines the observed state of AccessPolicy.
type AccessPolicyStatus struct {
	// For Policy Status API conventions, see:
	// https://gateway-api.sigs.k8s.io/geps/gep-713/#the-status-stanza-of-policy-objects
	//
	// Ancestors is a list of ancestor resources (usually Gateway or Mesh) of
	// the policy target which are enforcement points for the
	// policy, and the status of the policy with respect to each ancestor.

	// +required
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	Ancestors []gwapiv1.PolicyAncestorStatus `json:"ancestors"`
}

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:unservedversion

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
