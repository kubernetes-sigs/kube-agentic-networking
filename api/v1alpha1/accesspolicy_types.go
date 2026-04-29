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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// AccessPolicySpec defines the desired state of AccessPolicy.
//
// Implementations SHOULD return a regular HTTP formatted response if the policy is enforced against non-MCP traffic.
// Implementations MAY return a JSON-RPC formatted response if the policy is enforced against MCP traffic.
// +kubebuilder:validation:XValidation:rule="self.action == 'ExternalAuth' ? has(self.externalAuth) : true",message="externalAuth must be specified when action is set to 'ExternalAuth'"
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
	// An AccessPolicy must have at least one rule.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	// +listType=atomic
	// +kubebuilder:validation:XValidation:rule="self.all(r, self.filter(x, x.name == r.name).size() == 1)",message="AccessRule names must be unique"
	Rules []AccessRule `json:"rules"`
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
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// Source specifies the source of the request.
	// +required
	Source AccessRuleSource `json:"source"`
	// Authorization specifies the authorization rule to be applied to requests from the source.
	// If omitted, all access from the specified source is allowed.
	// +optional
	Authorization *AuthorizationRule `json:"authorization,omitempty"`
}

// AccessRuleSource specifies the source of a request.
//
// Type must be set to indicate the source type.
// Similarly, either SPIFFE or Serviceaccount can be set based on the type.
type AccessRuleSource struct {
	// +unionDiscriminator
	// +required
	Type AuthorizationSourceType `json:"type"`

	// spiffe specifies an identity that is matched by this rule.
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

	// serviceAccount specifies a Kubernetes Service Account that is
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

// AuthorizationRule defines the specific authorization criteria that requests must meet.
type AuthorizationRule struct {
	// +unionDiscriminator
	// +required
	Type AuthorizationRuleType `json:"type"`

	// MCP defines MCP-specific matching criteria.
	// If omitted, the policy does not check MCP-level parameters, allowing all MCP traffic that
	// successfully passes through the matched HTTP routing envelope.
	// +optional
	MCP MCPAttributes `json:"mcp,omitempty"`
}

// MCPAttributes defines the protocol-specific attributes for MCP authorization.
type MCPAttributes struct {
	// Methods is a list of specific MCP functional methods to match.
	// If specified, only MCP requests with a method
	// that matches one of these items will be authorized.
	// If empty or omitted, no method-level whitelisting is applied, meaning all
	// MCP methods (e.g., all tools, prompts, and resources) are permitted.
	// +kubebuilder:validation:MaxItems=10
	// +optional
	// +listType=map
	// +listMapKey=name
	Methods []MCPMethod `json:"methods,omitempty"`
}

// MCPMethod defines a specific MCP method and its associated parameters.
// +kubebuilder:validation:XValidation:rule="has(self.params) && self.params.size() > 0 ? self.name in ['prompts/get', 'tools/call', 'resources/subscribe', 'resources/unsubscribe', 'resources/read'] : true",message="Params can only be specified for get, call, subscribe, unsubscribe, or read methods"
type MCPMethod struct {
	// Name is the MCP method to match against (e.g., 'tools/call').
	// Allowed values:
	// 1. 'tools', 'prompts', 'resources': Matches all sub-methods under these categories.
	// 2. 'prompts/list', 'tools/list', 'resources/list', 'resources/templates/list'.
	// 3. 'prompts/get', 'tools/call', 'resources/subscribe', 'resources/unsubscribe', 'resources/read'.
	// Parameters cannot be specified for categories 1 and 2.
	// +required
	Name MCPMethodName `json:"name"`

	// Params allows matching against specific arguments in the MCP request.
	// Only valid for 'get', 'call', 'subscribe', 'unsubscribe', and 'read' methods.
	// If empty or omitted, parameter-level whitelisting is not applied, meaning the method
	// is authorized regardless of the arguments passed in the request.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=10
	Params []MCPMethodParam `json:"params,omitempty"`
}

// +kubebuilder:validation:MaxLength=20
type MCPMethodParam string

// MCPMethodName defines the allowed MCP methods for matching.
// +kubebuilder:validation:Enum=tools;prompts;resources;prompts/list;tools/list;resources/list;resources/templates/list;prompts/get;tools/call;resources/subscribe;resources/unsubscribe;resources/read
type MCPMethodName string

// AuthorizationRuleType identifies a type of authorization rule.
// +kubebuilder:validation:Enum=Inline
type AuthorizationRuleType string

const (
	// AuthorizationRuleTypeInline is used to identify authorization rules
	// declared as attributes inside the policy (inline)
	AuthorizationRuleTypeInline AuthorizationRuleType = "Inline"
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
	//
	PolicyConditionAccepted gwapiv1.PolicyConditionType = "Accepted"

	// This reason is used with the "Accepted" condition when the policy
	// has been accepted by the controller.
	PolicyReasonAccepted gwapiv1.PolicyConditionReason = "Accepted"

	// This reason is used with the "Accepted" condition when the policy
	// was rejected because the maximum number of policies per target was exceeded.
	PolicyLimitPerTargetExceeded gwapiv1.PolicyConditionReason = "LimitPerTargetExceeded"
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
// +kubebuilder:storageversion

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
