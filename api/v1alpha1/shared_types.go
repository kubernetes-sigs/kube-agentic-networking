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

// HTTPPathMatch describes how to select a HTTP route by matching the HTTP request path.
type HTTPPathMatch struct {
	// Type specifies how to match against the path Value.
	// +optional
	// +kubebuilder:default=PathPrefix
	Type *PathMatchType `json:"type,omitempty"`

	// Value of the HTTP path to match against.
	// +optional
	// +kubebuilder:default=""
	// +kubebuilder:validation:MaxLength=1024
	Value *string `json:"value,omitempty"`
}

// PathMatchType specifies the semantics of how HTTP paths should be compared.
// +kubebuilder:validation:Enum=Exact;PathPrefix;RegularExpression
type PathMatchType string

const (
	// PathMatchExact matches the exact HTTP path.
	PathMatchExact PathMatchType = "Exact"

	// PathMatchPathPrefix matches based on a URL path prefix split by `/`.
	PathMatchPathPrefix PathMatchType = "PathPrefix"

	// PathMatchRegularExpression matches if the HTTP path matches the specified RE2 regular expression.
	PathMatchRegularExpression PathMatchType = "RegularExpression"
)

// HTTPHeaderMatch describes how to select a HTTP route by matching HTTP request headers.
type HTTPHeaderMatch struct {
	// Type specifies how to match against the value of the header.
	// +optional
	// +kubebuilder:default=Exact
	Type *HeaderMatchType `json:"type,omitempty"`

	// Name is the name of the HTTP Header to be matched.
	// +required
	Name HTTPHeaderName `json:"name"`

	// Value is the value of HTTP Header to be matched.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	Value string `json:"value"`
}

// HeaderMatchType specifies the semantics of how HTTP header values should be compared.
// +kubebuilder:validation:Enum=Exact;RegularExpression
type HeaderMatchType string

const (
	// HeaderMatchExact matches the exact HTTP header value.
	HeaderMatchExact HeaderMatchType = "Exact"

	// HeaderMatchRegularExpression matches if the HTTP header value matches the specified RE2 regular expression.
	HeaderMatchRegularExpression HeaderMatchType = "RegularExpression"
)

// HTTPHeaderName is the name of an HTTP header.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=256
// +kubebuilder:validation:Pattern=`^[A-Za-z0-9!#$%&'*+\-.^_\x60|~]+$`
type HTTPHeaderName string

// HTTPMethod describes how to select a HTTP route by matching the HTTP method.
// +kubebuilder:validation:Enum=GET;HEAD;POST;PUT;DELETE;CONNECT;OPTIONS;TRACE;PATCH
type HTTPMethod string

// Hostname is the fully qualified domain name of a network host.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^(\*\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
type Hostname string

// PortNumber defines a network port.
// +kubebuilder:validation:Minimum=1
// +kubebuilder:validation:Maximum=65535
type PortNumber int32
