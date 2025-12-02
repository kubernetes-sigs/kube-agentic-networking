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
)

// BackendSpec defines the desired state of Backend.
type BackendSpec struct {
	// Type specifies the type of the backend.
	// Currently, only "MCP" is supported.
	// +required
	Type *BackendType `json:"type"`

	// MCP defines a MCP backend.
	// +optional
	MCP MCPBackend `json:"mcp,omitempty"`
}

// BackendType defines the type of the Backend.
// +kubebuilder:validation:Enum=MCP
type BackendType string

const (
	// BackendTypeMCP defines the type of the backend as MCP.
	BackendTypeMCP BackendType = "MCP"
)

// MCPBackend describes a MCP Backend.
// ServiceName and Hostname cannot be defined at the same time.
// +kubebuilder:validation:ExactlyOneOf=serviceName;hostname
type MCPBackend struct {
	// ServiceName defines the Kubernetes Service name of a MCP backend.
	// +optional
	ServiceName string `json:"serviceName,omitempty"`

	// Hostname defines the hostname of the external MCP service to connect to.
	// +optional
	Hostname string `json:"hostname,omitempty"`

	// Port defines the port of the backend endpoint.
	// +required
	Port int32 `json:"port"`

	// Path is the URL path of the MCP backend for MCP traffic.
	// A MCP backend may serve both MCP traffic and non-MCP traffic.
	// If not specified, the default is /mcp.
	// +optional
	// +kubebuilder:default:=/mcp
	Path string `json:"path,omitempty"`
}

// BackendStatus defines the observed state of Backend.
type BackendStatus struct {
	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// conditions represent the current state of the Backend resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Backend is the Schema for the backends API.
type Backend struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of Backend.
	// +required
	Spec BackendSpec `json:"spec"`

	// status defines the observed state of Backend.
	// +optional
	Status BackendStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BackendList contains a list of Backend.
type BackendList struct {
	metav1.TypeMeta `json:",inline"`
	// metadata is a standard list metadata.
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Backend `json:"items"`
}
