package v0alpha0

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
type KANConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KANConfigSpec   `json:"spec,omitempty"`
	Status KANConfigStatus `json:"status,omitempty"`
}

type KANConfigSpec struct {
	// +required
	ProxyImage string `json:"proxyImage"`
	// +optional
	// +kubebuilder:default=2
	WorkerCount int `json:"workerCount,omitempty"`
	// +optional
	AgenticIdentityTrustDomain string `json:"agenticIdentityTrustDomain,omitempty"`
	// +optional
	EnableAgenticIdentitySigner bool `json:"enableAgenticIdentitySigner,omitempty"`
}

// KANConfigStatus reflects the observed state of a KANConfig.
type KANConfigStatus struct {
	// ObservedGeneration is the generation of the spec last processed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions describe the current state of the KANConfig.
	// Known condition types: Accepted, Applied.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ReferencedBy lists the names of GatewayClasses currently referencing this KANConfig.
	// +optional
	ReferencedBy []string `json:"referencedBy,omitempty"`

	// ActiveWorkerCount is the effective number of workers currently running.
	// This may differ from spec.workerCount when the spec value is 0 and the
	// controller default applies.
	// +optional
	ActiveWorkerCount int `json:"activeWorkerCount,omitempty"`
}

type KANConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KANConfig `json:"items"`
}