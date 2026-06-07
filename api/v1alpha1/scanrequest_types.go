package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ScanRequestSpec defines the target for a one-shot registry scan.
type ScanRequestSpec struct {
	// RegistryRef names the OCIRegistry CR in the same namespace to scan.
	// +kubebuilder:validation:Required
	RegistryRef corev1.LocalObjectReference `json:"registryRef"`

	// Repository narrows the scan to a specific repository.
	// +optional
	Repository string `json:"repository,omitempty"`

	// Tag narrows the scan to a specific tag.
	// +optional
	Tag string `json:"tag,omitempty"`

	// Digest narrows the scan to a specific digest.
	// +optional
	Digest string `json:"digest,omitempty"`
}

// ScanRequestStatus reflects the observed state of a ScanRequest.
type ScanRequestStatus struct {
	// Phase is the lifecycle state of the scan request.
	// A ScanRequest transitions from empty to Pending (waiting for registry) to
	// Dispatched (scan accepted by OCIDex) or Failed (API error).
	// Once terminal (Dispatched or Failed) the controller does not re-fire the scan.
	// +kubebuilder:validation:Enum=Pending;Dispatched;Failed
	// +optional
	Phase string `json:"phase,omitempty"`

	// Conditions describe the current state.
	// The Dispatched condition is True when the OCIDex API accepted the scan request.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=scanreq
// +kubebuilder:printcolumn:name="Registry",type=string,JSONPath=`.spec.registryRef.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ScanRequest is a one-shot trigger that dispatches an ad-hoc scan for the
// referenced OCIRegistry. Once the scan is accepted by OCIDex the CR enters
// a terminal Dispatched state and is not re-fired.
type ScanRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ScanRequestSpec   `json:"spec,omitempty"`
	Status ScanRequestStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ScanRequestList contains a list of ScanRequest.
type ScanRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ScanRequest `json:"items"`
}
