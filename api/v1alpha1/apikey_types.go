package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// APIKeySpec defines the desired state of an OCIDex API key.
type APIKeySpec struct {
	// Name is a human-readable label for the key.
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Scope controls what operations the key permits.
	// +kubebuilder:validation:Enum=read;read-write
	// +kubebuilder:default=read
	// +optional
	Scope string `json:"scope,omitempty"`

	// SecretRef names the Secret (in the same namespace) where the plaintext
	// API key will be written under the "api-key" data key.
	// +kubebuilder:validation:Required
	SecretRef corev1.LocalObjectReference `json:"secretRef"`
}

// APIKeyStatus reflects the observed state of an APIKey.
type APIKeyStatus struct {
	// KeyID is the OCIDex UUID of the provisioned API key.
	KeyID string `json:"keyID,omitempty"`

	// Prefix is the first 12 characters of the key, safe to expose for
	// identification without revealing the full credential.
	Prefix string `json:"prefix,omitempty"`

	// Conditions describe the current state.
	// The Ready condition is True when the key exists in OCIDex and the Secret
	// is up to date.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=apikey
// +kubebuilder:printcolumn:name="Scope",type=string,JSONPath=`.spec.scope`
// +kubebuilder:printcolumn:name="Prefix",type=string,JSONPath=`.status.prefix`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// APIKey declaratively provisions an OCIDex API key and writes the plaintext
// credential into the referenced Kubernetes Secret.
type APIKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   APIKeySpec   `json:"spec,omitempty"`
	Status APIKeyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// APIKeyList contains a list of APIKey.
type APIKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []APIKey `json:"items"`
}
