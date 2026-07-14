package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OCIRegistrySpec defines the desired state of an OCI registry registration.
type OCIRegistrySpec struct {
	// URL is the registry address (e.g. "zot:5000" or "ghcr.io").
	// +kubebuilder:validation:Required
	URL string `json:"url"`

	// Name is a human-readable label for the registry.
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Type is the registry implementation.
	// +kubebuilder:validation:Enum=docker;generic;ghcr;harbor;zot
	// +kubebuilder:validation:Required
	Type string `json:"type"`

	// Visibility controls whether the registry is publicly listed.
	// +kubebuilder:validation:Enum=public;private
	// +kubebuilder:default=private
	// +optional
	Visibility string `json:"visibility,omitempty"`

	// Insecure allows HTTP (non-TLS) connections.
	// +optional
	Insecure bool `json:"insecure,omitempty"`

	// ScanMode controls how OCIDex discovers new images.
	// +kubebuilder:validation:Enum=poll;webhook;both
	// +kubebuilder:default=poll
	// +optional
	ScanMode string `json:"scanMode,omitempty"`

	// PollIntervalMinutes is the time between registry polls.
	// +optional
	PollIntervalMinutes *int64 `json:"pollIntervalMinutes,omitempty"`

	// Repositories is an explicit list of repositories to walk; bypasses catalog
	// discovery when non-empty.
	// +optional
	Repositories []string `json:"repositories,omitempty"`

	// RepositoryPatterns are glob patterns for repositories to ingest. Empty means all.
	// +optional
	RepositoryPatterns []string `json:"repositoryPatterns,omitempty"`

	// TagPatterns are glob patterns or "semver" for tags to ingest. Empty means all.
	// +optional
	TagPatterns []string `json:"tagPatterns,omitempty"`

	// IncludeUntagged enables scanning of untagged manifests (zot/harbor/ghcr only).
	// +optional
	IncludeUntagged bool `json:"includeUntagged,omitempty"`

	// AuthSecretRef references a Secret containing "username" and "token" keys for
	// registry authentication. Omit for anonymous access.
	// +optional
	AuthSecretRef *corev1.LocalObjectReference `json:"authSecretRef,omitempty"`

	// VerificationMode controls signature verification for images in this registry.
	// +kubebuilder:validation:Enum=none;public_key
	// +kubebuilder:default=none
	// +optional
	VerificationMode string `json:"verificationMode,omitempty"`

	// TrustPublicKey is a PEM-encoded EC public key, required when VerificationMode is public_key.
	// +optional
	TrustPublicKey *string `json:"trustPublicKey,omitempty"`
}

// OCIRegistryStatus reflects the observed state of an OCIRegistry.
type OCIRegistryStatus struct {
	// RegistryID is the OCIDex UUID assigned on creation.
	RegistryID string `json:"registryID,omitempty"`

	// Conditions describe the current state of the registry.
	// The Ready condition is True when the registry exists in OCIDex and spec is in sync.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ocireg
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.url`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OCIRegistry declaratively registers an OCI registry with OCIDex.
type OCIRegistry struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OCIRegistrySpec   `json:"spec,omitempty"`
	Status OCIRegistryStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OCIRegistryList contains a list of OCIRegistry.
type OCIRegistryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OCIRegistry `json:"items"`
}
