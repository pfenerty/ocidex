// Package v1alpha1 contains API types for the ocidex.io/v1alpha1 API group.
//
// +groupName=ocidex.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersion is the API group and version for this package.
var GroupVersion = schema.GroupVersion{Group: "ocidex.io", Version: "v1alpha1"}

// SchemeBuilder is used to add functions to the API group scheme.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme adds the types in this group-version to the given scheme.
var AddToScheme = SchemeBuilder.AddToScheme

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&OCIRegistry{}, &OCIRegistryList{},
		&ScanRequest{}, &ScanRequestList{},
		&APIKey{}, &APIKeyList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
