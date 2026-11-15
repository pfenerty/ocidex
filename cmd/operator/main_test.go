package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// The operator's ClusterRole grants Secrets get only (the kubebuilder markers
// in internal/controller). A cached read needs list and watch, so Secrets must
// stay out of the cache or every authSecretRef read hangs (ocidex-osrl.1).
func TestSecretsBypassTheCache(t *testing.T) {
	for _, o := range uncachedObjects() {
		if _, ok := o.(*corev1.Secret); ok {
			return
		}
	}
	t.Fatal("corev1.Secret must be in uncachedObjects: the role does not grant list/watch on secrets")
}
