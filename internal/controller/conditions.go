package controller

import (
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetCondition upserts a status condition on the given slice.
// It is a thin wrapper around apimeta.SetStatusCondition shared across all reconcilers.
func SetCondition(conditions *[]metav1.Condition, condType string, status metav1.ConditionStatus, reason, msg string, generation int64) {
	apimeta.SetStatusCondition(conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: generation,
	})
}
