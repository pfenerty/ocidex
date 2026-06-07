package controller

import (
	"context"
	"errors"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/pfenerty/ocidex/api/v1alpha1"
	ocidexclient "github.com/pfenerty/ocidex/pkg/client"
)

const (
	requeueWhenPending = 10 * time.Second
	phaseDispatched    = "Dispatched"
	phaseFailed        = "Failed"
	phasePending       = "Pending"
)

// ScanRequestReconciler reconciles ScanRequest resources.
type ScanRequestReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	OCIDexClient ocidexclient.Client
}

// Reconcile is the main reconcile loop for ScanRequest.
//
// Contract (ADR-030): ScanRequest is a one-shot fire-and-forget trigger.
// Once phase reaches Dispatched or Failed it is terminal; the controller
// becomes a no-op for that CR. No finalizer is used.
func (r *ScanRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	cr := &v1alpha1.ScanRequest{}
	if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Terminal guard — never re-dispatch.
	if cr.Status.Phase == phaseDispatched || cr.Status.Phase == phaseFailed {
		return ctrl.Result{}, nil
	}

	// Look up the referenced OCIRegistry in the same namespace.
	reg := &v1alpha1.OCIRegistry{}
	regKey := types.NamespacedName{Name: cr.Spec.RegistryRef.Name, Namespace: cr.Namespace}
	if err := r.Get(ctx, regKey, reg); err != nil {
		if client.IgnoreNotFound(err) == nil {
			SetCondition(&cr.Status.Conditions, phaseDispatched, metav1.ConditionFalse, "RegistryNotFound",
				"referenced OCIRegistry not found", cr.Generation)
			cr.Status.Phase = phaseFailed
			return ctrl.Result{}, r.Status().Update(ctx, cr)
		}
		return ctrl.Result{}, err
	}

	if reg.Status.RegistryID == "" {
		SetCondition(&cr.Status.Conditions, phaseDispatched, metav1.ConditionFalse, "RegistryNotReady",
			"OCIRegistry has no registryID yet; waiting", cr.Generation)
		cr.Status.Phase = phasePending
		return ctrl.Result{RequeueAfter: requeueWhenPending}, r.Status().Update(ctx, cr)
	}

	if _, err := r.OCIDexClient.ScanRegistry(ctx, reg.Status.RegistryID); err != nil {
		if !errors.Is(err, ocidexclient.ErrNotFound) {
			SetCondition(&cr.Status.Conditions, phaseDispatched, metav1.ConditionFalse, "APIError", err.Error(), cr.Generation)
			cr.Status.Phase = phaseFailed
			_ = r.Status().Update(ctx, cr)
			return ctrl.Result{}, err
		}
		SetCondition(&cr.Status.Conditions, phaseDispatched, metav1.ConditionFalse, "RegistryNotFound",
			"registry not found in OCIDex", cr.Generation)
		cr.Status.Phase = phaseFailed
		return ctrl.Result{}, r.Status().Update(ctx, cr)
	}

	SetCondition(&cr.Status.Conditions, phaseDispatched, metav1.ConditionTrue, phaseDispatched, "", cr.Generation)
	cr.Status.Phase = phaseDispatched
	return ctrl.Result{}, r.Status().Update(ctx, cr)
}

// SetupWithManager registers the controller with the manager.
// No GenerationChangedPredicate: spec is immutable after creation; the phase
// guard in Reconcile prevents re-dispatch on status-write re-reconciles.
func (r *ScanRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ScanRequest{}).
		Complete(r)
}
