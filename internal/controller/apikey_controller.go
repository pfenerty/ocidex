package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v1alpha1 "github.com/pfenerty/ocidex/api/v1alpha1"
	ocidexclient "github.com/pfenerty/ocidex/pkg/client"
)

const (
	apiKeyFinalizer    = "ocidex.io/apikey-protection" //nolint:gosec // Kubernetes finalizer, not a credential
	apiKeyVerifyPeriod = 5 * time.Minute
)

// APIKeyReconciler reconciles APIKey resources.
type APIKeyReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	OCIDexClient ocidexclient.Client
}

// Reconcile is the main reconcile loop for APIKey.
//
//+kubebuilder:rbac:groups=ocidex.io,resources=apikeys,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ocidex.io,resources=apikeys/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;create;update;patch;delete

// Contract (ADR-030):
//  1. Deletion: call DeleteAPIKey, delete Secret, remove finalizer.
//  2. Add finalizer; re-fetch; continue (GenerationChangedPredicate filters the event).
//  3. Create when status.keyID is empty: CreateAPIKey → ListAPIKeys (find by prefix) → write Secret.
//  4. Verify/rotate when status.keyID is set:
//     - If key missing from list → clear keyID, requeue (re-creates on next call).
//     - If generation advanced → rotate (delete old, create new, update Secret).
//     - Otherwise → verify only, requeue after 5 min.
func (r *APIKeyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	cr := &v1alpha1.APIKey{}
	if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !cr.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, cr)
	}

	if !controllerutil.ContainsFinalizer(cr, apiKeyFinalizer) {
		controllerutil.AddFinalizer(cr, apiKeyFinalizer)
		if err := r.Update(ctx, cr); err != nil {
			return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
		}
		if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}

	if cr.Status.KeyID == "" {
		return r.createAndPersist(ctx, cr)
	}

	return r.verifyOrRotate(ctx, cr)
}

func (r *APIKeyReconciler) createAndPersist(ctx context.Context, cr *v1alpha1.APIKey) (ctrl.Result, error) {
	scope := ocidexclient.CreateAPIKeyInputBodyScope(cr.Spec.Scope)
	out, err := r.OCIDexClient.CreateAPIKey(ctx, ocidexclient.CreateAPIKeyInputBody{
		Name:  cr.Spec.Name,
		Scope: &scope,
	})
	if err != nil {
		SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionFalse, "APIError", err.Error(), cr.Generation)
		_ = r.Status().Update(ctx, cr)
		return ctrl.Result{}, err
	}

	keyID, prefix, err := r.findKeyByPrefix(ctx, out.Key)
	if err != nil {
		SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionFalse, "LookupError", err.Error(), cr.Generation)
		_ = r.Status().Update(ctx, cr)
		return ctrl.Result{}, err
	}

	if err := r.writeSecret(ctx, cr, out.Key); err != nil {
		SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionFalse, "SecretWriteError", err.Error(), cr.Generation)
		_ = r.Status().Update(ctx, cr)
		return ctrl.Result{}, err
	}

	cr.Status.KeyID = keyID
	cr.Status.Prefix = prefix
	SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionTrue, "Created", "", cr.Generation)
	return ctrl.Result{}, r.Status().Update(ctx, cr)
}

func (r *APIKeyReconciler) verifyOrRotate(ctx context.Context, cr *v1alpha1.APIKey) (ctrl.Result, error) {
	keys, err := r.OCIDexClient.ListAPIKeys(ctx)
	if err != nil {
		SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionFalse, "APIError", err.Error(), cr.Generation)
		_ = r.Status().Update(ctx, cr)
		return ctrl.Result{}, err
	}

	found := false
	for _, k := range keys {
		if k.Id == cr.Status.KeyID {
			found = true
			break
		}
	}

	if !found {
		cr.Status.KeyID = ""
		cr.Status.Prefix = ""
		SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionFalse, "KeyMissing",
			"API key deleted externally; will re-create", cr.Generation)
		return ctrl.Result{Requeue: true}, r.Status().Update(ctx, cr)
	}

	// Check if spec changed since last successful reconcile.
	ready := apimeta.FindStatusCondition(cr.Status.Conditions, "Ready")
	if ready != nil && ready.Status == metav1.ConditionTrue && ready.ObservedGeneration < cr.Generation {
		return r.rotate(ctx, cr)
	}

	SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionTrue, "Synced", "", cr.Generation)
	return ctrl.Result{RequeueAfter: apiKeyVerifyPeriod}, r.Status().Update(ctx, cr)
}

func (r *APIKeyReconciler) rotate(ctx context.Context, cr *v1alpha1.APIKey) (ctrl.Result, error) {
	if err := r.OCIDexClient.DeleteAPIKey(ctx, cr.Status.KeyID); err != nil && !errors.Is(err, ocidexclient.ErrNotFound) {
		SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionFalse, "RotateError", err.Error(), cr.Generation)
		_ = r.Status().Update(ctx, cr)
		return ctrl.Result{}, err
	}
	cr.Status.KeyID = ""
	cr.Status.Prefix = ""
	return r.createAndPersist(ctx, cr)
}

func (r *APIKeyReconciler) handleDeletion(ctx context.Context, cr *v1alpha1.APIKey) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(cr, apiKeyFinalizer) {
		return ctrl.Result{}, nil
	}
	if cr.Status.KeyID != "" {
		if err := r.OCIDexClient.DeleteAPIKey(ctx, cr.Status.KeyID); err != nil && !errors.Is(err, ocidexclient.ErrNotFound) {
			SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionFalse, "DeleteError", err.Error(), cr.Generation)
			_ = r.Status().Update(ctx, cr)
			return ctrl.Result{}, err
		}
	}
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{Name: cr.Spec.SecretRef.Name, Namespace: cr.Namespace}
	if err := r.Get(ctx, secretKey, secret); err == nil {
		if err := r.Delete(ctx, secret); client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, fmt.Errorf("deleting Secret: %w", err)
		}
	}
	controllerutil.RemoveFinalizer(cr, apiKeyFinalizer)
	return ctrl.Result{}, r.Update(ctx, cr)
}

// SetupWithManager registers the controller with the manager.
// GenerationChangedPredicate ensures status-only updates do not trigger re-reconciles.
// The verify path explicitly requeues after apiKeyVerifyPeriod for periodic existence checks.
func (r *APIKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.APIKey{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// findKeyByPrefix calls ListAPIKeys and returns the ID and prefix of the key whose
// server-reported prefix matches the first 8 characters of the newly created plaintext key.
// CreateAPIKey does not return a key ID, so this is the only way to retrieve it.
func (r *APIKeyReconciler) findKeyByPrefix(ctx context.Context, plaintext string) (id, prefix string, err error) {
	pfx := plaintext
	if len(pfx) > 8 {
		pfx = pfx[:8]
	}
	keys, err := r.OCIDexClient.ListAPIKeys(ctx)
	if err != nil {
		return "", "", fmt.Errorf("listing API keys: %w", err)
	}
	for _, k := range keys {
		if k.Prefix == pfx {
			return k.Id, k.Prefix, nil
		}
	}
	return "", "", fmt.Errorf("newly created key (prefix %q) not found in list", pfx)
}

// writeSecret creates or updates the Secret referenced by spec.secretRef.
func (r *APIKeyReconciler) writeSecret(ctx context.Context, cr *v1alpha1.APIKey, plaintext string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.SecretRef.Name,
			Namespace: cr.Namespace,
		},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if secret.Data == nil {
			secret.Data = make(map[string][]byte)
		}
		secret.Data["api-key"] = []byte(plaintext)
		return nil
	})
	return err
}
