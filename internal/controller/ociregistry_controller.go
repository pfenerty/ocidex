// Package controller implements controller-runtime reconcilers for OCIDex CRDs.
package controller

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
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

const ociRegistryFinalizer = "ocidex.io/registry-protection"

// OCIRegistryReconciler reconciles OCIRegistry resources.
type OCIRegistryReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	OCIDexClient ocidexclient.Client
}

//+kubebuilder:rbac:groups=ocidex.io,resources=ociregistries,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ocidex.io,resources=ociregistries/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get

// Reconcile is the main reconcile loop for OCIRegistry.
//
// Contract (ADR-030):
//  1. Deletion path: call DeleteRegistry, remove finalizer.
//  2. Add finalizer on first reconcile; re-fetch and continue in the same call
//     (GenerationChangedPredicate filters the finalizer-add watch event).
//  3. Create when status.registryID is empty.
//  4. Update when status.registryID is set; re-create if the record was deleted externally.
func (r *OCIRegistryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	cr := &v1alpha1.OCIRegistry{}
	if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !cr.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, cr)
	}

	// Add finalizer on first reconcile; continue in the same call because
	// GenerationChangedPredicate filters metadata-only updates.
	if !controllerutil.ContainsFinalizer(cr, ociRegistryFinalizer) {
		controllerutil.AddFinalizer(cr, ociRegistryFinalizer)
		if err := r.Update(ctx, cr); err != nil {
			return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
		}
		// Re-fetch to get the latest resourceVersion before status writes.
		if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}

	username, token, err := r.readAuthSecret(ctx, cr)
	if err != nil {
		SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionFalse, "SecretReadError", err.Error(), cr.Generation)
		_ = r.Status().Update(ctx, cr)
		return ctrl.Result{}, err
	}

	if cr.Status.RegistryID == "" {
		resp, err := r.OCIDexClient.CreateRegistry(ctx, specToCreateBody(cr.Spec, username, token))
		if err != nil {
			SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionFalse, "APIError", err.Error(), cr.Generation)
			_ = r.Status().Update(ctx, cr)
			return ctrl.Result{}, err
		}
		cr.Status.RegistryID = resp.Id
		SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionTrue, "Created", "", cr.Generation)
		return ctrl.Result{}, r.Status().Update(ctx, cr)
	}

	if _, err := r.OCIDexClient.GetRegistry(ctx, cr.Status.RegistryID); err != nil {
		if errors.Is(err, ocidexclient.ErrNotFound) {
			cr.Status.RegistryID = ""
			SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionFalse, "NotFound", "registry deleted externally; will re-create on next reconcile", cr.Generation)
			return ctrl.Result{Requeue: true}, r.Status().Update(ctx, cr)
		}
		SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionFalse, "APIError", err.Error(), cr.Generation)
		_ = r.Status().Update(ctx, cr)
		return ctrl.Result{}, err
	}

	if _, err := r.OCIDexClient.UpdateRegistry(ctx, cr.Status.RegistryID, specToUpdateBody(cr.Spec, username, token)); err != nil {
		SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionFalse, "APIError", err.Error(), cr.Generation)
		_ = r.Status().Update(ctx, cr)
		return ctrl.Result{}, err
	}
	SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionTrue, "Synced", "", cr.Generation)
	return ctrl.Result{}, r.Status().Update(ctx, cr)
}

func (r *OCIRegistryReconciler) handleDeletion(ctx context.Context, cr *v1alpha1.OCIRegistry) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(cr, ociRegistryFinalizer) {
		return ctrl.Result{}, nil
	}
	if cr.Status.RegistryID != "" {
		if err := r.OCIDexClient.DeleteRegistry(ctx, cr.Status.RegistryID); err != nil && !errors.Is(err, ocidexclient.ErrNotFound) {
			SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionFalse, "DeleteError", err.Error(), cr.Generation)
			_ = r.Status().Update(ctx, cr)
			return ctrl.Result{}, err
		}
	}
	controllerutil.RemoveFinalizer(cr, ociRegistryFinalizer)
	return ctrl.Result{}, r.Update(ctx, cr)
}

// SetupWithManager registers the controller with the manager.
// GenerationChangedPredicate ensures status-only updates do not trigger re-reconciles.
func (r *OCIRegistryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OCIRegistry{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

func (r *OCIRegistryReconciler) readAuthSecret(ctx context.Context, cr *v1alpha1.OCIRegistry) (username, token string, err error) {
	if cr.Spec.AuthSecretRef == nil {
		return "", "", nil
	}
	secret := &corev1.Secret{}
	key := types.NamespacedName{Namespace: cr.Namespace, Name: cr.Spec.AuthSecretRef.Name}
	if err := r.Get(ctx, key, secret); err != nil {
		return "", "", fmt.Errorf("reading auth secret %q: %w", cr.Spec.AuthSecretRef.Name, err)
	}
	return string(secret.Data["username"]), string(secret.Data["token"]), nil
}

func specToCreateBody(spec v1alpha1.OCIRegistrySpec, username, token string) ocidexclient.CreateRegistryInputBody {
	body := ocidexclient.CreateRegistryInputBody{
		Url:      spec.URL,
		Name:     spec.Name,
		Type:     ocidexclient.CreateRegistryInputBodyType(spec.Type),
		Insecure: spec.Insecure,
	}
	if spec.Visibility != "" {
		v := ocidexclient.CreateRegistryInputBodyVisibility(spec.Visibility)
		body.Visibility = &v
	}
	if spec.ScanMode != "" {
		sm := ocidexclient.CreateRegistryInputBodyScanMode(spec.ScanMode)
		body.ScanMode = &sm
	}
	body.PollIntervalMinutes = spec.PollIntervalMinutes
	if len(spec.Repositories) > 0 {
		repos := make([]string, len(spec.Repositories))
		copy(repos, spec.Repositories)
		body.Repositories = &repos
	}
	if len(spec.RepositoryPatterns) > 0 {
		rp := make([]string, len(spec.RepositoryPatterns))
		copy(rp, spec.RepositoryPatterns)
		body.RepositoryPatterns = &rp
	}
	if len(spec.TagPatterns) > 0 {
		tp := make([]string, len(spec.TagPatterns))
		copy(tp, spec.TagPatterns)
		body.TagPatterns = &tp
	}
	if spec.IncludeUntagged {
		iu := true
		body.IncludeUntagged = &iu
	}
	if spec.VerificationMode != "" {
		body.VerificationMode = (*ocidexclient.CreateRegistryInputBodyVerificationMode)(&spec.VerificationMode)
	}
	body.TrustPublicKey = spec.TrustPublicKey
	if username != "" {
		body.AuthUsername = &username
		body.AuthToken = &token
	}
	return body
}

func specToUpdateBody(spec v1alpha1.OCIRegistrySpec, username, token string) ocidexclient.UpdateRegistryInputBody {
	body := ocidexclient.UpdateRegistryInputBody{
		Url:      spec.URL,
		Name:     spec.Name,
		Type:     ocidexclient.UpdateRegistryInputBodyType(spec.Type),
		Insecure: spec.Insecure,
		Enabled:  true,
	}
	if spec.Visibility != "" {
		v := ocidexclient.UpdateRegistryInputBodyVisibility(spec.Visibility)
		body.Visibility = &v
	}
	if spec.ScanMode != "" {
		sm := ocidexclient.UpdateRegistryInputBodyScanMode(spec.ScanMode)
		body.ScanMode = &sm
	}
	body.PollIntervalMinutes = spec.PollIntervalMinutes
	if len(spec.Repositories) > 0 {
		repos := make([]string, len(spec.Repositories))
		copy(repos, spec.Repositories)
		body.Repositories = &repos
	}
	if len(spec.RepositoryPatterns) > 0 {
		rp := make([]string, len(spec.RepositoryPatterns))
		copy(rp, spec.RepositoryPatterns)
		body.RepositoryPatterns = &rp
	}
	if len(spec.TagPatterns) > 0 {
		tp := make([]string, len(spec.TagPatterns))
		copy(tp, spec.TagPatterns)
		body.TagPatterns = &tp
	}
	if spec.IncludeUntagged {
		iu := true
		body.IncludeUntagged = &iu
	}
	if spec.VerificationMode != "" {
		body.VerificationMode = (*ocidexclient.UpdateRegistryInputBodyVerificationMode)(&spec.VerificationMode)
	}
	body.TrustPublicKey = spec.TrustPublicKey
	if username != "" {
		body.AuthUsername = &username
		body.AuthToken = &token
	}
	return body
}
