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
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v1alpha1 "github.com/pfenerty/ocidex/api/v1alpha1"
	ocidexclient "github.com/pfenerty/ocidex/pkg/client"
)

const (
	apiKeyFinalizer    = "ocidex.io/apikey-protection" //nolint:gosec // Kubernetes finalizer, not a credential
	apiKeyVerifyPeriod = 5 * time.Minute
	// requeueAfterDrift re-runs the reconcile after the remote object was found
	// to have been deleted externally, so the create path runs on the next pass.
	// Replaces ctrl.Result{Requeue: true}, deprecated in controller-runtime; the
	// delay is now explicit instead of the manager's rate-limiter backoff.
	requeueAfterDrift = 5 * time.Second
)

// APIKeyReconciler reconciles APIKey resources.
type APIKeyReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	OCIDexClient ocidexclient.Client
	// Now is the clock for expiry and rotation. Nil means time.Now.
	Now func() time.Time
}

// minAPIKeyLifetime is the shortest spec.lifetime accepted. Rotation happens
// at 80% of the lifetime, so anything shorter churns keys faster than
// consumers are likely to re-read the Secret.
const minAPIKeyLifetime = time.Hour

func (r *APIKeyReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// rotateAt is when a key with a lifetime is replaced: once 80% of its
// lifetime has passed. Zero means never.
func rotateAt(cr *v1alpha1.APIKey) time.Time {
	if cr.Spec.Lifetime == nil || cr.Status.ExpiresAt == nil {
		return time.Time{}
	}
	return cr.Status.ExpiresAt.Add(-cr.Spec.Lifetime.Duration / 5)
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

	if cr.Spec.Lifetime != nil && cr.Spec.Lifetime.Duration < minAPIKeyLifetime {
		SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionFalse, "InvalidSpec",
			fmt.Sprintf("spec.lifetime must be at least %s", minAPIKeyLifetime), cr.Generation)
		return ctrl.Result{}, r.Status().Update(ctx, cr)
	}

	if cr.Status.KeyID == "" {
		return r.createAndPersist(ctx, cr)
	}

	return r.verifyOrRotate(ctx, cr)
}

func (r *APIKeyReconciler) createAndPersist(ctx context.Context, cr *v1alpha1.APIKey) (ctrl.Result, error) {
	body := ocidexclient.CreateAPIKeyInputBody{Name: cr.Spec.Name}
	// An empty list is left absent rather than sent: both mean "everything the
	// operator's own user may do", and sending nothing keeps that the server's
	// definition alone.
	if len(cr.Spec.Capabilities) > 0 {
		caps := make([]ocidexclient.CreateAPIKeyInputBodyCapabilities, len(cr.Spec.Capabilities))
		for i, c := range cr.Spec.Capabilities {
			caps[i] = ocidexclient.CreateAPIKeyInputBodyCapabilities(c)
		}
		body.Capabilities = &caps
	}
	var expiresAt *metav1.Time
	if cr.Spec.Lifetime != nil {
		exp := r.now().Add(cr.Spec.Lifetime.Duration).UTC().Truncate(time.Second)
		body.ExpiresAt = &exp
		expiresAt = &metav1.Time{Time: exp}
	}
	out, err := r.OCIDexClient.CreateAPIKey(ctx, body)
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
	cr.Status.ExpiresAt = expiresAt
	SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionTrue, "Created", "", cr.Generation)
	return r.requeue(cr), r.Status().Update(ctx, cr)
}

// requeue schedules the next check: the regular verify period, or the
// rotation time if that comes first.
func (r *APIKeyReconciler) requeue(cr *v1alpha1.APIKey) ctrl.Result {
	after := apiKeyVerifyPeriod
	if at := rotateAt(cr); !at.IsZero() {
		if until := at.Sub(r.now()); until < after {
			after = max(until, time.Second)
		}
	}
	return ctrl.Result{RequeueAfter: after}
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
		return ctrl.Result{RequeueAfter: requeueAfterDrift}, r.Status().Update(ctx, cr)
	}

	// Check if spec changed since last successful reconcile.
	ready := apimeta.FindStatusCondition(cr.Status.Conditions, "Ready")
	if ready != nil && ready.Status == metav1.ConditionTrue && ready.ObservedGeneration < cr.Generation {
		return r.rotate(ctx, cr)
	}

	if at := rotateAt(cr); !at.IsZero() && !r.now().Before(at) {
		return r.renew(ctx, cr)
	}

	SetCondition(&cr.Status.Conditions, "Ready", metav1.ConditionTrue, "Synced", "", cr.Generation)
	return r.requeue(cr), r.Status().Update(ctx, cr)
}

// renew replaces a key that is nearing the end of its lifetime, make before
// break: the new key is minted and written to the Secret before the old one
// is deleted, so a consumer re-reading the Secret never finds a dead key.
func (r *APIKeyReconciler) renew(ctx context.Context, cr *v1alpha1.APIKey) (ctrl.Result, error) {
	oldID := cr.Status.KeyID
	res, err := r.createAndPersist(ctx, cr)
	if err != nil {
		return res, err
	}
	if err := r.OCIDexClient.DeleteAPIKey(ctx, oldID); err != nil && !errors.Is(err, ocidexclient.ErrNotFound) {
		// The new key is live and in the Secret; the old one expires on its
		// own, so this is worth a log line, not a failed reconcile.
		log.FromContext(ctx).Error(err, "deleting renewed API key", "keyID", oldID)
	}
	return res, nil
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
