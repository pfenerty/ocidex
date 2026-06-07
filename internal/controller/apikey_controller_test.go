package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/matryer/is"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/pfenerty/ocidex/api/v1alpha1"
	ocidexclient "github.com/pfenerty/ocidex/pkg/client"
)

func newTestAPIKey() *v1alpha1.APIKey {
	return &v1alpha1.APIKey{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "mykey",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: v1alpha1.APIKeySpec{
			Name:      "my-api-key",
			Scope:     "read",
			SecretRef: corev1.LocalObjectReference{Name: "key-secret"},
		},
	}
}

func reconcileKey(t *testing.T, k8s client.Client, ocidex ocidexclient.Client, cr *v1alpha1.APIKey) (ctrl.Result, error) {
	t.Helper()
	r := &APIKeyReconciler{
		Client:       k8s,
		Scheme:       testScheme,
		OCIDexClient: ocidex,
	}
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: cr.Name, Namespace: cr.Namespace},
	})
}

// stubCreate wires up CreateAPIKeyFn + ListAPIKeysFn with consistent test data.
func stubCreate(plaintext, keyID string) *ocidexclient.FakeClient {
	return &ocidexclient.FakeClient{
		CreateAPIKeyFn: func(_ context.Context, _ ocidexclient.CreateAPIKeyInputBody) (ocidexclient.CreateAPIKeyOutputBody, error) {
			return ocidexclient.CreateAPIKeyOutputBody{Key: plaintext}, nil
		},
		ListAPIKeysFn: func(_ context.Context) ([]ocidexclient.KeyMetaResponse, error) {
			return []ocidexclient.KeyMetaResponse{
				{Id: keyID, Name: "my-api-key", Prefix: plaintext[:8]},
			}, nil
		},
	}
}

func TestAPIKeyReconciler_Create(t *testing.T) {
	is := is.New(t)
	cr := newTestAPIKey()
	cr.Finalizers = []string{apiKeyFinalizer}

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	ocidex := stubCreate("ocidex_sk_abcdefgh1234", "key-uuid")

	_, err := reconcileKey(t, k8s, ocidex, cr)
	is.NoErr(err)

	updated := &v1alpha1.APIKey{}
	is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "mykey", Namespace: "default"}, updated))
	is.Equal(updated.Status.KeyID, "key-uuid")
	is.Equal(updated.Status.Prefix, "ocidex_s")
	is.True(isConditionTrue(updated.Status.Conditions, "Ready"))

	secret := &corev1.Secret{}
	is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "key-secret", Namespace: "default"}, secret))
	is.Equal(string(secret.Data["api-key"]), "ocidex_sk_abcdefgh1234")
}

func TestAPIKeyReconciler_VerifyNoRotation(t *testing.T) {
	is := is.New(t)
	cr := newTestAPIKey()
	cr.Finalizers = []string{apiKeyFinalizer}
	cr.Status.KeyID = "key-uuid"
	cr.Status.Prefix = "ocidex_s"
	// Set condition with same generation — no rotation needed.
	metav1.SetMetaDataAnnotation(&cr.ObjectMeta, "test", "noop")
	cr.Status.Conditions = []metav1.Condition{{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Created",
		ObservedGeneration: 1, // matches cr.Generation
	}}

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	ocidex := &ocidexclient.FakeClient{
		ListAPIKeysFn: func(_ context.Context) ([]ocidexclient.KeyMetaResponse, error) {
			return []ocidexclient.KeyMetaResponse{
				{Id: "key-uuid", Name: "my-api-key", Prefix: "ocidex_s"},
			}, nil
		},
	}

	result, err := reconcileKey(t, k8s, ocidex, cr)
	is.NoErr(err)
	is.True(result.RequeueAfter > 0)

	updated := &v1alpha1.APIKey{}
	is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "mykey", Namespace: "default"}, updated))
	is.True(isConditionTrue(updated.Status.Conditions, "Ready"))
}

func TestAPIKeyReconciler_RecreateOnMissing(t *testing.T) {
	is := is.New(t)
	cr := newTestAPIKey()
	cr.Finalizers = []string{apiKeyFinalizer}
	cr.Status.KeyID = "stale-uuid"
	cr.Status.Prefix = "ocidex_s"

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	ocidex := &ocidexclient.FakeClient{
		ListAPIKeysFn: func(_ context.Context) ([]ocidexclient.KeyMetaResponse, error) {
			return []ocidexclient.KeyMetaResponse{}, nil // key not in list
		},
	}

	result, err := reconcileKey(t, k8s, ocidex, cr)
	is.NoErr(err)
	is.True(result.Requeue)

	updated := &v1alpha1.APIKey{}
	is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "mykey", Namespace: "default"}, updated))
	is.Equal(updated.Status.KeyID, "")
	is.True(isConditionFalse(updated.Status.Conditions, "Ready"))
}

func TestAPIKeyReconciler_Rotation(t *testing.T) {
	is := is.New(t)
	cr := newTestAPIKey()
	cr.Generation = 2 // spec changed
	cr.Finalizers = []string{apiKeyFinalizer}
	cr.Status.KeyID = "old-uuid"
	cr.Status.Prefix = "ocidex_s"
	cr.Status.Conditions = []metav1.Condition{{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Created",
		ObservedGeneration: 1, // < cr.Generation=2 → rotation
	}}

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	var deletedID string
	ocidex := &ocidexclient.FakeClient{
		ListAPIKeysFn: func(_ context.Context) ([]ocidexclient.KeyMetaResponse, error) {
			// First call (verify): old key present. Second call (findByPrefix): new key.
			return []ocidexclient.KeyMetaResponse{
				{Id: "old-uuid", Name: "my-api-key", Prefix: "ocidex_s"},
				{Id: "new-uuid", Name: "my-api-key", Prefix: "newkey_1"},
			}, nil
		},
		DeleteAPIKeyFn: func(_ context.Context, id string) error {
			deletedID = id
			return nil
		},
		CreateAPIKeyFn: func(_ context.Context, _ ocidexclient.CreateAPIKeyInputBody) (ocidexclient.CreateAPIKeyOutputBody, error) {
			return ocidexclient.CreateAPIKeyOutputBody{Key: "newkey_1xyzabcd"}, nil
		},
	}

	_, err := reconcileKey(t, k8s, ocidex, cr)
	is.NoErr(err)
	is.Equal(deletedID, "old-uuid")

	updated := &v1alpha1.APIKey{}
	is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "mykey", Namespace: "default"}, updated))
	is.Equal(updated.Status.KeyID, "new-uuid")
	is.True(isConditionTrue(updated.Status.Conditions, "Ready"))
}

func TestAPIKeyReconciler_Delete(t *testing.T) {
	is := is.New(t)
	now := metav1.NewTime(time.Now())
	cr := newTestAPIKey()
	cr.Finalizers = []string{apiKeyFinalizer}
	cr.Status.KeyID = "key-uuid"
	cr.DeletionTimestamp = &now

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "key-secret", Namespace: "default"},
		Data:       map[string][]byte{"api-key": []byte("ocidex_sk_abcdef")},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr, secret).
		WithStatusSubresource(cr).
		Build()

	var deletedKeyID string
	ocidex := &ocidexclient.FakeClient{
		DeleteAPIKeyFn: func(_ context.Context, id string) error {
			deletedKeyID = id
			return nil
		},
	}

	_, err := reconcileKey(t, k8s, ocidex, cr)
	is.NoErr(err)
	is.Equal(deletedKeyID, "key-uuid")

	// Secret should be gone.
	gone := &corev1.Secret{}
	getErr := k8s.Get(context.Background(), types.NamespacedName{Name: "key-secret", Namespace: "default"}, gone)
	is.True(getErr != nil)

	// CR should be gone (finalizer removed).
	goneCR := &v1alpha1.APIKey{}
	crErr := k8s.Get(context.Background(), types.NamespacedName{Name: "mykey", Namespace: "default"}, goneCR)
	is.True(crErr != nil)
}

func TestAPIKeyReconciler_DeleteIgnoresNotFound(t *testing.T) {
	is := is.New(t)
	now := metav1.NewTime(time.Now())
	cr := newTestAPIKey()
	cr.Finalizers = []string{apiKeyFinalizer}
	cr.Status.KeyID = "key-uuid"
	cr.DeletionTimestamp = &now

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	ocidex := &ocidexclient.FakeClient{
		DeleteAPIKeyFn: func(_ context.Context, _ string) error {
			return ocidexclient.ErrNotFound
		},
	}

	_, err := reconcileKey(t, k8s, ocidex, cr)
	is.NoErr(err)

	goneCR := &v1alpha1.APIKey{}
	crErr := k8s.Get(context.Background(), types.NamespacedName{Name: "mykey", Namespace: "default"}, goneCR)
	is.True(crErr != nil)
}

func TestAPIKeyReconciler_CreateAPIError(t *testing.T) {
	is := is.New(t)
	cr := newTestAPIKey()
	cr.Finalizers = []string{apiKeyFinalizer}

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	apiErr := errors.New("quota exceeded")
	ocidex := &ocidexclient.FakeClient{
		CreateAPIKeyFn: func(_ context.Context, _ ocidexclient.CreateAPIKeyInputBody) (ocidexclient.CreateAPIKeyOutputBody, error) {
			return ocidexclient.CreateAPIKeyOutputBody{}, apiErr
		},
	}

	_, err := reconcileKey(t, k8s, ocidex, cr)
	is.True(errors.Is(err, apiErr))

	updated := &v1alpha1.APIKey{}
	is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "mykey", Namespace: "default"}, updated))
	is.True(isConditionFalse(updated.Status.Conditions, "Ready"))
}
