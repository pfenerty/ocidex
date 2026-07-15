package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/matryer/is"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/pfenerty/ocidex/api/v1alpha1"
	ocidexclient "github.com/pfenerty/ocidex/pkg/client"
)

var testScheme = func() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(v1alpha1.AddToScheme(s))
	return s
}()

func newTestRegistry() *v1alpha1.OCIRegistry {
	return &v1alpha1.OCIRegistry{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "reg",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: v1alpha1.OCIRegistrySpec{
			URL:  "zot:5000",
			Name: "test-registry",
			Type: "zot",
		},
	}
}

func reconcile(t *testing.T, k8s client.Client, ocidex ocidexclient.Client, cr *v1alpha1.OCIRegistry) (ctrl.Result, error) {
	t.Helper()
	r := &OCIRegistryReconciler{
		Client:       k8s,
		Scheme:       testScheme,
		OCIDexClient: ocidex,
	}
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: cr.Name, Namespace: cr.Namespace},
	})
}

func TestOCIRegistryReconciler_Create(t *testing.T) {
	is := is.New(t)
	cr := newTestRegistry()

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	ocidex := &ocidexclient.FakeClient{
		CreateRegistryFn: func(_ context.Context, body ocidexclient.CreateRegistryInputBody) (ocidexclient.CreateRegistryResponseBody, error) {
			is.Equal(body.Url, "zot:5000")
			is.Equal(body.Name, "test-registry")
			return ocidexclient.CreateRegistryResponseBody{Id: "reg-uuid"}, nil
		},
	}

	_, err := reconcile(t, k8s, ocidex, cr)
	is.NoErr(err)

	updated := &v1alpha1.OCIRegistry{}
	is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "reg", Namespace: "default"}, updated))
	is.Equal(updated.Status.RegistryID, "reg-uuid")
	is.True(isConditionTrue(updated.Status.Conditions, "Ready"))
}

func TestOCIRegistryReconciler_Update(t *testing.T) {
	is := is.New(t)
	cr := newTestRegistry()
	cr.Status.RegistryID = "existing-uuid"
	cr.Finalizers = []string{ociRegistryFinalizer}

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	var updateCalled bool
	ocidex := &ocidexclient.FakeClient{
		GetRegistryFn: func(_ context.Context, id string) (ocidexclient.RegistryResponse, error) {
			is.Equal(id, "existing-uuid")
			return ocidexclient.RegistryResponse{Id: id}, nil
		},
		UpdateRegistryFn: func(_ context.Context, id string, body ocidexclient.UpdateRegistryInputBody) (ocidexclient.RegistryResponse, error) {
			is.Equal(id, "existing-uuid")
			is.True(body.Enabled)
			updateCalled = true
			return ocidexclient.RegistryResponse{Id: id}, nil
		},
	}

	_, err := reconcile(t, k8s, ocidex, cr)
	is.NoErr(err)
	is.True(updateCalled)

	updated := &v1alpha1.OCIRegistry{}
	is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "reg", Namespace: "default"}, updated))
	is.True(isConditionTrue(updated.Status.Conditions, "Ready"))
}

func TestOCIRegistryReconciler_RecreateOnNotFound(t *testing.T) {
	is := is.New(t)
	cr := newTestRegistry()
	cr.Status.RegistryID = "stale-uuid"
	cr.Finalizers = []string{ociRegistryFinalizer}

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	ocidex := &ocidexclient.FakeClient{
		GetRegistryFn: func(_ context.Context, _ string) (ocidexclient.RegistryResponse, error) {
			return ocidexclient.RegistryResponse{}, ocidexclient.ErrNotFound
		},
	}

	result, err := reconcile(t, k8s, ocidex, cr)
	is.NoErr(err)
	is.True(result.Requeue)

	updated := &v1alpha1.OCIRegistry{}
	is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "reg", Namespace: "default"}, updated))
	is.Equal(updated.Status.RegistryID, "")
	is.True(isConditionFalse(updated.Status.Conditions, "Ready"))
}

func TestOCIRegistryReconciler_Delete(t *testing.T) {
	is := is.New(t)
	now := metav1.NewTime(time.Now())
	cr := newTestRegistry()
	cr.Status.RegistryID = "reg-uuid"
	cr.Finalizers = []string{ociRegistryFinalizer}
	cr.DeletionTimestamp = &now

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	var deletedID string
	ocidex := &ocidexclient.FakeClient{
		DeleteRegistryFn: func(_ context.Context, id string) error {
			deletedID = id
			return nil
		},
	}

	_, err := reconcile(t, k8s, ocidex, cr)
	is.NoErr(err)
	is.Equal(deletedID, "reg-uuid")

	// After finalizer removal the fake client GCs the object (DeletionTimestamp was set).
	gone := &v1alpha1.OCIRegistry{}
	getErr := k8s.Get(context.Background(), types.NamespacedName{Name: "reg", Namespace: "default"}, gone)
	is.True(getErr != nil) // object should be gone
}

func TestOCIRegistryReconciler_DeleteIgnoresNotFound(t *testing.T) {
	is := is.New(t)
	now := metav1.NewTime(time.Now())
	cr := newTestRegistry()
	cr.Status.RegistryID = "reg-uuid"
	cr.Finalizers = []string{ociRegistryFinalizer}
	cr.DeletionTimestamp = &now

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	ocidex := &ocidexclient.FakeClient{
		DeleteRegistryFn: func(_ context.Context, _ string) error {
			return ocidexclient.ErrNotFound
		},
	}

	_, err := reconcile(t, k8s, ocidex, cr)
	is.NoErr(err)

	// After finalizer removal the fake client GCs the object.
	gone := &v1alpha1.OCIRegistry{}
	getErr := k8s.Get(context.Background(), types.NamespacedName{Name: "reg", Namespace: "default"}, gone)
	is.True(getErr != nil)
}

func TestOCIRegistryReconciler_CreateAPIError(t *testing.T) {
	is := is.New(t)
	cr := newTestRegistry()
	cr.Finalizers = []string{ociRegistryFinalizer}

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	apiErr := errors.New("internal server error")
	ocidex := &ocidexclient.FakeClient{
		CreateRegistryFn: func(_ context.Context, _ ocidexclient.CreateRegistryInputBody) (ocidexclient.CreateRegistryResponseBody, error) {
			return ocidexclient.CreateRegistryResponseBody{}, apiErr
		},
	}

	_, err := reconcile(t, k8s, ocidex, cr)
	is.True(errors.Is(err, apiErr))

	updated := &v1alpha1.OCIRegistry{}
	is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "reg", Namespace: "default"}, updated))
	is.True(isConditionFalse(updated.Status.Conditions, "Ready"))
}

func TestOCIRegistryReconciler_CreateConflictAdoptsExisting(t *testing.T) {
	is := is.New(t)
	cr := newTestRegistry()

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	ocidex := &ocidexclient.FakeClient{
		CreateRegistryFn: func(_ context.Context, _ ocidexclient.CreateRegistryInputBody) (ocidexclient.CreateRegistryResponseBody, error) {
			return ocidexclient.CreateRegistryResponseBody{}, ocidexclient.ErrConflict
		},
		GetRegistryByNameFn: func(_ context.Context, name string) (ocidexclient.RegistryResponse, error) {
			is.Equal(name, "test-registry")
			return ocidexclient.RegistryResponse{Id: "existing-uuid"}, nil
		},
	}

	_, err := reconcile(t, k8s, ocidex, cr)
	is.NoErr(err)

	updated := &v1alpha1.OCIRegistry{}
	is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "reg", Namespace: "default"}, updated))
	is.Equal(updated.Status.RegistryID, "existing-uuid")
	is.True(isConditionTrue(updated.Status.Conditions, "Ready"))
}

func TestOCIRegistryReconciler_CreateConflictLookupAlsoFails(t *testing.T) {
	is := is.New(t)
	cr := newTestRegistry()

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	ocidex := &ocidexclient.FakeClient{
		CreateRegistryFn: func(_ context.Context, _ ocidexclient.CreateRegistryInputBody) (ocidexclient.CreateRegistryResponseBody, error) {
			return ocidexclient.CreateRegistryResponseBody{}, ocidexclient.ErrConflict
		},
		GetRegistryByNameFn: func(_ context.Context, _ string) (ocidexclient.RegistryResponse, error) {
			return ocidexclient.RegistryResponse{}, ocidexclient.ErrNotFound
		},
	}

	_, err := reconcile(t, k8s, ocidex, cr)
	is.True(errors.Is(err, ocidexclient.ErrNotFound))

	updated := &v1alpha1.OCIRegistry{}
	is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "reg", Namespace: "default"}, updated))
	is.Equal(updated.Status.RegistryID, "")
	is.True(isConditionFalse(updated.Status.Conditions, "Ready"))
}

func TestOCIRegistryReconciler_AuthSecret(t *testing.T) {
	is := is.New(t)
	cr := newTestRegistry()
	cr.Spec.AuthSecretRef = &corev1.LocalObjectReference{Name: "reg-creds"}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "reg-creds", Namespace: "default"},
		Data: map[string][]byte{
			"username": []byte("user"),
			"token":    []byte("s3cr3t"),
		},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr, secret).
		WithStatusSubresource(cr).
		Build()

	var gotUser, gotToken string
	ocidex := &ocidexclient.FakeClient{
		CreateRegistryFn: func(_ context.Context, body ocidexclient.CreateRegistryInputBody) (ocidexclient.CreateRegistryResponseBody, error) {
			if body.AuthUsername != nil {
				gotUser = *body.AuthUsername
			}
			if body.AuthToken != nil {
				gotToken = *body.AuthToken
			}
			return ocidexclient.CreateRegistryResponseBody{Id: "reg-uuid"}, nil
		},
	}

	_, err := reconcile(t, k8s, ocidex, cr)
	is.NoErr(err)
	is.Equal(gotUser, "user")
	is.Equal(gotToken, "s3cr3t")
}

func TestOCIRegistryReconciler_Verification(t *testing.T) {
	is := is.New(t)
	cr := newTestRegistry()
	pubKey := "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----"
	cr.Spec.VerificationMode = "public_key"
	cr.Spec.TrustPublicKey = &pubKey

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	var gotMode string
	var gotKey *string
	ocidex := &ocidexclient.FakeClient{
		CreateRegistryFn: func(_ context.Context, body ocidexclient.CreateRegistryInputBody) (ocidexclient.CreateRegistryResponseBody, error) {
			if body.VerificationMode != nil {
				gotMode = string(*body.VerificationMode)
			}
			gotKey = body.TrustPublicKey
			return ocidexclient.CreateRegistryResponseBody{Id: "reg-uuid"}, nil
		},
	}

	_, err := reconcile(t, k8s, ocidex, cr)
	is.NoErr(err)
	is.Equal(gotMode, "public_key")
	is.True(gotKey != nil)
	is.Equal(*gotKey, pubKey)
}

func isConditionTrue(conditions []metav1.Condition, condType string) bool {
	for _, c := range conditions {
		if c.Type == condType {
			return c.Status == metav1.ConditionTrue
		}
	}
	return false
}

func isConditionFalse(conditions []metav1.Condition, condType string) bool {
	for _, c := range conditions {
		if c.Type == condType {
			return c.Status == metav1.ConditionFalse
		}
	}
	return false
}
