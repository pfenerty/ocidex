package controller

import (
	"context"
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

var lifetimeT0 = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func reconcileKeyAt(t *testing.T, now time.Time, k8s client.Client, ocidex ocidexclient.Client, cr *v1alpha1.APIKey) (ctrl.Result, error) {
	t.Helper()
	r := &APIKeyReconciler{Client: k8s, Scheme: testScheme, OCIDexClient: ocidex, Now: func() time.Time { return now }}
	return r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: cr.Name, Namespace: cr.Namespace}})
}

func k8sWith(cr *v1alpha1.APIKey) client.Client {
	return fake.NewClientBuilder().WithScheme(testScheme).WithObjects(cr).WithStatusSubresource(cr).Build()
}

func getKey(t *testing.T, k8s client.Client) *v1alpha1.APIKey {
	t.Helper()
	out := &v1alpha1.APIKey{}
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: "mykey", Namespace: "default"}, out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A lifetime mints the key with an expiry, records it, and schedules the next
// reconcile for the rotation point (80% of the lifetime) when that comes
// before the regular verify.
func TestAPIKeyReconciler_LifetimeSetsExpiry(t *testing.T) {
	is := is.New(t)
	cr := newTestAPIKey()
	cr.Finalizers = []string{apiKeyFinalizer}
	cr.Spec.Lifetime = &metav1.Duration{Duration: 10 * time.Hour}
	k8s := k8sWith(cr)

	var sent *time.Time
	ocidex := stubCreate("ocidex_sk_abcdefgh1234", "key-uuid")
	ocidex.CreateAPIKeyFn = func(_ context.Context, body ocidexclient.CreateAPIKeyInputBody) (ocidexclient.CreateAPIKeyOutputBody, error) {
		sent = body.ExpiresAt
		return ocidexclient.CreateAPIKeyOutputBody{Key: "ocidex_sk_abcdefgh1234"}, nil
	}

	res, err := reconcileKeyAt(t, lifetimeT0, k8s, ocidex, cr)
	is.NoErr(err)
	want := lifetimeT0.Add(10 * time.Hour)
	is.True(sent != nil)
	is.True(sent.Equal(want))
	is.True(getKey(t, k8s).Status.ExpiresAt.Equal(&metav1.Time{Time: want}))
	is.Equal(res.RequeueAfter, apiKeyVerifyPeriod) // rotation is 8h away, verify comes first
}

func TestAPIKeyReconciler_NoLifetimeNoExpiry(t *testing.T) {
	is := is.New(t)
	cr := newTestAPIKey()
	cr.Finalizers = []string{apiKeyFinalizer}
	k8s := k8sWith(cr)
	ocidex := stubCreate("ocidex_sk_zyxwvuts9876", "key-uuid-2")
	var sent *time.Time
	ocidex.CreateAPIKeyFn = func(_ context.Context, body ocidexclient.CreateAPIKeyInputBody) (ocidexclient.CreateAPIKeyOutputBody, error) {
		sent = body.ExpiresAt
		return ocidexclient.CreateAPIKeyOutputBody{Key: "ocidex_sk_zyxwvuts9876"}, nil
	}
	_, err := reconcileKeyAt(t, lifetimeT0, k8s, ocidex, cr)
	is.NoErr(err)
	is.True(sent == nil)
	is.True(getKey(t, k8s).Status.ExpiresAt == nil)
}

func lifetimeKey(expiresAt time.Time) *v1alpha1.APIKey {
	cr := newTestAPIKey()
	cr.Finalizers = []string{apiKeyFinalizer}
	cr.Spec.Lifetime = &metav1.Duration{Duration: 10 * time.Hour}
	cr.Status.KeyID = "old-uuid"
	cr.Status.Prefix = "ocidex_s"
	cr.Status.ExpiresAt = &metav1.Time{Time: expiresAt}
	cr.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Created", ObservedGeneration: 1}}
	return cr
}

// Before the rotation point the key is only verified, and the requeue lands
// on the rotation point when that is sooner than the verify period.
func TestAPIKeyReconciler_LifetimeRequeuesForRotation(t *testing.T) {
	is := is.New(t)
	exp := lifetimeT0.Add(2*time.Hour + 2*time.Minute) // rotates at exp-2h: 2 min from now
	cr := lifetimeKey(exp)
	k8s := k8sWith(cr)
	ocidex := &ocidexclient.FakeClient{
		ListAPIKeysFn: func(context.Context) ([]ocidexclient.KeyMetaResponse, error) {
			return []ocidexclient.KeyMetaResponse{{Id: "old-uuid", Prefix: "ocidex_s"}}, nil
		},
		CreateAPIKeyFn: func(context.Context, ocidexclient.CreateAPIKeyInputBody) (ocidexclient.CreateAPIKeyOutputBody, error) {
			t.Fatal("rotated too early")
			return ocidexclient.CreateAPIKeyOutputBody{}, nil
		},
	}
	res, err := reconcileKeyAt(t, lifetimeT0, k8s, ocidex, cr)
	is.NoErr(err)
	is.Equal(res.RequeueAfter, 2*time.Minute)
}

// At the rotation point the key is renewed make-before-break: the new key is
// in the Secret before the old one is deleted.
func TestAPIKeyReconciler_LifetimeRenewsBeforeExpiry(t *testing.T) {
	is := is.New(t)
	exp := lifetimeT0.Add(time.Hour) // inside the last 20% (2h) of a 10h lifetime
	cr := lifetimeKey(exp)
	k8s := k8sWith(cr)

	var order []string
	ocidex := &ocidexclient.FakeClient{
		ListAPIKeysFn: func(context.Context) ([]ocidexclient.KeyMetaResponse, error) {
			return []ocidexclient.KeyMetaResponse{
				{Id: "old-uuid", Prefix: "ocidex_s"},
				{Id: "new-uuid", Prefix: "newkey_1"},
			}, nil
		},
		CreateAPIKeyFn: func(context.Context, ocidexclient.CreateAPIKeyInputBody) (ocidexclient.CreateAPIKeyOutputBody, error) {
			order = append(order, "create")
			return ocidexclient.CreateAPIKeyOutputBody{Key: "newkey_1xyzabcd"}, nil
		},
		DeleteAPIKeyFn: func(_ context.Context, id string) error {
			secret := &corev1.Secret{}
			is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "key-secret", Namespace: "default"}, secret))
			is.Equal(string(secret.Data["api-key"]), "newkey_1xyzabcd") // new key already in place
			order = append(order, "delete "+id)
			return nil
		},
	}

	_, err := reconcileKeyAt(t, lifetimeT0, k8s, ocidex, cr)
	is.NoErr(err)
	is.Equal(order, []string{"create", "delete old-uuid"})
	updated := getKey(t, k8s)
	is.Equal(updated.Status.KeyID, "new-uuid")
	is.True(updated.Status.ExpiresAt.Equal(&metav1.Time{Time: lifetimeT0.Add(10 * time.Hour)}))
}

func TestAPIKeyReconciler_LifetimeTooShort(t *testing.T) {
	is := is.New(t)
	cr := newTestAPIKey()
	cr.Finalizers = []string{apiKeyFinalizer}
	cr.Spec.Lifetime = &metav1.Duration{Duration: 30 * time.Minute}
	k8s := k8sWith(cr)
	ocidex := &ocidexclient.FakeClient{
		CreateAPIKeyFn: func(context.Context, ocidexclient.CreateAPIKeyInputBody) (ocidexclient.CreateAPIKeyOutputBody, error) {
			t.Fatal("created a key with an invalid lifetime")
			return ocidexclient.CreateAPIKeyOutputBody{}, nil
		},
	}
	_, err := reconcileKeyAt(t, lifetimeT0, k8s, ocidex, cr)
	is.NoErr(err)
	is.True(isConditionFalse(getKey(t, k8s).Status.Conditions, "Ready"))
}

// The APIKey deepcopy is hand-maintained; a pointer field it forgets is shared
// between a cached object and its copy.
func TestAPIKeyDeepCopyOwnsLifetimeAndExpiry(t *testing.T) {
	is := is.New(t)
	cr := lifetimeKey(lifetimeT0)
	cp := cr.DeepCopy()
	cp.Spec.Lifetime.Duration = time.Minute
	cp.Status.ExpiresAt.Time = time.Time{}
	is.Equal(cr.Spec.Lifetime.Duration, 10*time.Hour)
	is.True(cr.Status.ExpiresAt.Equal(&metav1.Time{Time: lifetimeT0}))
}
