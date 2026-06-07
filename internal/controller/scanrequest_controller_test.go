package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/matryer/is"
	corev1ref "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/pfenerty/ocidex/api/v1alpha1"
	ocidexclient "github.com/pfenerty/ocidex/pkg/client"
)

func newTestScanRequest() *v1alpha1.ScanRequest {
	return &v1alpha1.ScanRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "scan",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: v1alpha1.ScanRequestSpec{
			RegistryRef: corev1ref.LocalObjectReference{Name: "reg"},
		},
	}
}

func newReadyRegistry() *v1alpha1.OCIRegistry {
	return &v1alpha1.OCIRegistry{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "reg",
			Namespace: "default",
		},
		Status: v1alpha1.OCIRegistryStatus{
			RegistryID: "reg-uuid",
		},
	}
}

func reconcileScan(t *testing.T, k8s client.Client, ocidex ocidexclient.Client, cr *v1alpha1.ScanRequest) (ctrl.Result, error) {
	t.Helper()
	r := &ScanRequestReconciler{
		Client:       k8s,
		Scheme:       testScheme,
		OCIDexClient: ocidex,
	}
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: cr.Name, Namespace: cr.Namespace},
	})
}

func TestScanRequestReconciler_Dispatch(t *testing.T) {
	is := is.New(t)
	cr := newTestScanRequest()
	reg := newReadyRegistry()

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr, reg).
		WithStatusSubresource(cr, reg).
		Build()

	var scanCalledWith string
	ocidex := &ocidexclient.FakeClient{
		ScanRegistryFn: func(_ context.Context, id string) (ocidexclient.ScanRegistryOutputBody, error) {
			scanCalledWith = id
			return ocidexclient.ScanRegistryOutputBody{Message: "scan queued"}, nil
		},
	}

	_, err := reconcileScan(t, k8s, ocidex, cr)
	is.NoErr(err)
	is.Equal(scanCalledWith, "reg-uuid")

	updated := &v1alpha1.ScanRequest{}
	is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "scan", Namespace: "default"}, updated))
	is.Equal(updated.Status.Phase, "Dispatched")
	is.True(isConditionTrue(updated.Status.Conditions, "Dispatched"))
}

func TestScanRequestReconciler_RegistryNotReady(t *testing.T) {
	is := is.New(t)
	cr := newTestScanRequest()
	reg := &v1alpha1.OCIRegistry{
		ObjectMeta: metav1.ObjectMeta{Name: "reg", Namespace: "default"},
		Status:     v1alpha1.OCIRegistryStatus{RegistryID: ""},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr, reg).
		WithStatusSubresource(cr, reg).
		Build()

	var scanCalled bool
	ocidex := &ocidexclient.FakeClient{
		ScanRegistryFn: func(_ context.Context, _ string) (ocidexclient.ScanRegistryOutputBody, error) {
			scanCalled = true
			return ocidexclient.ScanRegistryOutputBody{}, nil
		},
	}

	result, err := reconcileScan(t, k8s, ocidex, cr)
	is.NoErr(err)
	is.True(!scanCalled)
	is.True(result.RequeueAfter > 0)

	updated := &v1alpha1.ScanRequest{}
	is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "scan", Namespace: "default"}, updated))
	is.Equal(updated.Status.Phase, "Pending")
	is.True(isConditionFalse(updated.Status.Conditions, "Dispatched"))
}

func TestScanRequestReconciler_RegistryNotFound(t *testing.T) {
	is := is.New(t)
	cr := newTestScanRequest()

	// No OCIRegistry object in the cluster.
	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	ocidex := &ocidexclient.FakeClient{}

	_, err := reconcileScan(t, k8s, ocidex, cr)
	is.NoErr(err)

	updated := &v1alpha1.ScanRequest{}
	is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "scan", Namespace: "default"}, updated))
	is.Equal(updated.Status.Phase, "Failed")
	is.True(isConditionFalse(updated.Status.Conditions, "Dispatched"))
}

func TestScanRequestReconciler_AlreadyDispatched(t *testing.T) {
	is := is.New(t)
	cr := newTestScanRequest()
	cr.Status.Phase = "Dispatched"

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	var scanCalled bool
	ocidex := &ocidexclient.FakeClient{
		ScanRegistryFn: func(_ context.Context, _ string) (ocidexclient.ScanRegistryOutputBody, error) {
			scanCalled = true
			return ocidexclient.ScanRegistryOutputBody{}, nil
		},
	}

	result, err := reconcileScan(t, k8s, ocidex, cr)
	is.NoErr(err)
	is.True(!scanCalled)
	is.Equal(result, ctrl.Result{})
}

func TestScanRequestReconciler_AlreadyFailed(t *testing.T) {
	is := is.New(t)
	cr := newTestScanRequest()
	cr.Status.Phase = "Failed"

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	var scanCalled bool
	ocidex := &ocidexclient.FakeClient{
		ScanRegistryFn: func(_ context.Context, _ string) (ocidexclient.ScanRegistryOutputBody, error) {
			scanCalled = true
			return ocidexclient.ScanRegistryOutputBody{}, nil
		},
	}

	result, err := reconcileScan(t, k8s, ocidex, cr)
	is.NoErr(err)
	is.True(!scanCalled)
	is.Equal(result, ctrl.Result{})
}

func TestScanRequestReconciler_ScanRegistryError(t *testing.T) {
	is := is.New(t)
	cr := newTestScanRequest()
	reg := newReadyRegistry()

	k8s := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(cr, reg).
		WithStatusSubresource(cr, reg).
		Build()

	apiErr := errors.New("scan service unavailable")
	ocidex := &ocidexclient.FakeClient{
		ScanRegistryFn: func(_ context.Context, _ string) (ocidexclient.ScanRegistryOutputBody, error) {
			return ocidexclient.ScanRegistryOutputBody{}, apiErr
		},
	}

	_, err := reconcileScan(t, k8s, ocidex, cr)
	is.True(errors.Is(err, apiErr))

	updated := &v1alpha1.ScanRequest{}
	is.NoErr(k8s.Get(context.Background(), types.NamespacedName{Name: "scan", Namespace: "default"}, updated))
	is.Equal(updated.Status.Phase, "Failed")
	is.True(isConditionFalse(updated.Status.Conditions, "Dispatched"))
}
