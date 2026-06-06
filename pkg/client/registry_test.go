package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
)

func newTestClient(srv *httptest.Server) *httpClient {
	return New(Config{BaseURL: srv.URL})
}

func TestListRegistries(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.Method, http.MethodGet)
		is.Equal(r.URL.Path, "/api/v1/registries")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"reg-1","name":"my-reg","type":"zot","url":"http://zot:5000","scan_mode":"poll","visibility":"private","enabled":true,"insecure":false,"include_untagged":false,"has_auth":false,"has_secret":false,"poll_interval_minutes":60,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","webhook_url":""}],"pagination":{"total":1,"limit":50,"offset":0}}`))
	}))
	defer srv.Close()

	page, err := newTestClient(srv).ListRegistries(context.Background(), PageOpts{})
	is.NoErr(err)
	is.Equal(len(page.Data), 1)
	is.Equal(page.Data[0].Id, "reg-1")
	is.Equal(page.Pagination.Total, int64(1))
	is.True(!page.HasMore())
}

func TestGetRegistry(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/registries/reg-1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"reg-1","name":"my-reg","type":"zot","url":"http://zot:5000","scan_mode":"poll","visibility":"private","enabled":true,"insecure":false,"include_untagged":false,"has_auth":false,"has_secret":false,"poll_interval_minutes":60,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","webhook_url":""}`))
	}))
	defer srv.Close()

	reg, err := newTestClient(srv).GetRegistry(context.Background(), "reg-1")
	is.NoErr(err)
	is.Equal(reg.Id, "reg-1")
	is.Equal(reg.Name, "my-reg")
}

func TestGetRegistry_NotFound(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"status":404,"detail":"not found"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv).GetRegistry(context.Background(), "missing")
	is.True(errors.Is(err, ErrNotFound))
}

func TestCreateRegistry(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.Method, http.MethodPost)
		is.Equal(r.URL.Path, "/api/v1/registries")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"reg-2","name":"new-reg","type":"docker","url":"https://registry-1.docker.io","scan_mode":"poll","visibility":"private","enabled":true,"insecure":false,"include_untagged":false,"has_auth":false,"has_secret":true,"poll_interval_minutes":60,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","webhook_url":"http://host/webhook","webhook_secret":"secret-abc"}`))
	}))
	defer srv.Close()

	regType := CreateRegistryInputBodyTypeDocker
	body := CreateRegistryInputBody{Name: "new-reg", Type: regType, Url: "https://registry-1.docker.io"}
	resp, err := newTestClient(srv).CreateRegistry(context.Background(), body)
	is.NoErr(err)
	is.Equal(resp.Id, "reg-2")
}

func TestUpdateRegistry(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.Method, http.MethodPatch)
		is.Equal(r.URL.Path, "/api/v1/registries/reg-1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"reg-1","name":"updated-reg","type":"zot","url":"http://zot:5000","scan_mode":"poll","visibility":"private","enabled":true,"insecure":false,"include_untagged":false,"has_auth":false,"has_secret":false,"poll_interval_minutes":60,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-02T00:00:00Z","webhook_url":""}`))
	}))
	defer srv.Close()

	body := UpdateRegistryInputBody{Name: "updated-reg", Type: UpdateRegistryInputBodyTypeZot, Url: "http://zot:5000"}
	resp, err := newTestClient(srv).UpdateRegistry(context.Background(), "reg-1", body)
	is.NoErr(err)
	is.Equal(resp.Name, "updated-reg")
}

func TestDeleteRegistry(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.Method, http.MethodDelete)
		is.Equal(r.URL.Path, "/api/v1/registries/reg-1")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	err := newTestClient(srv).DeleteRegistry(context.Background(), "reg-1")
	is.NoErr(err)
}

func TestScanRegistry(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.Method, http.MethodPost)
		is.Equal(r.URL.Path, "/api/v1/registries/reg-1/scan")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"message":"scan initiated"}`))
	}))
	defer srv.Close()

	resp, err := newTestClient(srv).ScanRegistry(context.Background(), "reg-1")
	is.NoErr(err)
	is.Equal(resp.Message, "scan initiated")
}

func TestTestRegistryConnection(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.Method, http.MethodPost)
		is.Equal(r.URL.Path, "/api/v1/registries/test-connection")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"reachable":true,"message":"HTTP 200"}`))
	}))
	defer srv.Close()

	body := TestRegistryConnectionInputBody{Url: "http://zot:5000"}
	resp, err := newTestClient(srv).TestRegistryConnection(context.Background(), body)
	is.NoErr(err)
	is.True(resp.Reachable)
	is.Equal(resp.Message, "HTTP 200")
}

func TestRegenerateWebhookSecret(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.Method, http.MethodPost)
		is.Equal(r.URL.Path, "/api/v1/registries/reg-1/webhook-secret")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"webhook_secret":"new-secret-xyz"}`))
	}))
	defer srv.Close()

	resp, err := newTestClient(srv).RegenerateWebhookSecret(context.Background(), "reg-1")
	is.NoErr(err)
	is.Equal(resp.WebhookSecret, "new-secret-xyz")
}
