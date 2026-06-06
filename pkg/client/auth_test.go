package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
)

func TestCreateAPIKey(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.Method, http.MethodPost)
		is.Equal(r.URL.Path, "/api/v1/auth/keys")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"key":"ocidex_abc123"}`))
	}))
	defer srv.Close()

	scope := CreateAPIKeyInputBodyScopeReadWrite
	body := CreateAPIKeyInputBody{Name: "my-key", Scope: &scope}
	resp, err := newTestClient(srv).CreateAPIKey(context.Background(), body)
	is.NoErr(err)
	is.Equal(resp.Key, "ocidex_abc123")
}

func TestListAPIKeys(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.Method, http.MethodGet)
		is.Equal(r.URL.Path, "/api/v1/auth/keys")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[{"id":"key-1","name":"my-key","prefix":"ocidex_a","scope":"read-write","created_at":"2024-01-01T00:00:00Z"}]}`))
	}))
	defer srv.Close()

	keys, err := newTestClient(srv).ListAPIKeys(context.Background())
	is.NoErr(err)
	is.Equal(len(keys), 1)
	is.Equal(keys[0].Id, "key-1")
	is.Equal(keys[0].Name, "my-key")
}

func TestDeleteAPIKey(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.Method, http.MethodDelete)
		is.Equal(r.URL.Path, "/api/v1/auth/keys/key-1")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	err := newTestClient(srv).DeleteAPIKey(context.Background(), "key-1")
	is.NoErr(err)
}

func TestGetCurrentUser(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.Method, http.MethodGet)
		is.Equal(r.URL.Path, "/api/v1/users/me")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"user-1","github_username":"pfenerty","role":"admin"}`))
	}))
	defer srv.Close()

	me, err := newTestClient(srv).GetCurrentUser(context.Background())
	is.NoErr(err)
	is.Equal(me.Id, "user-1")
	is.Equal(me.GithubUsername, "pfenerty")
	is.Equal(me.Role, "admin")
}

func TestGetCurrentUser_Forbidden(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"status":403,"detail":"forbidden"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv).GetCurrentUser(context.Background())
	is.True(errors.Is(err, ErrForbidden))
}
