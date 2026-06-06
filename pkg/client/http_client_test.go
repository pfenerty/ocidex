package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
)

func TestNew_DefaultHTTPClient(t *testing.T) {
	is := is.New(t)
	c := New(Config{BaseURL: "http://localhost:8080"})
	is.True(c != nil)
	is.Equal(c.http, http.DefaultClient)
}

func TestNew_CustomHTTPClient(t *testing.T) {
	is := is.New(t)
	custom := &http.Client{}
	c := New(Config{HTTPClient: custom})
	is.Equal(c.http, custom)
}


func TestDo_SendsBearerToken(t *testing.T) {
	is := is.New(t)
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, APIKey: "ocidex_testkey"})
	err := c.request(context.Background(), http.MethodGet, "/test", nil, nil, nil)
	is.NoErr(err)
	is.Equal(got, "Bearer ocidex_testkey")
}

func TestDo_NoAuthHeaderWhenKeyEmpty(t *testing.T) {
	is := is.New(t)
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL})
	err := c.request(context.Background(), http.MethodGet, "/test", nil, nil, nil)
	is.NoErr(err)
	is.Equal(got, "")
}

func TestDo_404MapsToErrNotFound(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"status":404,"detail":"not found"}`))
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL})
	err := c.request(context.Background(), http.MethodGet, "/missing", nil, nil, nil)
	is.True(errors.Is(err, ErrNotFound))
}

func TestDo_DecodesJSONResponse(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL})
	var result struct {
		Status string `json:"status"`
	}
	err := c.request(context.Background(), http.MethodGet, "/", nil, nil, &result)
	is.NoErr(err)
	is.Equal(result.Status, "ok")
}
