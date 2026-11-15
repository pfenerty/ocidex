package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

type recorded struct {
	cluster string
	attempt service.PushAttempt
}

type fakeRecorder struct{ got []recorded }

func (f *fakeRecorder) RecordPush(_ context.Context, id string, p service.PushAttempt) error {
	f.got = append(f.got, recorded{id, p})
	return nil
}

const pushCluster = "0eea643d-b563-4fbc-8093-ed801966a739"

func TestRecordInventoryPushes(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		status     int
		body       string
		bound      string
		wantCount  int
		wantReason string
	}{
		{"accepted push is left to the handler", http.MethodPost, "/api/v1/clusters/" + pushCluster + "/inventory", 200, `{}`, "", 0, ""},
		{"other routes ignored", http.MethodPost, "/api/v1/sboms", 401, `{}`, "", 0, ""},
		{"bad key", http.MethodPost, "/api/v1/clusters/" + pushCluster + "/inventory", 401, `{"detail":"not authenticated"}`, "", 1,
			"The agent's API key was not accepted: it was revoked, rotated or mistyped."},
		{"missing capability", http.MethodPost, "/api/v1/clusters/" + pushCluster + "/inventory", 403, `{"detail":"missing push_inventory"}`, "", 1,
			"The agent's key may not push here: missing push_inventory"},
		{"validation", http.MethodPost, "/api/v1/clusters/" + pushCluster + "/inventory", 422,
			`{"detail":"validation failed","errors":[{"message":"expected string","location":"body.workloads[0].imageRef"}]}`, "", 1,
			"The snapshot failed validation: validation failed; body.workloads[0].imageRef expected string"},
		{"oversized", http.MethodPost, "/api/v1/clusters/" + pushCluster + "/inventory", 413, ``, "", 1,
			"The snapshot was larger than the server accepts."},
		{"credential for another cluster", http.MethodPost, "/api/v1/clusters/22e457b6-3338-4526-8af3-66435dd9eb1a/inventory", 403, `{}`, pushCluster, 2, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			rec := &fakeRecorder{}
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.bound != "" {
					notePushFromContext(r.Context()).boundClusterID = tt.bound
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			h := RecordInventoryPushes(rec)(inner)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path, nil))

			is.Equal(w.Code, tt.status) // the response passes through untouched
			is.Equal(len(rec.got), tt.wantCount)
			if tt.wantReason != "" {
				is.Equal(rec.got[0].cluster, pushCluster)
				is.Equal(rec.got[0].attempt.Reason, tt.wantReason)
				is.Equal(rec.got[0].attempt.Accepted, false)
			}
			if tt.bound != "" {
				is.Equal(rec.got[0].cluster, tt.bound)
			}
		})
	}
}
