package user

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/pfenerty/ocidex/internal/enrichment"
)

func TestEnricher_Name(t *testing.T) {
	if got := NewEnricher().Name(); got != "user" {
		t.Errorf("Name() = %q, want %q", got, "user")
	}
}

func TestEnricher_CanEnrich(t *testing.T) {
	tests := []struct {
		name string
		ref  enrichment.SubjectRef
		want bool
	}{
		{
			name: "all empty",
			ref:  enrichment.SubjectRef{},
			want: false,
		},
		{
			name: "architecture only",
			ref:  enrichment.SubjectRef{Architecture: "amd64"},
			want: true,
		},
		{
			name: "build date only",
			ref:  enrichment.SubjectRef{BuildDate: "2024-01-01T00:00:00Z"},
			want: true,
		},
		{
			name: "subject version only",
			ref:  enrichment.SubjectRef{SubjectVersion: "v1.0.0"},
			want: true,
		},
		{
			name: "all fields",
			ref:  enrichment.SubjectRef{Architecture: "arm64", BuildDate: "2024-06-01", SubjectVersion: "v2.0.0"},
			want: true,
		},
	}
	e := NewEnricher()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e.CanEnrich(tt.ref); got != tt.want {
				t.Errorf("CanEnrich() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnricher_Enrich(t *testing.T) {
	tests := []struct {
		name     string
		ref      enrichment.SubjectRef
		wantKeys map[string]string
	}{
		{
			name:     "empty ref produces empty object",
			ref:      enrichment.SubjectRef{},
			wantKeys: map[string]string{},
		},
		{
			name:     "architecture maps to architecture key",
			ref:      enrichment.SubjectRef{Architecture: "amd64"},
			wantKeys: map[string]string{"architecture": "amd64"},
		},
		{
			name:     "build date maps to created key",
			ref:      enrichment.SubjectRef{BuildDate: "2024-01-01T00:00:00Z"},
			wantKeys: map[string]string{"created": "2024-01-01T00:00:00Z"},
		},
		{
			name:     "subject version maps to imageVersion key",
			ref:      enrichment.SubjectRef{SubjectVersion: "v1.2.3"},
			wantKeys: map[string]string{"imageVersion": "v1.2.3"},
		},
		{
			name: "all fields present",
			ref: enrichment.SubjectRef{
				Architecture:   "arm64",
				BuildDate:      "2024-06-15T12:00:00Z",
				SubjectVersion: "v3.0.0",
			},
			wantKeys: map[string]string{
				"architecture": "arm64",
				"created":      "2024-06-15T12:00:00Z",
				"imageVersion": "v3.0.0",
			},
		},
	}

	e := NewEnricher()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := e.Enrich(context.Background(), tt.ref)
			if err != nil {
				t.Fatalf("Enrich() error = %v", err)
			}
			var got map[string]string
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal result: %v", err)
			}
			if len(got) != len(tt.wantKeys) {
				t.Errorf("got %d keys, want %d: %v", len(got), len(tt.wantKeys), got)
			}
			for k, v := range tt.wantKeys {
				if got[k] != v {
					t.Errorf("key %q: got %q, want %q", k, got[k], v)
				}
			}
		})
	}
}
