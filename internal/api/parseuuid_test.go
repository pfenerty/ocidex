package api

// Internal test file: requireUUID is unexported, so its unit tests live
// inside the package rather than in package api_test.

import (
	"strings"
	"testing"
)

func TestRequireUUID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid UUID", "3e671687-395b-41f5-a30f-a58921a69b79", false},
		{"uppercase is canonicalized", "3E671687-395B-41F5-A30F-A58921A69B79", false},
		{"invalid", "not-a-uuid", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := requireUUID(tt.input)
			switch {
			case tt.wantErr && err == nil:
				t.Fatalf("requireUUID(%q): expected an error, got none", tt.input)
			case !tt.wantErr && err != nil:
				t.Fatalf("requireUUID(%q): %v", tt.input, err)
			case !tt.wantErr && id != strings.ToLower(tt.input):
				t.Fatalf("requireUUID(%q) = %q, want the canonical lowercase form", tt.input, id)
			}
		})
	}
}
