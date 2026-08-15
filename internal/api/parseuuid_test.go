package api

// Internal test file. parseUUID is unexported and has no exported shim any
// more (ocidex-wp9b.4 removed the deprecated ParseUUID), so its unit tests
// live inside the package rather than in package api_test.

import "testing"

func TestParseUUID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid UUID", "3e671687-395b-41f5-a30f-a58921a69b79", false},
		{"invalid", "not-a-uuid", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := parseUUID(tt.input)
			switch {
			case tt.wantErr && err == nil:
				t.Fatalf("parseUUID(%q): expected an error, got none", tt.input)
			case !tt.wantErr && err != nil:
				t.Fatalf("parseUUID(%q): %v", tt.input, err)
			case !tt.wantErr && !id.Valid:
				t.Fatalf("parseUUID(%q): returned an invalid UUID", tt.input)
			}
		})
	}
}
