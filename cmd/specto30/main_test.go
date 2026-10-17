package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestConvert(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "nullable array",
			in:   `{"openapi":"3.1.0","s":{"type":["array","null"],"items":{"type":"string"}}}`,
			want: `{"openapi":"3.0.3","s":{"type":"array","nullable":true,"items":{"type":"string"}}}`,
		},
		{
			name: "multi-type without null stays a list",
			in:   `{"openapi":"3.1.0","s":{"type":["string","integer"]}}`,
			want: `{"openapi":"3.0.3","s":{"type":["string","integer"]}}`,
		},
		{
			name: "only null becomes an empty list, as the python script did",
			in:   `{"openapi":"3.1.0","s":{"type":["null"]}}`,
			want: `{"openapi":"3.0.3","s":{"type":[],"nullable":true}}`,
		},
		{
			name: "nested in arrays and scalar types untouched",
			in:   `{"openapi":"3.1.0","allOf":[{"type":["object","null"]},{"type":"integer","maximum":9007199254740993}]}`,
			want: `{"openapi":"3.0.3","allOf":[{"type":"object","nullable":true},{"type":"integer","maximum":9007199254740993}]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "spec.json")
			if err := os.WriteFile(path, []byte(tt.in), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := convert(path)
			if err != nil {
				t.Fatalf("convert: %v", err)
			}
			if got, want := canonical(t, out), canonical(t, []byte(tt.want)); got != want {
				t.Errorf("got  %s\nwant %s", got, want)
			}
		})
	}
}

// canonical re-encodes JSON with sorted keys and exact numbers, so the test
// compares content rather than formatting.
func canonical(t *testing.T, b []byte) string {
	t.Helper()
	var v any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decoding %s: %v", b, err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
