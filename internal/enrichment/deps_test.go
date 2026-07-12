package enrichment

import (
	"reflect"
	"testing"
)

func TestDependents(t *testing.T) {
	tests := []struct {
		name     string
		enricher string
		want     []string
	}{
		{name: "prerequisite has dependents", enricher: "oci-metadata", want: []string{"git"}},
		{name: "root enricher has no dependents", enricher: "user", want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Dependents(tt.enricher)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Dependents(%q) = %v, want %v", tt.enricher, got, tt.want)
			}
		})
	}
}

func TestPrerequisites(t *testing.T) {
	tests := []struct {
		name     string
		enricher string
		want     []string
	}{
		{name: "dependent enricher has prerequisites", enricher: "git", want: []string{"oci-metadata"}},
		{name: "root enricher has no prerequisites", enricher: "user", want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Prerequisites(tt.enricher)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Prerequisites(%q) = %v, want %v", tt.enricher, got, tt.want)
			}
		})
	}
}
