package vuln

import (
	"testing"

	"github.com/matryer/is"
)

func TestNormalizeSeverityLabel(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"HIGH", "HIGH"},
		{"high", "HIGH"},
		{"Medium", "MEDIUM"},
		{"CRITICAL", "CRITICAL"},
		{"low", "LOW"},
		{"", ""},
		{"unknown", ""},
		{"moderate", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			is := is.New(t)
			is.Equal(normalizeSeverityLabel(tt.in), tt.want)
		})
	}
}

func TestDeriveSeverity(t *testing.T) {
	tests := []struct {
		name     string
		sevs     []Severity
		wantName string
		wantNil  bool
	}{
		{
			name:     "cvss v3.1 critical",
			sevs:     []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			wantName: "CRITICAL",
		},
		{
			name:     "cvss v3.1 medium",
			sevs:     []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}},
			wantName: "MEDIUM",
		},
		{
			name:     "picks highest across entries",
			sevs:     []Severity{{Score: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"}, {Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			wantName: "CRITICAL",
		},
		{
			name:     "no cvss vector",
			sevs:     []Severity{{Type: "Ubuntu", Score: "high"}},
			wantName: "UNKNOWN",
			wantNil:  true,
		},
		{
			name:     "empty",
			sevs:     nil,
			wantName: "UNKNOWN",
			wantNil:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			label, score := DeriveSeverity(tt.sevs)
			is.Equal(label, tt.wantName)
			is.Equal(score == nil, tt.wantNil)
		})
	}
}
