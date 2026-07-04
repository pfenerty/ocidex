package vuln

import (
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// Severity labels, mapped from the CVSS base score per the v3/v4 qualitative scale.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityUnknown  = "UNKNOWN"
)

// DeriveSeverity returns the highest severity label and CVSS base score across a
// record's CVSS severity entries. It returns ("UNKNOWN", nil) when no entry
// carries a parseable CVSS vector (e.g. records that only ship a distro severity
// string). The vector's own prefix selects the CVSS version.
func DeriveSeverity(sevs []Severity) (string, *float32) {
	var best float64
	var found bool
	for _, s := range sevs {
		if score, ok := scoreFromVector(s.Score); ok && score >= best {
			best = score
			found = true
		}
	}
	if !found {
		return SeverityUnknown, nil
	}
	f := float32(best)
	return severityLabel(best), &f
}

func scoreFromVector(vector string) (float64, bool) {
	switch {
	case strings.HasPrefix(vector, "CVSS:4.0"):
		if v, err := gocvss40.ParseVector(vector); err == nil {
			return v.Score(), true
		}
	case strings.HasPrefix(vector, "CVSS:3.1"):
		if v, err := gocvss31.ParseVector(vector); err == nil {
			return v.BaseScore(), true
		}
	case strings.HasPrefix(vector, "CVSS:3.0"):
		if v, err := gocvss30.ParseVector(vector); err == nil {
			return v.BaseScore(), true
		}
	default:
		// CVSS v2 vectors have no "CVSS:" prefix (e.g. "AV:N/AC:L/Au:N/C:P/I:P/A:P").
		if v, err := gocvss20.ParseVector(vector); err == nil {
			return v.BaseScore(), true
		}
	}
	return 0, false
}

// normalizeSeverityLabel converts a plain-text severity string (e.g. from
// database_specific.severity in Go advisories) to a canonical label. Returns ""
// for unrecognised values so callers can distinguish "not present" from UNKNOWN.
func normalizeSeverityLabel(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case SeverityCritical:
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityMedium:
		return SeverityMedium
	case SeverityLow:
		return SeverityLow
	default:
		return ""
	}
}

// severityLabel maps a CVSS base score to the qualitative rating used by the
// v3/v4 spec.
func severityLabel(score float64) string {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0.0:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}
