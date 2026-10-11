package grypematch

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/anchore/grype/grype/vulnerability"

	"github.com/pfenerty/ocidex/internal/vuln"
)

// summaryMaxRunes bounds the derived one-line summary; grype records carry only
// a description, while the read side lists a summary per row.
const summaryMaxRunes = 200

// Rows folds findings into one vulnerability row per ID. The same ID can arrive
// from several namespaces (a CVE matched against both a Debian and an Ubuntu
// package, each with NVD as a related record); the row takes the most severe of
// the matched sources' own assessments (see rowAcc.row). Rows are sorted by ID.
func Rows(findings []Finding) []vuln.Row {
	byID := map[string]*rowAcc{}
	var order []string
	for _, f := range findings {
		acc, ok := byID[f.VulnerabilityID]
		if !ok {
			acc = &rowAcc{id: f.VulnerabilityID, seen: map[string]bool{}}
			byID[f.VulnerabilityID] = acc
			order = append(order, f.VulnerabilityID)
		}
		acc.add(f)
	}
	sort.Strings(order)
	out := make([]vuln.Row, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id].row())
	}
	return out
}

// Mappings groups findings into the per-purl mapping rows ReplacePackageVulns
// writes, one per (purl, vulnerability). When grype reports the same pair twice
// (two matchers, or two namespaces), the first carrying a fixed version wins.
func Mappings(findings []Finding) map[string][]vuln.PackageVulnRef {
	out := map[string][]vuln.PackageVulnRef{}
	idx := map[[2]string]int{}
	for _, f := range findings {
		k := [2]string{f.Purl, f.VulnerabilityID}
		if i, ok := idx[k]; ok {
			if out[f.Purl][i].FixedVersion == "" {
				out[f.Purl][i].FixedVersion = f.FixedVersion
			}
			continue
		}
		idx[k] = len(out[f.Purl])
		out[f.Purl] = append(out[f.Purl], vuln.PackageVulnRef{
			VulnerabilityID: f.VulnerabilityID,
			FixedVersion:    f.FixedVersion,
		})
	}
	return out
}

type rowAcc struct {
	id          string
	aliases     []string
	seen        map[string]bool
	description string
	// descFromMatch: description came from a matched record, not a related one.
	descFromMatch bool
	labels        []string        // matched records' own severity labels
	ownVectors    []vuln.Severity // CVSS from matched records
	relVectors    []vuln.Severity // CVSS from related records (usually NVD)
	refs          []vuln.Reference
	raw           []*vulnerability.Metadata
}

func (a *rowAcc) add(f Finding) {
	for _, r := range f.Related {
		if r != a.id && !a.seen["alias:"+r] {
			a.seen["alias:"+r] = true
			a.aliases = append(a.aliases, r)
		}
	}
	if f.Metadata != nil {
		a.addMetadata(f.Metadata, true)
	}
	for _, md := range f.RelatedMetadata {
		if md != nil {
			a.addMetadata(md, false)
		}
	}
}

// addMetadata folds one record in. matched is true for the record grype matched,
// false for a related one.
func (a *rowAcc) addMetadata(md *vulnerability.Metadata, matched bool) {
	// The first matched record's description wins; a related record's only fills
	// in until a matched one with text arrives.
	if md.Description != "" && !a.descFromMatch && (matched || a.description == "") {
		a.description = md.Description
		a.descFromMatch = matched
	}
	a.addCVSS(md.Cvss, matched)
	if matched {
		if md.Severity != "" {
			a.labels = append(a.labels, md.Severity)
		}
		a.addRef("ADVISORY", md.DataSource)
		for _, u := range md.URLs {
			a.addRef("WEB", u)
		}
	}
	if key := "raw:" + md.Namespace + "/" + md.ID; !a.seen[key] {
		a.seen[key] = true
		a.raw = append(a.raw, md)
	}
}

func (a *rowAcc) addCVSS(cvss []vulnerability.Cvss, matched bool) {
	for _, c := range cvss {
		key := fmt.Sprintf("cvss:%t:%s", matched, c.Vector)
		if c.Vector == "" || a.seen[key] {
			continue
		}
		a.seen[key] = true
		sev := vuln.Severity{Type: "CVSS_V" + c.Version, Score: c.Vector}
		if matched {
			a.ownVectors = append(a.ownVectors, sev)
		} else {
			a.relVectors = append(a.relVectors, sev)
		}
	}
}

func (a *rowAcc) addRef(typ, url string) {
	if url == "" || a.seen["ref:"+url] {
		return
	}
	a.seen["ref:"+url] = true
	a.refs = append(a.refs, vuln.Reference{Type: typ, URL: url})
}

// row resolves severity the way grype presents it: the matched source's own
// assessment wins, because a distro's "negligible" is a statement that NVD's score
// does not apply to its build. Only when no matched record says anything does a
// related record's CVSS decide. The stored score/vector is the best available
// CVSS either way, so a LOW Debian finding can still show NVD's 9.8.
func (a *rowAcc) row() vuln.Row {
	ownLabel, ownScore, ownVector := vuln.DeriveSeverity(a.ownVectors)
	_, relScore, relVector := vuln.DeriveSeverity(a.relVectors)
	label := highestLabel(a.labels)
	if label == vuln.SeverityUnknown {
		label = ownLabel
	}
	score, vector := ownScore, ownVector
	if score == nil {
		score, vector = relScore, relVector
	}
	if label == vuln.SeverityUnknown && relScore != nil {
		label, _, _ = vuln.DeriveSeverity(a.relVectors)
	}
	raw, _ := json.Marshal(a.raw) // metadata is plain data; Marshal cannot fail here
	return vuln.Row{
		ID:          a.id,
		Aliases:     a.aliases,
		CanonicalID: vuln.CanonicalID(a.id, a.aliases),
		Summary:     summarize(a.description),
		Details:     a.description,
		Severity:    label,
		CVSSScore:   score,
		CVSSVector:  vector,
		Raw:         raw,
		References:  a.refs,
	}
}

// highestLabel maps grype's per-source severity labels onto ocidex's scale and
// returns the most severe. grype's "Negligible" (Debian's "unimportant", Ubuntu's
// "negligible") has no ocidex equivalent and reads as LOW.
func highestLabel(labels []string) string {
	rank := map[string]int{vuln.SeverityLow: 1, vuln.SeverityMedium: 2, vuln.SeverityHigh: 3, vuln.SeverityCritical: 4}
	best := vuln.SeverityUnknown
	for _, l := range labels {
		var norm string
		switch strings.ToLower(strings.TrimSpace(l)) {
		case "critical":
			norm = vuln.SeverityCritical
		case "high":
			norm = vuln.SeverityHigh
		case "medium", "moderate":
			norm = vuln.SeverityMedium
		case "low", "negligible":
			norm = vuln.SeverityLow
		default:
			continue
		}
		if rank[norm] > rank[best] {
			best = norm
		}
	}
	return best
}

// summarize returns the description's first line, cut at summaryMaxRunes on a
// word boundary.
func summarize(desc string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(desc), "\n")
	line = strings.TrimSpace(line)
	if utf8.RuneCountInString(line) <= summaryMaxRunes {
		return line
	}
	r := []rune(line)[:summaryMaxRunes]
	cut := string(r)
	if i := strings.LastIndexByte(cut, ' '); i > summaryMaxRunes/2 {
		cut = cut[:i]
	}
	return strings.TrimRight(cut, " ,.;:") + "…"
}
