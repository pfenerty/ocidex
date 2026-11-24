package service

import (
	"context"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/vuln"
)

// ChangeVuln is one CVE a package change closed or opened.
type ChangeVuln struct {
	ID       string `json:"id" doc:"Canonical vulnerability id; aliases are collapsed"`
	Severity string `json:"severity" enum:"CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN"`
}

// SeverityTally counts distinct CVEs per severity.
type SeverityTally struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

func (t *SeverityTally) add(severity string) {
	switch severity {
	case vuln.SeverityCritical:
		t.Critical++
	case vuln.SeverityHigh:
		t.High++
	case vuln.SeverityMedium:
		t.Medium++
	case vuln.SeverityLow:
		t.Low++
	default:
		t.Unknown++
	}
}

// ChangelogVulnTotals is what a release did to the image's CVEs.
type ChangelogVulnTotals struct {
	Closed SeverityTally `json:"closed" doc:"CVEs the previous release had and this one does not"`
	Opened SeverityTally `json:"opened" doc:"CVEs this release has and the previous one did not"`
}

// sbomVulns is one SBOM's findings: component purl -> canonical id -> severity.
type sbomVulns map[string]map[string]string

// all flattens the findings to canonical id -> severity across every component.
func (v sbomVulns) all() map[string]string {
	out := map[string]string{}
	for _, byID := range v {
		for id, sev := range byID {
			out[id] = sev
		}
	}
	return out
}

// vulnsForSBOMs loads the findings for every given SBOM in one query.
func vulnsForSBOMs(ctx context.Context, q *repository.Queries, ids []pgtype.UUID) (map[pgtype.UUID]sbomVulns, error) {
	rows, err := q.ListSBOMsComponentCanonicalVulns(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("listing changelog vulnerabilities: %w", err)
	}
	out := make(map[pgtype.UUID]sbomVulns, len(ids))
	for _, r := range rows {
		bySBOM := out[r.SbomID]
		if bySBOM == nil {
			bySBOM = sbomVulns{}
			out[r.SbomID] = bySBOM
		}
		byID := bySBOM[r.Purl]
		if byID == nil {
			byID = map[string]string{}
			bySBOM[r.Purl] = byID
		}
		sev := r.Severity
		if sev == "" {
			sev = vuln.SeverityUnknown
		}
		byID[r.CanonicalID] = sev
	}
	return out, nil
}

// annotateVulns fills Closes/Opens on each change and the entry's totals.
//
// The per-change lists compare the package's own findings across the two
// versions. The totals compare the whole images instead, so a CVE one change
// closes but another package still carries is not counted as closed.
func annotateVulns(entry *ChangelogEntry, from, to sbomVulns) {
	for i := range entry.Changes {
		c := &entry.Changes[i]
		var before, after map[string]string
		switch c.Type {
		case dirRemoved:
			before = lookupVulns(from, c.Purl)
		case dirAdded:
			after = lookupVulns(to, c.Purl)
		default:
			before = lookupVulns(from, c.previousPurl)
			after = lookupVulns(to, c.Purl)
		}
		c.Closes = vulnDifference(before, after)
		c.Opens = vulnDifference(after, before)
	}

	totals := &ChangelogVulnTotals{}
	fromAll, toAll := from.all(), to.all()
	for _, v := range vulnDifference(fromAll, toAll) {
		totals.Closed.add(v.Severity)
	}
	for _, v := range vulnDifference(toAll, fromAll) {
		totals.Opened.add(v.Severity)
	}
	entry.Vulns = totals
}

func lookupVulns(v sbomVulns, purl *string) map[string]string {
	if purl == nil {
		return nil
	}
	return v[*purl]
}

// vulnDifference returns the CVEs in a that are not in b, most severe first.
func vulnDifference(a, b map[string]string) []ChangeVuln {
	var out []ChangeVuln
	for id, sev := range a {
		if _, ok := b[id]; !ok {
			out = append(out, ChangeVuln{ID: id, Severity: sev})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := severityRank(out[i].Severity), severityRank(out[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return out[i].ID < out[j].ID
	})
	return out
}
