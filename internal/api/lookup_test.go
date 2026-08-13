package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// Artifact UUIDs the fake resolver hands out. artUbuntuPrivate deliberately
// shares a name with artUbuntu so the visibility test has something that would
// produce a 409 if R5 filtering were skipped.
const (
	artUbuntu        = "3e671687-395b-41f5-a30f-a58921a69b79"
	artUbuntuPrivate = "11111111-2222-3333-4444-555555555555"
	artUbuntuFile    = "66666666-7777-8888-9999-aaaaaaaaaaaa"
	artOcidex        = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
)

// artifactRow is one row in the fake resolver's table. private mirrors what
// artifact_visible() decides in the real query.
type artifactRow struct {
	id      string
	typ     string
	name    string
	group   string
	private bool
}

// lookupSearchService resolves artifact lookups against an in-memory table,
// applying the same ADR-042 R4 qualifier ladder and R5 visibility filter that
// the LookupArtifacts query applies. Filtering here rather than in the handler
// is the point: it lets the tests assert the handler counts only what the
// service already deemed visible.
type lookupSearchService struct {
	fakeSearchService
	rows []artifactRow
}

func (f *lookupSearchService) LookupArtifact(_ context.Context, q service.ArtifactLookupQuery, vis service.VisibilityFilter) ([]service.LookupCandidate, error) {
	out := make([]service.LookupCandidate, 0, len(f.rows))
	for _, r := range f.rows {
		switch {
		case r.name != q.Name:
			continue
		case q.Type != "" && r.typ != q.Type:
			continue
		case q.Group != "" && r.group != q.Group:
			continue
		case r.private && !vis.IsAdmin:
			continue
		}
		out = append(out, service.LookupCandidate{
			ID:         r.id,
			Qualifiers: map[string]string{"name": r.name, "type": r.typ, "group": r.group},
		})
	}
	return out, nil
}

// GetArtifact echoes back the requested id so a 200 proves which candidate the
// resolver picked, not merely that some artifact came back.
func (f *lookupSearchService) GetArtifact(_ context.Context, id pgtype.UUID, _ service.VisibilityFilter) (service.ArtifactDetail, error) {
	return service.ArtifactDetail{
		ArtifactSummary: service.ArtifactSummary{ID: uuidString(id), Type: "container", Name: "resolved"},
	}, nil
}

func uuidString(u pgtype.UUID) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u.Bytes[0:4], u.Bytes[4:6], u.Bytes[6:8], u.Bytes[8:10], u.Bytes[10:16])
}

// lookupFixture is the table every artifact lookup test resolves against.
func lookupFixture() *lookupSearchService {
	return &lookupSearchService{rows: []artifactRow{
		// Two rows named "ubuntu" differing only by type — the R4 ladder's
		// second rung disambiguates them.
		{id: artUbuntu, typ: "container", name: "ubuntu"},
		{id: artUbuntuFile, typ: "file", name: "ubuntu"},
		// A third "ubuntu", private. It must never reach the candidate count.
		{id: artUbuntuPrivate, typ: "container", name: "ubuntu", group: "canonical", private: true},
		// Slash-bearing name: the reason the key travels in the query string
		// rather than a path segment (ADR-042 R1).
		{id: artOcidex, typ: "container", name: "ghcr.io/pfenerty/ocidex"},
	}}
}

func TestLookupArtifact(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantStatus int
		wantID     string
	}{
		{"unique match", "?name=ghcr.io/pfenerty/ocidex", http.StatusOK, artOcidex},
		{"unique match with type qualifier", "?name=ubuntu&type=file", http.StatusOK, artUbuntuFile},
		{"no match", "?name=alpine", http.StatusNotFound, ""},
		{"ambiguous", "?name=ubuntu", http.StatusConflict, ""},
		{"missing name", "", http.StatusUnprocessableEntity, ""},
		// An empty qualifier is a wildcard, not a match on the empty string,
		// so it must not narrow "ubuntu" down to a single row.
		{"empty qualifier is a wildcard", "?name=ubuntu&type=&group=", http.StatusConflict, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			router := newTestRouter(&fakeSBOMService{}, lookupFixture())

			r := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/lookup"+tt.query, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			is.Equal(w.Code, tt.wantStatus)

			if tt.wantID != "" {
				var body service.ArtifactDetail
				is.NoErr(json.Unmarshal(w.Body.Bytes(), &body))
				is.Equal(body.ID, tt.wantID)
			}
		})
	}
}

// A 409 must carry the candidates and the qualifier values that tell the
// caller which rung of the ladder to try next.
func TestLookupArtifact_ConflictListsCandidates(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, lookupFixture())

	r := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/lookup?name=ubuntu", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusConflict)

	var body struct {
		Status     int                       `json:"status"`
		Candidates []service.LookupCandidate `json:"candidates"`
	}
	is.NoErr(json.Unmarshal(w.Body.Bytes(), &body))
	is.Equal(body.Status, http.StatusConflict)
	is.Equal(len(body.Candidates), 2)

	types := map[string]string{}
	for _, c := range body.Candidates {
		types[c.ID] = c.Qualifiers["type"]
	}
	is.Equal(types[artUbuntu], "container")
	is.Equal(types[artUbuntuFile], "file")
}

// R5: a private candidate must not turn a unique public match into a 409.
// Without the visibility filter, "ubuntu" + type=container matches both the
// public artUbuntu and the private artUbuntuPrivate.
func TestLookupArtifact_PrivateCandidateDoesNotCauseConflict(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, lookupFixture())

	r := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/lookup?name=ubuntu&type=container", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)

	var body service.ArtifactDetail
	is.NoErr(json.Unmarshal(w.Body.Bytes(), &body))
	is.Equal(body.ID, artUbuntu)
}

// The slash-bearing name has to survive the round trip both raw and
// percent-encoded — a query value tolerates either, which is the whole reason
// ADR-042 R1 rejects a {name} path segment.
func TestLookupArtifact_SlashBearingName(t *testing.T) {
	for _, name := range []string{
		"/api/v1/artifacts/lookup?name=ghcr.io/pfenerty/ocidex",
		"/api/v1/artifacts/lookup?name=" + url.QueryEscape("ghcr.io/pfenerty/ocidex"),
	} {
		is := is.New(t)
		router := newTestRouter(&fakeSBOMService{}, lookupFixture())

		r := httptest.NewRequest(http.MethodGet, name, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		is.Equal(w.Code, http.StatusOK)

		var body service.ArtifactDetail
		is.NoErr(json.Unmarshal(w.Body.Bytes(), &body))
		is.Equal(body.ID, artOcidex)
	}
}
