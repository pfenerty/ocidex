package vuln

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
)

func TestQueryPurlsMapsResultsByIndex(t *testing.T) {
	is := is.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/v1/querybatch")
		var req struct {
			Queries []batchQuery `json:"queries"`
		}
		body, _ := io.ReadAll(r.Body)
		is.NoErr(json.Unmarshal(body, &req))
		is.Equal(len(req.Queries), 2)

		// Echo one vuln for the first purl, none for the second.
		_, _ = w.Write([]byte(`{"results":[
			{"vulns":[{"id":"CVE-1","modified":"2026-01-01T00:00:00Z"},{"id":"GHSA-2","modified":"2026-01-02T00:00:00Z"}]},
			{"vulns":[]}
		]}`))
	}))
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	got, err := c.QueryPurls(context.Background(), []string{"pkg:npm/lodash@4.17.20", "pkg:npm/clean@1.0.0"})
	is.NoErr(err)
	is.Equal(got["pkg:npm/lodash@4.17.20"], []QueryRef{{ID: "CVE-1", Modified: "2026-01-01T00:00:00Z"}, {ID: "GHSA-2", Modified: "2026-01-02T00:00:00Z"}})
	is.Equal(got["pkg:npm/clean@1.0.0"], []QueryRef{})
}

func TestQueryPurlsChunksLargeInput(t *testing.T) {
	is := is.New(t)

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req struct {
			Queries []batchQuery `json:"queries"`
		}
		body, _ := io.ReadAll(r.Body)
		is.NoErr(json.Unmarshal(body, &req))
		// One empty result per query so counts line up.
		w.Write([]byte(`{"results":[`))
		for i := range req.Queries {
			if i > 0 {
				w.Write([]byte(","))
			}
			w.Write([]byte(`{"vulns":[]}`))
		}
		w.Write([]byte(`]}`))
	}))
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL), WithBatchSize(2))
	purls := []string{"a", "b", "c", "d", "e"}
	got, err := c.QueryPurls(context.Background(), purls)
	is.NoErr(err)
	is.Equal(calls, 3)    // 2 + 2 + 1
	is.Equal(len(got), 5) // every purl present in the map
}

func TestQueryPurlsResultCountMismatch(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]}]}`)) // 1 result for 2 queries
	}))
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	_, err := c.QueryPurls(context.Background(), []string{"a", "b"})
	is.True(err != nil)
}

func TestGetVulnParsesRecordAndKeepsRaw(t *testing.T) {
	is := is.New(t)

	const rec = `{
		"id":"CVE-2021-23337",
		"aliases":["GHSA-35jh-r3h4-6jhm"],
		"summary":"Command injection in lodash",
		"details":"long details",
		"published":"2021-02-15T11:15:00Z",
		"modified":"2026-01-01T00:00:00Z",
		"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
		"affected":[{"package":{"ecosystem":"npm","name":"lodash","purl":"pkg:npm/lodash"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/v1/vulns/CVE-2021-23337")
		_, _ = w.Write([]byte(rec))
	}))
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	got, err := c.GetVuln(context.Background(), "CVE-2021-23337")
	is.NoErr(err)
	is.Equal(got.ID, "CVE-2021-23337")
	is.Equal(got.Aliases, []string{"GHSA-35jh-r3h4-6jhm"})
	is.Equal(got.Severity[0].Type, "CVSS_V3")
	is.Equal(got.Affected[0].Ranges[0].Events[1].Fixed, "4.17.21")
	is.True(len(got.Raw) > 0) // full body retained for JSONB storage
}

func TestGetVulnNon200(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	_, err := c.GetVuln(context.Background(), "MISSING")
	is.True(err != nil)
}
