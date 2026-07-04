package vuln

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"time"
)

const defaultOSVBucketBaseURL = "https://storage.googleapis.com/osv-vulnerabilities"

// ModifiedCSVFetcher fetches per-ecosystem modified_id.csv files from the OSV
// GCS bucket over plain HTTPS (the bucket is publicly readable).
type ModifiedCSVFetcher struct {
	baseURL    string
	httpClient *http.Client
}

// NewModifiedCSVFetcher constructs a fetcher. Empty baseURL falls back to the
// OSV public bucket. A nil httpClient uses a 30-second default.
func NewModifiedCSVFetcher(baseURL string, httpClient *http.Client) *ModifiedCSVFetcher {
	if baseURL == "" {
		baseURL = defaultOSVBucketBaseURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &ModifiedCSVFetcher{baseURL: baseURL, httpClient: httpClient}
}

// FetchMaxModifiedAt downloads <baseURL>/<ecosystem>/modified_id.csv and
// returns the latest modified timestamp across all data rows. Returns a zero
// time if the file contains no parseable timestamps (e.g. empty body or
// header-only). Non-RFC3339 rows are silently skipped.
func (f *ModifiedCSVFetcher) FetchMaxModifiedAt(ctx context.Context, ecosystem string) (time.Time, error) {
	url := fmt.Sprintf("%s/%s/modified_id.csv", f.baseURL, ecosystem)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("building request: %w", err)
	}
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("unexpected status %d fetching %s", resp.StatusCode, url)
	}

	r := csv.NewReader(resp.Body)
	var maxTime time.Time
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return time.Time{}, fmt.Errorf("parsing CSV from %s: %w", url, err)
		}
		if len(record) < 2 {
			continue
		}
		// Skip header row or any row whose second column is not a timestamp.
		t, err := time.Parse(time.RFC3339, record[1])
		if err != nil {
			continue
		}
		if t.After(maxTime) {
			maxTime = t
		}
	}
	return maxTime, nil
}
