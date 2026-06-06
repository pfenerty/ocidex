package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// Config holds options for constructing a Client.
type Config struct {
	BaseURL    string       // API base URL, e.g. "http://localhost:8080"; no trailing slash
	APIKey     string       // Bearer token (ocidex_<token>); empty for unauthenticated
	HTTPClient *http.Client // nil uses http.DefaultClient
}

type httpClient struct {
	base   string
	apiKey string
	http   *http.Client
}

// New creates a Client from cfg. Returns *httpClient; callers assign to Client as needed.
func New(cfg Config) *httpClient {
	c := cfg.HTTPClient
	if c == nil {
		c = http.DefaultClient
	}
	return &httpClient{base: cfg.BaseURL, apiKey: cfg.APIKey, http: c}
}

// request is the JSON-body convenience wrapper around do.
// jsonBody is marshaled to JSON and sent as application/json.
// dest, if non-nil, is JSON-decoded from a 2xx response body.
func (c *httpClient) request(ctx context.Context, method, path string, params url.Values, jsonBody, dest any) error {
	var body io.Reader
	ct := ""
	if jsonBody != nil {
		b, err := json.Marshal(jsonBody)
		if err != nil {
			return fmt.Errorf("encoding request body: %w", err)
		}
		body = bytes.NewReader(b)
		ct = "application/json"
	}
	return c.do(ctx, method, path, params, body, ct, dest)
}

// do executes one HTTP request and handles auth, errors, and response decoding.
// body may be nil (no body). contentType is set only when body is non-nil.
func (c *httpClient) do(ctx context.Context, method, path string, params url.Values, body io.Reader, contentType string, dest any) error {
	u := c.base + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return mapError(resp.StatusCode, respBody)
	}

	if dest != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, dest); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}

// pageParams converts PageOpts into url.Values for list endpoints.
func pageParams(opts PageOpts) url.Values {
	p := url.Values{}
	if opts.Limit > 0 {
		p.Set("limit", strconv.Itoa(int(opts.Limit)))
	}
	if opts.Offset > 0 {
		p.Set("offset", strconv.Itoa(int(opts.Offset)))
	}
	return p
}

// Compile-time assertion that *httpClient satisfies the full Client interface.
var _ Client = (*httpClient)(nil)
