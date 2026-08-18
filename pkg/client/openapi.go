package client

import (
	"context"
	"encoding/json"
	"net/http"
)

// GetOpenAPISpec fetches the running server's own OpenAPI document.
//
// It is served by huma from the live route table, so it describes the server
// this client is pointed at rather than whatever spec the caller was built
// from — which is the point: a caller reaching past the typed methods needs the
// surface that actually exists on the other end.
func (c *httpClient) GetOpenAPISpec(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/openapi.json", nil, nil, "", &out); err != nil {
		return nil, err
	}
	return out, nil
}
