package client

import (
	"context"
	"net/http"
)

func (c *httpClient) CreateAPIKey(ctx context.Context, body CreateAPIKeyInputBody) (CreateAPIKeyOutputBody, error) {
	var out CreateAPIKeyOutputBody
	err := c.request(ctx, http.MethodPost, "/api/v1/auth/keys", nil, body, &out)
	return out, err
}

func (c *httpClient) ListAPIKeys(ctx context.Context) ([]KeyMetaResponse, error) {
	var out ListAPIKeysOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/auth/keys", nil, nil, &out); err != nil {
		return nil, err
	}
	return derefSlice(out.Keys), nil
}

func (c *httpClient) DeleteAPIKey(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/auth/keys/"+id, nil, nil, nil)
}

func (c *httpClient) GetCurrentUser(ctx context.Context) (MeOutputBody, error) {
	var out MeOutputBody
	err := c.request(ctx, http.MethodGet, "/api/v1/users/me", nil, nil, &out)
	return out, err
}
