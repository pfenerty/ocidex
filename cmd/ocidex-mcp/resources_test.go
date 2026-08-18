package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/matryer/is"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/pkg/client"
)

func TestOpenAPIResourceIsListedAndReadable(t *testing.T) {
	i := is.New(t)
	var called bool
	api := &client.FakeClient{
		GetOpenAPISpecFn: func(context.Context) (json.RawMessage, error) {
			called = true
			return json.RawMessage(`{"openapi":"3.1.0","paths":{}}`), nil
		},
	}
	session := connect(t, api)

	listed, err := session.ListResources(t.Context(), nil)
	i.NoErr(err)
	var found bool
	for _, r := range listed.Resources {
		if r.URI == openAPIResourceURI {
			found = true
			i.Equal(r.MIMEType, "application/json")
			// The description names the server, so a client holding two OCIDex
			// connections can tell which spec is which.
			i.True(strings.Contains(r.Description, testServerURL))
		}
	}
	i.True(found)

	res, err := session.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: openAPIResourceURI})
	i.NoErr(err)
	i.True(called)
	i.Equal(len(res.Contents), 1)
	i.True(strings.Contains(res.Contents[0].Text, `"openapi":"3.1.0"`))
}

// An unreachable or unauthorised server must fail the read with the same
// advice the tools give, not with a bare transport error.
func TestOpenAPIResourceSurfacesErrors(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		GetOpenAPISpecFn: func(context.Context) (json.RawMessage, error) {
			return nil, &client.APIError{Status: 401, Detail: "invalid api key"}
		},
	}

	_, err := connect(t, api).ReadResource(t.Context(), &mcp.ReadResourceParams{URI: openAPIResourceURI})
	i.True(err != nil)
	i.True(strings.Contains(err.Error(), "ocidex-cli login"))
}
