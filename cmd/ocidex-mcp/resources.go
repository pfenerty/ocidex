package main

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/pkg/client"
)

// openAPIResourceURI names the spec resource. The ocidex:// scheme keeps it
// distinct from any file:// or https:// resource a client also holds, and the
// path says which document it is.
const openAPIResourceURI = "ocidex://openapi.json"

// registerResources exposes the server's own OpenAPI document.
//
// It is fetched from the live server rather than embedded at build time, so it
// describes the deployment these tools are actually talking to — a binary built
// from one revision and pointed at a server running another would otherwise
// hand out a spec that quietly disagrees with every response.
//
// The tools remain the intended path; this exists for the endpoints no tool
// wraps, so an agent that needs one can read the schema instead of guessing.
func registerResources(srv *mcp.Server, api client.Client, server string) {
	srv.AddResource(&mcp.Resource{
		URI:      openAPIResourceURI,
		Name:     "openapi",
		Title:    "OCIDex OpenAPI specification",
		MIMEType: "application/json",
		Description: fmt.Sprintf(
			"The complete OpenAPI 3.1 description of the OCIDex API at %s, fetched from that "+
				"server. Read it when you need an endpoint the tools do not cover; prefer the tools "+
				"otherwise, since they handle pagination and ambiguous lookups for you.", server),
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		spec, err := api.GetOpenAPISpec(ctx)
		if err != nil {
			return nil, toolError("reading the OpenAPI specification", err)
		}
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{
				URI:      req.Params.URI,
				MIMEType: "application/json",
				Text:     string(spec),
			}},
		}, nil
	})
}
