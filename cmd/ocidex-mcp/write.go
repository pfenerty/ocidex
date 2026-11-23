package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/pkg/client"
)

// Write tools (ADR-0058 A8). They are registered only for an agent key whose
// capabilities allow them (registerWriteTools), and every one of them:
//
//   - can preview: preview=true describes what would happen and changes nothing;
//   - is safe to retry: the server returns the same pending action for an
//     identical held request, and watching is idempotent;
//   - reports a hold plainly: the request is waiting for a person, nothing ran,
//     and the agent should poll ocidex_approval_status, not resend.

// writeOutcome is what every write tool returns.
type writeOutcome struct {
	Status string `json:"status" jsonschema:"done: it ran. held: waiting for a person's approval; nothing has run. preview: nothing was sent. declined or cancelled: the user refused when asked; nothing was sent"`
	Effect string `json:"effect,omitempty" jsonschema:"What the request does, in OCIDex's words when held, otherwise the tool's"`
	// Set when held.
	ApprovalID  string `json:"approval_id,omitempty" jsonschema:"Pass to ocidex_approval_status to learn the outcome"`
	ApprovalURL string `json:"approval_url,omitempty" jsonschema:"Where a person approves it; give it to the user"`
	Next        string `json:"next,omitempty" jsonschema:"What to do next"`
}

const (
	statusPreview = "preview"
	statusFailed  = "failed"
)

// previewOutcome is the answer to preview=true: what would happen.
func previewOutcome(effect string) writeOutcome {
	return writeOutcome{Status: statusPreview, Effect: effect}
}

// writeAnnotations marks a tool as a non-destructive, retry-safe write.
func writeAnnotations() *mcp.ToolAnnotations {
	f := false
	return &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &f, IdempotentHint: true, OpenWorldHint: &f}
}

const heldNext = "A person must approve this in OCIDex before it runs. Tell the user and give them approval_url. " +
	"Check later with ocidex_approval_status; do not send the request again."

// outcomeFor turns a client write result into the tool's answer.
func outcomeFor(server string, res client.WriteResult, doneEffect string) writeOutcome {
	if res.Held != nil {
		return writeOutcome{
			Status:      "held",
			Effect:      res.Held.Effect,
			ApprovalID:  res.Held.Id.String(),
			ApprovalURL: strings.TrimRight(server, "/") + "/approvals/" + res.Held.Id.String(),
			Next:        heldNext,
		}
	}
	return writeOutcome{Status: "done", Effect: doneEffect}
}

type watchInput struct {
	ArtifactID string `json:"artifact_id" jsonschema:"UUID of the artifact, from ocidex_lookup_artifact or ocidex_search_artifacts"`
	Preview    bool   `json:"preview,omitempty" jsonschema:"Describe what would happen and change nothing"`
}

type scanRegistryInput struct {
	RegistryID string `json:"registry_id" jsonschema:"UUID of the registry (ocidex_cluster_coverage_gaps names the registry an image resolves to)"`
	Force      bool   `json:"force,omitempty" jsonschema:"Re-scan images already scanned. Default false: new and changed images only"`
	Reason     string `json:"reason,omitempty" jsonschema:"One sentence for the person approving: why this scan is needed"`
	Preview    bool   `json:"preview,omitempty" jsonschema:"Describe what would happen and change nothing"`
}

type ingestInput struct {
	ClusterID    string   `json:"cluster_id" jsonschema:"UUID of the cluster, from ocidex_list_clusters"`
	ImageDigests []string `json:"image_digests" jsonschema:"Digests of the running images to scan, from ocidex_cluster_coverage_gaps. Required, at most 200"`
	Reason       string   `json:"reason,omitempty" jsonschema:"One sentence for the person approving: why these images"`
	Preview      bool     `json:"preview,omitempty" jsonschema:"Describe what would happen and change nothing"`
}

type approvalInput struct {
	ApprovalID string `json:"approval_id" jsonschema:"The approval_id a write tool returned"`
}

type approvalOutput struct {
	Status       string `json:"status" jsonschema:"pending, approved, denied, expired, executed (it ran) or failed (it ran and the server refused it)"`
	Effect       string `json:"effect"`
	ResultStatus int64  `json:"result_status,omitempty" jsonschema:"HTTP status the request returned when it ran"`
	Next         string `json:"next,omitempty"`
}

// registerWriteTools registers the write tools the key allows.
func registerWriteTools(srv *mcp.Server, api client.Client, s keySurface) {
	if !s.writes() {
		return
	}
	registerWatchTools(srv, api, s.server)
	if s.allows("trigger_scan") {
		registerScanTools(srv, api, s)
	}
	registerApprovalStatus(srv, api)
}

func registerWatchTools(srv *mcp.Server, api client.Client, server string) {
	addTool(srv, &mcp.Tool{
		Name:        "ocidex_watch_artifact",
		Description: "Add an artifact to the user's watchlist, so its new versions and findings appear in their workspace feed. Use it to track what you are remediating.",
		Annotations: writeAnnotations(),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in watchInput) (*mcp.CallToolResult, writeOutcome, error) {
		effect := "Add artifact " + in.ArtifactID + " to the user's watchlist."
		if in.Preview {
			return nil, previewOutcome(effect), nil
		}
		if c := confirmWrite(req, effect); !c.proceed() {
			return c.ask, outcomeOrZero(c.stop), nil
		}
		res, err := api.WatchArtifact(ctx, in.ArtifactID, client.WriteOpts{Tool: "ocidex_watch_artifact"})
		if err != nil {
			return nil, writeOutcome{}, toolError("watching the artifact", err)
		}
		return nil, outcomeFor(server, res, effect), nil
	})
	addTool(srv, &mcp.Tool{
		Name:        "ocidex_unwatch_artifact",
		Description: "Remove an artifact from the user's watchlist.",
		Annotations: writeAnnotations(),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in watchInput) (*mcp.CallToolResult, writeOutcome, error) {
		effect := "Remove artifact " + in.ArtifactID + " from the user's watchlist."
		if in.Preview {
			return nil, previewOutcome(effect), nil
		}
		if c := confirmWrite(req, effect); !c.proceed() {
			return c.ask, outcomeOrZero(c.stop), nil
		}
		res, err := api.UnwatchArtifact(ctx, in.ArtifactID, client.WriteOpts{Tool: "ocidex_unwatch_artifact"})
		if err != nil {
			return nil, writeOutcome{}, toolError("unwatching the artifact", err)
		}
		return nil, outcomeFor(server, res, effect), nil
	})
}

func registerScanTools(srv *mcp.Server, api client.Client, s keySurface) {
	server := s.server
	held := s.held("trigger_scan")
	heldNote := ""
	if held {
		heldNote = " With this key it is held until a person approves it; the result says how to follow up."
	}
	addTool(srv, &mcp.Tool{
		Name: "ocidex_scan_registry",
		Description: "Ask OCIDex to scan a registry: walk its repositories and queue an SBOM scan for each new or changed image, " +
			"using the registry's stored credentials. Use it when coverage gaps point at a registry." + heldNote,
		Annotations: writeAnnotations(),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in scanRegistryInput) (*mcp.CallToolResult, writeOutcome, error) {
		scope := "new and changed images only"
		if in.Force {
			scope = "every image, including ones already scanned"
		}
		effect := fmt.Sprintf("Scan registry %s: %s.", in.RegistryID, scope)
		if in.Preview {
			return nil, previewOutcome(effect), nil
		}
		if !held {
			if c := confirmWrite(req, effect); !c.proceed() {
				return c.ask, outcomeOrZero(c.stop), nil
			}
		}
		res, err := api.RequestRegistryScan(ctx, in.RegistryID, in.Force, client.WriteOpts{Tool: "ocidex_scan_registry", Reason: in.Reason})
		if err != nil {
			return nil, writeOutcome{}, toolError("requesting the registry scan", err)
		}
		return nil, outcomeFor(server, res, effect), nil
	})
	addTool(srv, &mcp.Tool{
		Name: "ocidex_ingest_unknown_images",
		Description: "Ask OCIDex to scan named images a cluster runs with no SBOM, so their findings become visible. " +
			"Take the digests from ocidex_cluster_coverage_gaps." + heldNote,
		Annotations: writeAnnotations(),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in ingestInput) (*mcp.CallToolResult, writeOutcome, error) {
		if len(in.ImageDigests) == 0 || len(in.ImageDigests) > 200 {
			return nil, writeOutcome{}, fmt.Errorf("image_digests must name between 1 and 200 images")
		}
		effect := fmt.Sprintf("Queue scans of %d running image(s) in cluster %s.", len(in.ImageDigests), in.ClusterID)
		if in.Preview {
			return nil, previewOutcome(effect), nil
		}
		if !held {
			if c := confirmWrite(req, effect); !c.proceed() {
				return c.ask, outcomeOrZero(c.stop), nil
			}
		}
		res, err := api.RequestClusterIngest(ctx, in.ClusterID, in.ImageDigests, client.WriteOpts{Tool: "ocidex_ingest_unknown_images", Reason: in.Reason})
		if err != nil {
			return nil, writeOutcome{}, toolError("requesting the scans", err)
		}
		return nil, outcomeFor(server, res, effect), nil
	})
}

func registerApprovalStatus(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name:        "ocidex_approval_status",
		Description: "Check a request a write tool reported as held: whether a person approved or denied it, and what happened when it ran.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in approvalInput) (*mcp.CallToolResult, approvalOutput, error) {
		a, err := api.GetPendingAction(ctx, in.ApprovalID)
		if err != nil {
			return nil, approvalOutput{}, toolError("checking the approval", err)
		}
		out := approvalOutput{Status: string(a.Status), Effect: a.Effect}
		if a.ResultStatus != nil {
			out.ResultStatus = *a.ResultStatus
		}
		switch out.Status {
		case "pending":
			out.Next = "Still waiting for a person. Check again later; do not resend the request."
		case "denied", "expired":
			out.Next = "It will not run. Do not resend it; tell the user."
		case statusFailed:
			out.Next = "It ran and the server refused it; result_status says why. Tell the user."
		}
		return nil, out, nil
	})
}

func outcomeOrZero(o *writeOutcome) writeOutcome {
	if o == nil {
		return writeOutcome{}
	}
	return *o
}
