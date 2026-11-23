package main

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Confirmation through MCP elicitation (ADR-0058 A8).
//
// A write that will run at once is first put to the user, through the client,
// when the client says it can ask. The model cannot answer an elicitation, so
// this is consent it cannot forge, and no tool takes a "confirm" argument:
// anything the model sets is not the user's word. A write the server will hold
// skips this, because a person approves it in OCIDex, which is the stronger
// check. A client that cannot ask gets the write without a prompt, bounded by
// the key's capabilities, namespaces and budgets.
//
// The question goes out as a multi-round-trip input request: the tool returns
// it, the client asks the user and calls the tool again with the answer. The
// SDK does the same dance itself for clients on older protocol versions.

const (
	statusDeclined  = "declined"
	statusCancelled = "cancelled"

	confirmInput = "confirm"
)

// confirmation is what confirmWrite decided.
type confirmation struct {
	// ask, when set, is the result to return: the question for the user.
	ask *mcp.CallToolResult
	// stop, when set, is the outcome to return: the user said no.
	stop *writeOutcome
}

// proceed reports whether the write may be sent.
func (c confirmation) proceed() bool { return c.ask == nil && c.stop == nil }

// confirmWrite asks the user to allow effect, or reads their answer on the
// call that carries it.
func confirmWrite(req *mcp.CallToolRequest, effect string) confirmation {
	if !canElicit(req) {
		return confirmation{}
	}
	// The answer counts only for the change it was given for: the state binds
	// it to this effect, so a reply carried over to a different request asks
	// again rather than allowing it.
	state := effectState(effect)
	if resp, ok := req.Params.InputResponses[confirmInput].(*mcp.ElicitResult); ok && req.Params.RequestState == state {
		switch resp.Action {
		case "accept":
			return confirmation{}
		case "decline":
			return confirmation{stop: &writeOutcome{Status: statusDeclined, Effect: effect,
				Next: "The user declined. Do not retry; ask them what they want instead."}}
		default:
			return confirmation{stop: &writeOutcome{Status: statusCancelled, Effect: effect,
				Next: "The user dismissed the confirmation. Nothing changed; do not retry unless they ask."}}
		}
	}
	return confirmation{ask: &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{
			confirmInput: &mcp.ElicitParams{
				Message:         "An agent wants to make a change in OCIDex:\n\n" + effect + "\n\nAllow it?",
				RequestedSchema: map[string]any{"type": "object", "properties": map[string]any{}},
			},
		},
		RequestState: state,
	}}
}

func effectState(effect string) string {
	sum := sha256.Sum256([]byte(effect))
	return "confirm:" + hex.EncodeToString(sum[:16])
}

// canElicit reports whether the connected client declared elicitation.
func canElicit(req *mcp.CallToolRequest) bool {
	if req == nil || req.Session == nil {
		return false
	}
	p := req.Session.InitializeParams()
	return p != nil && p.Capabilities != nil && p.Capabilities.Elicitation != nil
}
