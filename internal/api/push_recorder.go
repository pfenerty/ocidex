package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/pfenerty/ocidex/internal/service"
)

// pushRecorder is the slice of ClusterService the push recorder needs.
type pushRecorder interface {
	RecordPush(ctx context.Context, clusterID string, p service.PushAttempt) error
}

var inventoryPath = regexp.MustCompile(`^/api/v1/clusters/([0-9a-fA-F-]{36})/inventory$`)

// pushNote is how authentication tells the recorder about the caller. A
// refused cluster-bound credential is named, because that refusal happens
// before any route runs and the cluster the credential belongs to is the one
// that needs to hear about it. authenticated says whether any credential
// resolved to a key or session: a rejection without one could come from
// anyone who knows the cluster id.
type pushNote struct {
	boundClusterID string
	authenticated  bool
}

type ctxKeyPushNote struct{}

func notePushFromContext(ctx context.Context) *pushNote {
	n, _ := ctx.Value(ctxKeyPushNote{}).(*pushNote)
	return n
}

// maxRecordedBody bounds how much of an error response is kept for its detail.
const maxRecordedBody = 4096

// RecordInventoryPushes records every rejected inventory push against the
// cluster it was meant for, so a misconfigured agent shows up
// as "erroring: <why>" rather than as a cluster that merely went quiet.
//
// It sits outside authentication on purpose: a revoked key, a wrong cluster
// and a schema failure are all refused before the handler, and those are the
// failures an operator most needs explained. Accepted pushes are recorded by
// the handler, which knows the workload count. Recording is capped per
// cluster, and a run of identical unauthenticated rejections is kept as one
// row, so an anonymous caller can neither grow the history nor push genuine
// attempts out of it.
func RecordInventoryPushes(rec pushRecorder) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if rec == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m := inventoryPath.FindStringSubmatch(r.URL.Path)
			if r.Method != http.MethodPost || m == nil {
				next.ServeHTTP(w, r)
				return
			}
			note := &pushNote{}
			cw := &captureWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(cw, r.WithContext(context.WithValue(r.Context(), ctxKeyPushNote{}, note)))
			if cw.status < 400 {
				return
			}

			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Second)
			defer cancel()
			target := strings.ToLower(m[1])
			reason := pushRejectionReason(cw.status, cw.body.Bytes())
			record := func(clusterID, why string) {
				attempt := service.PushAttempt{Status: cw.status, Reason: why, Unauthenticated: !note.authenticated}
				if err := rec.RecordPush(ctx, clusterID, attempt); err != nil {
					slog.WarnContext(ctx, "recording rejected push", "cluster_id", clusterID, "err", err)
				}
			}
			if bound := strings.ToLower(note.boundClusterID); bound != "" && bound != target {
				record(bound, fmt.Sprintf("This cluster's agent credential was used to push to a different cluster (%s). Check the agent's cluster.id.", target))
				record(target, "Pushed with an agent credential that belongs to a different cluster.")
				return
			}
			record(target, reason)
		})
	}
}

// pushRejectionReason says why a push was refused in terms an operator can
// act on, keeping the server's own detail where it has one.
func pushRejectionReason(status int, body []byte) string {
	detail := problemDetail(body)
	switch {
	case status == http.StatusUnauthorized:
		return "The agent's API key was not accepted: it was revoked, rotated or mistyped."
	case status == http.StatusForbidden:
		return "The agent's key may not push here: " + detail
	case status == http.StatusRequestEntityTooLarge:
		return "The snapshot was larger than the server accepts."
	case status == http.StatusUnprocessableEntity || status == http.StatusBadRequest:
		return "The snapshot failed validation: " + detail
	case status >= 500:
		return fmt.Sprintf("The server failed to store the snapshot (HTTP %d).", status)
	default:
		return fmt.Sprintf("Push refused (HTTP %d): %s", status, detail)
	}
}

// problemDetail pulls the human part out of a huma error body: its detail and
// the first few field errors, which is where a validation failure says what.
func problemDetail(body []byte) string {
	var p struct {
		Detail string `json:"detail"`
		Errors []struct {
			Message  string `json:"message"`
			Location string `json:"location"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return strings.TrimSpace(string(body))
	}
	parts := []string{p.Detail}
	for i, e := range p.Errors {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("and %d more", len(p.Errors)-3))
			break
		}
		parts = append(parts, strings.TrimSpace(e.Location+" "+e.Message))
	}
	out := strings.Join(parts, "; ")
	if len(out) > 500 {
		out = out[:500] + "…"
	}
	return out
}

// captureWriter keeps the status and the first bytes of the body.
type captureWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	body        bytes.Buffer
}

func (c *captureWriter) WriteHeader(code int) {
	if !c.wroteHeader {
		c.status, c.wroteHeader = code, true
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *captureWriter) Write(b []byte) (int, error) {
	if !c.wroteHeader {
		c.WriteHeader(http.StatusOK)
	}
	if room := maxRecordedBody - c.body.Len(); room > 0 {
		c.body.Write(b[:min(room, len(b))])
	}
	return c.ResponseWriter.Write(b)
}

func (c *captureWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }
