package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/pfenerty/ocidex/internal/service"
)

// quotaConsumer is the part of QuotaService the middleware needs.
type quotaConsumer interface {
	Consume(ctx context.Context, apiKeyID, class string, limit int) (bool, int, error)
	Refund(ctx context.Context, apiKeyID, class string) error
}

// EnforceAgentQuotas counts every request an agent key makes that changes
// something against the key's hourly budgets (ADR-0058 A6), and refuses the
// request with 429 once a budget is spent. Requests that queue scan work count
// against the scan budget as well. A held request is counted when it is asked
// for, so the replay that runs it on approval is not counted again.
//
// It fails open on a database error: the budget bounds a runaway agent, and
// refusing every write during a database blip would not make anything safer.
func EnforceAgentQuotas(q quotaConsumer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if q == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := UserFromContext(r.Context())
			if !ok || user.APIKeyKind != service.KeyKindAgent || !isMutatingMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			if _, replay := r.Context().Value(executingKey{}).(string); replay {
				next.ServeHTTP(w, r)
				return
			}
			checks := []struct {
				class string
				limit int
			}{{service.QuotaWrites, user.APIKeyWritesPerHour}}
			if scanRegistryPath.MatchString(r.URL.Path) || ingestUnknownPath.MatchString(r.URL.Path) {
				checks = append(checks, struct {
					class string
					limit int
				}{service.QuotaScans, user.APIKeyScansPerHour})
			}
			var counted []string
			refund := func() {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Second)
				defer cancel()
				for _, class := range counted {
					if err := q.Refund(ctx, user.APIKeyID, class); err != nil {
						slog.WarnContext(r.Context(), "refunding agent quota", "error", err)
					}
				}
			}
			for _, c := range checks {
				allowed, used, err := q.Consume(r.Context(), user.APIKeyID, c.class, c.limit)
				if err != nil {
					slog.WarnContext(r.Context(), "agent quota check failed; allowing", "error", err)
					continue
				}
				counted = append(counted, c.class)
				if !allowed {
					refund() // the refused request does nothing, including this count
					retry := time.Until(time.Now().Truncate(time.Hour).Add(time.Hour))
					w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
					writeProblem(w, http.StatusTooManyRequests, fmt.Sprintf(
						"this agent key has used its %s budget for the hour (%d of %d); wait for the next hour, or ask its owner to raise the budget",
						c.class, used-1, c.limit))
					return
				}
			}
			// A request the API refuses (validation, permission, conflict) did
			// nothing, so its count is given back.
			sw := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(sw, r)
			if sw.status >= 400 {
				refund()
			}
		})
	}
}
