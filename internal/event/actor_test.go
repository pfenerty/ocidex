package event_test

import (
	"context"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/event"
)

type ctxCapture struct{ ctx context.Context }

func (c *ctxCapture) Publish(ctx context.Context, _ event.Type, _ any) { c.ctx = ctx }

func TestActorRoundTrip(t *testing.T) {
	is := is.New(t)
	_, ok := event.ActorFromContext(context.Background())
	is.True(!ok)

	want := event.Actor{Kind: event.ActorUser, ID: "u1", APIKeyID: "k1"}
	got, ok := event.ActorFromContext(event.WithActor(context.Background(), want))
	is.True(ok)
	is.Equal(got, want)
}

func TestWithDefaultActor(t *testing.T) {
	sys := event.SystemActor("scanner-worker")
	user := event.Actor{Kind: event.ActorUser, ID: "u1"}

	tests := []struct {
		name string
		ctx  context.Context
		want event.Actor
	}{
		{"fills in a missing actor", context.Background(), sys},
		{"keeps the caller's actor", event.WithActor(context.Background(), user), user},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			c := &ctxCapture{}
			event.WithDefaultActor(c, sys).Publish(tt.ctx, event.SBOMIngested, nil)
			got, ok := event.ActorFromContext(c.ctx)
			is.True(ok)
			is.Equal(got, tt.want)
		})
	}
}
