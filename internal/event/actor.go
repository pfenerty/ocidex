package event

import "context"

// ActorKind says what sort of principal caused an event.
type ActorKind string

const (
	// ActorUser is a signed-in user, by session or by one of their API keys.
	ActorUser ActorKind = "user"
	// ActorSystem is an OCIDex component acting on its own, such as the
	// scanner worker or the retention sweep.
	ActorSystem ActorKind = "system"
	// ActorAnonymous is a request that carried no valid credentials.
	ActorAnonymous ActorKind = "anonymous"
)

// Actor is who caused an event: the principal the audit log records
// . It travels on the context rather than on each event's data:
// Bus.Publish is synchronous, so a subscriber sees the publisher's ctx, and
// the actor is known where the request is authenticated, far from where
// events are published.
type Actor struct {
	Kind ActorKind
	// ID is the user's ID for ActorUser and the component's name for
	// ActorSystem. Empty for ActorAnonymous.
	ID string
	// APIKeyID is set when a user acted through an API key rather than a
	// session, so a leaked key's actions can be told apart.
	APIKeyID string
}

// SystemActor is the actor for an OCIDex component acting on its own.
func SystemActor(component string) Actor {
	return Actor{Kind: ActorSystem, ID: component}
}

type actorKey struct{}

// WithActor returns ctx carrying a as the actor of events published under it.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

// ActorFromContext returns the actor ctx carries, if any.
func ActorFromContext(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorKey{}).(Actor)
	return a, ok
}

// WithDefaultActor wraps p so an event published under a ctx that carries no
// actor is attributed to a. A background component (the scanner worker, the
// retention sweep) hands its services this in place of the bus, so its events
// name it without threading an actor through every call path.
func WithDefaultActor(p Publisher, a Actor) Publisher {
	return defaultActorPublisher{next: p, actor: a}
}

type defaultActorPublisher struct {
	next  Publisher
	actor Actor
}

func (d defaultActorPublisher) Publish(ctx context.Context, t Type, data any) {
	if _, ok := ActorFromContext(ctx); !ok {
		ctx = WithActor(ctx, d.actor)
	}
	d.next.Publish(ctx, t, data)
}
