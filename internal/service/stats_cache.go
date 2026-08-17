package service

import (
	"sync"
	"time"
)

// statsCacheTTL is how long a computed dashboard-stats payload is reused before
// recomputation. The dashboard aggregates scan the whole component table, so
// recomputing on every load does not scale; stats tolerate staleness.
//
// StatsWarmInterval must stay comfortably below this: the warmer is what keeps
// entries fresh, and if an entry could lapse between two warms, a dashboard
// load would land on the slow path the warmer exists to avoid.
const (
	statsCacheTTL = 15 * time.Minute

	// StatsWarmInterval is how often the background warmer recomputes stats.
	StatsWarmInterval = 5 * time.Minute
)

type ttlCacheEntry[T any] struct {
	value     *T
	expiresAt time.Time
}

// ttlCache is a small TTL cache for an out-of-band computed payload, keyed by
// whatever scope distinguishes one payload from another. Safe for concurrent
// use.
type ttlCache[T any] struct {
	mu    sync.Mutex
	ttl   time.Duration
	now   func() time.Time
	items map[string]ttlCacheEntry[T]
}

func newTTLCache[T any](ttl time.Duration) *ttlCache[T] {
	return &ttlCache[T]{
		ttl:   ttl,
		now:   time.Now,
		items: make(map[string]ttlCacheEntry[T]),
	}
}

// newStatsCache is the dashboard-stats instantiation: keyed by visibility
// scope, because different viewers see different data.
func newStatsCache(ttl time.Duration) *ttlCache[DashboardStats] {
	return newTTLCache[DashboardStats](ttl)
}

// statsCacheKey collapses a VisibilityFilter to the distinct data scopes:
// admins share the full dataset, each authenticated user has their own scope
// (public + owned), and anonymous viewers share the public scope.
//
// Callers on the request path should key on the *normalized* filter from
// searchService.normalizeStatsScope rather than the raw one — a viewer who owns
// no private registry sees the same data as an anonymous viewer, and giving
// them their own key would mint a scope the warmer never fills.
func statsCacheKey(vis VisibilityFilter) string {
	switch {
	case vis.IsAdmin:
		return roleAdmin
	case vis.UserID.Valid:
		return "u:" + uuidToString(vis.UserID)
	default:
		return "anon"
	}
}

// get returns a non-expired cached payload, or nil on miss.
func (c *ttlCache[T]) get(key string) *T {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.items[key]
	if !ok || c.now().After(entry.expiresAt) {
		return nil
	}
	return entry.value
}

func (c *ttlCache[T]) set(key string, value *T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = ttlCacheEntry[T]{value: value, expiresAt: c.now().Add(c.ttl)}
}
