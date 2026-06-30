package service

import (
	"sync"
	"time"
)

// statsCacheTTL is how long a computed dashboard-stats payload is reused before
// recomputation. The dashboard aggregates scan the whole component table, so
// recomputing on every load does not scale; stats tolerate slight staleness.
const statsCacheTTL = 60 * time.Second

type statsCacheEntry struct {
	stats     *DashboardStats
	expiresAt time.Time
}

// statsCache is a small TTL cache for dashboard stats, keyed by visibility
// scope (different viewers see different data). Safe for concurrent use.
type statsCache struct {
	mu    sync.Mutex
	ttl   time.Duration
	now   func() time.Time
	items map[string]statsCacheEntry
}

func newStatsCache(ttl time.Duration) *statsCache {
	return &statsCache{
		ttl:   ttl,
		now:   time.Now,
		items: make(map[string]statsCacheEntry),
	}
}

// statsCacheKey collapses a VisibilityFilter to the distinct data scopes:
// admins share the full dataset, each authenticated user has their own scope
// (public + owned), and anonymous viewers share the public scope.
func statsCacheKey(vis VisibilityFilter) string {
	switch {
	case vis.IsAdmin:
		return "admin"
	case vis.UserID.Valid:
		return "u:" + uuidToString(vis.UserID)
	default:
		return "anon"
	}
}

// get returns a non-expired cached payload, or nil on miss.
func (c *statsCache) get(key string) *DashboardStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.items[key]
	if !ok || c.now().After(entry.expiresAt) {
		return nil
	}
	return entry.stats
}

func (c *statsCache) set(key string, stats *DashboardStats) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = statsCacheEntry{stats: stats, expiresAt: c.now().Add(c.ttl)}
}
