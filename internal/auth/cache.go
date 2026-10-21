package auth

import (
	"crypto/sha256"
	"sync"
	"time"
)

// cacheKey never contains the plaintext token.
type cacheKey struct {
	tokenHash [sha256.Size]byte
	audience  string
	cluster   string
}

func newCacheKey(token, audience, cluster string) cacheKey {
	return cacheKey{tokenHash: sha256.Sum256([]byte(token)), audience: audience, cluster: cluster}
}

// singleflightKey is the string form of the cache key for singleflight.Group.
func (k cacheKey) singleflightKey() string {
	return string(k.tokenHash[:]) + "\x00" + k.audience + "\x00" + k.cluster
}

type cacheEntry struct {
	identity  Identity
	expiresAt time.Time
}

// authCache holds successful authentication results only. It is unrelated to
// authorization decisions, which are never cached.
type authCache struct {
	mu         sync.RWMutex
	entries    map[cacheKey]cacheEntry
	maxEntries int
	now        func() time.Time
}

func newAuthCache(maxEntries int, now func() time.Time) *authCache {
	return &authCache{entries: make(map[cacheKey]cacheEntry), maxEntries: maxEntries, now: now}
}

// get returns an entry only if it has not expired.
func (c *authCache) get(k cacheKey) (cacheEntry, bool) {
	c.mu.RLock()
	e, ok := c.entries[k]
	c.mu.RUnlock()
	if !ok {
		return cacheEntry{}, false
	}
	if !c.now().Before(e.expiresAt) {
		c.mu.Lock()
		if cur, ok := c.entries[k]; ok && !c.now().Before(cur.expiresAt) {
			delete(c.entries, k)
		}
		c.mu.Unlock()
		return cacheEntry{}, false
	}
	return e, true
}

func (c *authCache) set(k cacheKey, e cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxEntries {
		now := c.now()
		for key, v := range c.entries {
			if !now.Before(v.expiresAt) {
				delete(c.entries, key)
			}
		}
		// Still full: drop arbitrary entries. Worst case is an extra TokenReview.
		for key := range c.entries {
			if len(c.entries) < c.maxEntries {
				break
			}
			delete(c.entries, key)
		}
	}
	c.entries[k] = e
}
