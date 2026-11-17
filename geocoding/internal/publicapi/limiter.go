package publicapi

import (
	"container/list"
	"sync"
	"time"
)

// tokenBucket is a per-key token bucket (D-006). Tokens refill continuously;
// a burst up to the bucket size is allowed, then the steady rate.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

// newTokenBucket creates a bucket with the given per-second rate and burst.
func newTokenBucket(rate, burst float64) *tokenBucket {
	return &tokenBucket{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

// Allow consumes one token. Returns false when the bucket is empty.
func (b *tokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.tokens = min(b.tokens+elapsed*b.rate, b.burst)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type lruEntry struct {
	key    string
	bucket *tokenBucket
}

// RateLimiter holds per-key token buckets in an LRU of at most maxKeys
// entries. Lookup, touch and eviction are all O(1) (map + container/list),
// so a flood of unique keys at capacity costs the same per request as one
// key. The limiter lock covers only the map/list update; the bucket has its
// own lock.
type RateLimiter struct {
	mu      sync.Mutex
	keys    map[string]*list.Element
	lru     *list.List // front = most recently used
	rate    float64
	burst   float64
	maxKeys int
}

// DefaultMaxKeys bounds the per-limiter bucket count.
const DefaultMaxKeys = 100000

// NewRateLimiter creates a limiter with per-key buckets at rate/s and burst.
func NewRateLimiter(rate, burst float64) *RateLimiter {
	return &RateLimiter{
		keys:    make(map[string]*list.Element),
		lru:     list.New(),
		rate:    rate,
		burst:   burst,
		maxKeys: DefaultMaxKeys,
	}
}

// Allow consumes one token for the key (or IP for anonymous). When the map
// is at maxKeys the least-recently-used bucket is evicted in O(1).
func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	var b *tokenBucket
	if el, ok := r.keys[key]; ok {
		r.lru.MoveToFront(el)
		b = el.Value.(*lruEntry).bucket
	} else {
		if r.maxKeys > 0 && len(r.keys) >= r.maxKeys {
			if old := r.lru.Back(); old != nil {
				r.lru.Remove(old)
				delete(r.keys, old.Value.(*lruEntry).key)
			}
		}
		b = newTokenBucket(r.rate, r.burst)
		r.keys[key] = r.lru.PushFront(&lruEntry{key: key, bucket: b})
	}
	r.mu.Unlock()
	return b.Allow()
}

// Len reports how many buckets are held.
func (r *RateLimiter) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.keys)
}
