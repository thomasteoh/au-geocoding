package publicapi

import (
	"sync"
	"time"
)

// MaxAnonIPs caps how many distinct anonymous IPs (or IPv6 /64s) are tracked
// per day. When the table is full a new IP is refused (fail closed):
// anonymous access is best effort, and a caller rotating source addresses
// must neither grow memory nor reset its own counter by forcing evictions.
const MaxAnonIPs = 100000

// anonCounter is a per-day, per-IP counter with a running global total, so
// a charge is O(1) rather than a sum over every IP seen today.
type anonCounter struct {
	mu    sync.Mutex
	day   string
	byIP  map[string]int64
	total int64
	max   int
	now   func() time.Time
}

func newAnonCounter(max int) *anonCounter {
	return &anonCounter{byIP: make(map[string]int64), max: max, now: time.Now}
}

// roll resets the counter at UTC midnight. Caller holds mu.
func (c *anonCounter) roll() {
	day := c.now().UTC().Format("2006-01-02")
	if c.day != day {
		c.day = day
		c.byIP = make(map[string]int64)
		c.total = 0
	}
}

// charge adds n for ip when that keeps ip within perIP and the total within
// global (0 = no global ceiling). n == 0 is a no-op that inserts nothing.
func (c *anonCounter) charge(ip string, n, perIP, global int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.roll()
	cur, seen := c.byIP[ip]
	if cur+n > perIP {
		return false
	}
	if global > 0 && c.total+n > global {
		return false
	}
	if n == 0 {
		return true
	}
	if !seen && c.max > 0 && len(c.byIP) >= c.max {
		return false
	}
	c.byIP[ip] = cur + n
	c.total += n
	return true
}

// atCeiling reports whether ip (or the global total) has no headroom left.
func (c *anonCounter) atCeiling(ip string, perIP, global int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.roll()
	cur, seen := c.byIP[ip]
	if cur >= perIP {
		return true
	}
	if global > 0 && c.total >= global {
		return true
	}
	return !seen && c.max > 0 && len(c.byIP) >= c.max
}

// len reports how many IPs are tracked today.
func (c *anonCounter) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.byIP)
}

// ChargeAnonDaily accounts for anonymous result rows consumed today, per IP
// (D-026: per-IP quota plus a global ceiling). In memory only — resets on
// restart and is per-replica; the global ceiling bounds the worst case.
// Returns false when the IP's daily ceiling or the global ceiling would be
// exceeded, or the IP table is full. perIP <= 0 means no anonymous ceiling.
func (s *Store) ChargeAnonDaily(ip string, rows int64, perIP, global int64) (bool, error) {
	if perIP <= 0 {
		return true, nil
	}
	if !s.anonRows.charge(ip, rows, perIP, global) {
		return false, ErrQuotaExceeded
	}
	return true, nil
}

// AnonAtCeiling is the pre-flight check: true when ip cannot be charged
// another row today, so the request is refused before any work.
func (s *Store) AnonAtCeiling(ip string, perIP, global int64) bool {
	if perIP <= 0 {
		return false
	}
	return s.anonRows.atCeiling(ip, perIP, global)
}

// ChargeAnonLLM counts one anonymous LLM-rung call for ip against the
// per-IP and global daily caps. perIP <= 0 or global <= 0 turns anonymous
// LLM access off (fail closed): the LLM is the only rung that costs money.
func (s *Store) ChargeAnonLLM(ip string, perIP, global int64) bool {
	if perIP <= 0 || global <= 0 {
		return false
	}
	return s.anonLLM.charge(ip, 1, perIP, global)
}
