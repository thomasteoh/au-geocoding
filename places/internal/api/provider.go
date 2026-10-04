package api

// DBProvider holds the serving database handle and supports an atomic swap
// (P3 — versioned dataset activation). Handlers read the current handle via
// the provider rather than capturing a fixed *sql.DB, so a swap routes new
// requests to the new pool while in-flight requests finish on the old one.
//
// INV-5: the version is read from the open handle, so a request that began on
// the old pool reports the old version even after a swap — skew is visible,
// not silent.

import (
	"database/sql"
	"sync"
	"sync/atomic"
)

// DBProvider is a concurrency-safe holder of the active *sql.DB.
type DBProvider struct {
	mu      sync.Mutex
	current atomic.Pointer[sql.DB]
	version string
}

// NewDBProvider creates a provider with an initial DB and version.
func NewDBProvider(db *sql.DB, version string) *DBProvider {
	p := &DBProvider{version: version}
	p.current.Store(db)
	return p
}

// Get returns the current active DB.
func (p *DBProvider) Get() *sql.DB {
	return p.current.Load()
}

// Version returns the dataset version of the active DB.
func (p *DBProvider) Version() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.version
}

// Swap atomically replaces the active DB with newDB and updates the version.
// The caller owns closing the old DB after in-flight requests drain.
func (p *DBProvider) Swap(newDB *sql.DB, version string) *sql.DB {
	p.mu.Lock()
	old := p.current.Swap(newDB)
	p.version = version
	p.mu.Unlock()
	return old
}
