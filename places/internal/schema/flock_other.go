//go:build !unix

package schema

import "os"

// flock is a no-op where advisory file locks are unavailable; the guard is
// best-effort there and the staging-file workflow is the protection.
func flock(f *os.File, exclusive bool) error { return nil }
