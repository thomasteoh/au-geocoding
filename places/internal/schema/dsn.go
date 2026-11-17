package schema

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
)

// ReadOnlyDSN is the DSN the server opens a serving dataset with. Every
// setting rides on the DSN rather than a one-off db.Exec: database/sql pools
// connections, and a PRAGMA run through db.Exec reaches only the one pooled
// connection that happened to execute it. The driver applies DSN parameters to
// each new connection, so every reader is read-only (INV-4).
//
// mode=ro makes SQLite refuse writes at the file level; _query_only adds the
// statement-level guard. The path is percent-escaped so a '?' or '#' in a file
// name cannot be read as the start of the URI query.
func ReadOnlyDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() +
		"?mode=ro&_query_only=1&_busy_timeout=5000"
}

// WriterDSN is the DSN a loader opens its target with. busy_timeout makes a
// loader wait out a reader's transient lock instead of failing with
// SQLITE_BUSY halfway through a build. Journal mode is left as the file has
// it: switching the serving file to WAL would make a mode=ro open need write
// access to the -shm file, which the server's read-only mount does not have.
func WriterDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?_busy_timeout=30000"
}

// OpenWriter opens path for a loader. It refuses a file that a server is
// serving (see LockServing) and holds an exclusive lock for the life of the
// returned release func, so a server cannot activate the file mid-build
// either. Call release after db.Close.
func OpenWriter(path string) (db *sql.DB, release func(), err error) {
	release, err = lockFile(path, true)
	if err != nil {
		return nil, nil, err
	}
	db, err = sql.Open("sqlite", WriterDSN(path))
	if err != nil {
		release()
		return nil, nil, err
	}
	return db, release, nil
}

// CheckNotServed reports an error if a server holds path open. It does not
// keep a lock: oscchain uses it before handing the file to a child loader
// process, which takes its own exclusive lock.
func CheckNotServed(path string) error {
	release, err := lockFile(path, true)
	if err != nil {
		return err
	}
	release()
	return nil
}

// LockServing takes a shared lock on a dataset the server is about to serve.
// Loaders take the exclusive lock (OpenWriter), so while any server holds the
// file no loader can open it for writing, and a file a loader is still
// building cannot be served. The lock is advisory (flock) and independent of
// SQLite's own byte-range locks. It works on a read-only mount: flock needs
// only a read descriptor.
func LockServing(path string) (release func(), err error) {
	return lockFile(path, false)
}

// errLocked is wrapped by lockFile when the other side holds the lock.
var errLocked = fmt.Errorf("dataset is locked by another process")

// lockFile opens path (creating it only for a writer: a loader may be the
// first to touch a new staging file) and takes the advisory lock.
func lockFile(path string, exclusive bool) (func(), error) {
	flags := os.O_RDONLY
	if exclusive {
		flags = os.O_RDWR | os.O_CREATE
	}
	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return nil, err
	}
	if err := flock(f, exclusive); err != nil {
		f.Close()
		if exclusive {
			return nil, fmt.Errorf("%s is being served or written by another process; build into a staging file and activate it instead: %w", path, err)
		}
		return nil, fmt.Errorf("%s is being written by a loader: %w", path, err)
	}
	return func() { f.Close() }, nil
}
