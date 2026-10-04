// Package appdb opens app.db, the geocoder's mutable service state (keys,
// usage, identity). One *sql.DB is shared by every store in the process so
// SQLite sees a single writer pool.
package appdb

import (
	"database/sql"
	"strings"

	_ "modernc.org/sqlite"
)

// Open opens (creating if needed) the SQLite file at path with WAL, a busy
// timeout and foreign keys on.
func Open(path string) (*sql.DB, error) {
	dsn := path
	if !strings.HasPrefix(dsn, "file:") {
		dsn = "file:" + dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	dsn += sep + "_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
