package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"auplaces/internal/schema"
)

// errNotAllowed is returned for any dataset path outside the data directory.
var errNotAllowed = errors.New("db path not allowed")

// resolveDataset turns a requested dataset path into the one real file the
// server will open. The symlinks are resolved here, once, and the result is
// what gets validated and opened: validating one spelling of a path and then
// opening another (relative to a different base, or through a symlink swapped
// in between) is how a traversal check gets bypassed.
//
// A relative path is relative to the server's working directory, as the
// activate tool sends it. dataDir must already be a resolved real path.
func resolveDataset(dataDir, requested string) (string, error) {
	if requested == "" {
		return "", errNotAllowed
	}
	abs, err := filepath.Abs(requested)
	if err != nil {
		return "", errNotAllowed
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", errNotAllowed
	}
	rel, err := filepath.Rel(dataDir, real)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errNotAllowed
	}
	fi, err := os.Stat(real)
	if err != nil || !fi.Mode().IsRegular() {
		return "", errNotAllowed
	}
	return real, nil
}

// realDataDir is the resolved directory holding the boot dataset: the only
// directory activation may serve from.
func realDataDir(bootDB string) (string, error) {
	abs, err := filepath.Abs(bootDB)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	return filepath.Dir(real), nil
}

// verifyReport is the part of cmd/verify's <db>.verify.json activation reads.
type verifyReport struct {
	OK     bool   `json:"ok"`
	SHA256 string `json:"sha256"`
}

// checkVerified requires a passing verify report for exactly this file
// (P1 stage 5 gates every swap). The report sits beside the dataset; it is
// looked for beside the requested spelling too, since verify records the path
// it was given. The checksum ties the report to the bytes being activated, so
// a file rebuilt after it was verified does not ride on the old report.
func checkVerified(real, requested string) error {
	var rep verifyReport
	var raw []byte
	var err error
	for _, p := range []string{real + ".verify.json", requested + ".verify.json"} {
		if raw, err = os.ReadFile(p); err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("no verify report: %w", err)
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		return fmt.Errorf("verify report: %w", err)
	}
	if !rep.OK {
		return errors.New("verify report says the dataset failed")
	}
	sum, err := sha256File(real)
	if err != nil {
		return err
	}
	if !strings.EqualFold(sum, rep.SHA256) {
		return errors.New("dataset changed since it was verified")
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// openServing opens a dataset for serving: locked against loaders, read-only
// on every pooled connection, and with its address table and version read.
// The caller owns release, to be called after db.Close.
func openServing(ctx context.Context, path string) (db *sql.DB, version string, addresses int, release func(), err error) {
	release, err = schema.LockServing(path)
	if err != nil {
		return nil, "", 0, nil, err
	}
	fail := func(e error) (*sql.DB, string, int, func(), error) {
		if db != nil {
			db.Close()
		}
		release()
		return nil, "", 0, nil, e
	}
	db, err = sql.Open("sqlite", schema.ReadOnlyDSN(path))
	if err != nil {
		return fail(err)
	}
	// A read-only pool: query_only rides on the DSN, so every connection the
	// pool opens is read-only, not just the first.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM address`).Scan(&addresses); err != nil {
		return fail(fmt.Errorf("address table: %w", err))
	}
	// The version is the dataset's own (written by buildaddr), so what the
	// server reports cannot drift from what the handlers stamp on responses.
	if err := db.QueryRowContext(ctx, `SELECT dataset_version FROM address LIMIT 1`).Scan(&version); err != nil && err != sql.ErrNoRows {
		return fail(fmt.Errorf("dataset version: %w", err))
	}
	return db, version, addresses, release, nil
}
