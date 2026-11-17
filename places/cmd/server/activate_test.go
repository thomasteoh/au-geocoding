package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"auplaces/internal/schema"
)

// dataset writes a minimal serving DB at path with the given version.
func dataset(t *testing.T, path, version string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range []string{schema.SchemaSQL,
		`INSERT INTO address (gnaf_pid, street_name, locality_name, state, latitude, longitude, confidence, geocode_rel, dataset_version)
			VALUES ('GAVIC1', 'COLLINS', 'MELBOURNE', 'VIC', -37.8, 144.9, 2, 6, '` + version + `')`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
}

func writeReport(t *testing.T, path string, ok bool, sum string) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"ok": ok, "sha256": sum})
	if err := os.WriteFile(path+".verify.json", b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveDatasetStaysInDataDir(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	os.Mkdir(data, 0o755)
	os.WriteFile(filepath.Join(data, "vic.db"), nil, 0o644)
	os.WriteFile(filepath.Join(data, "vic.db.new"), nil, 0o644)
	os.WriteFile(filepath.Join(root, "secret.db"), nil, 0o644)
	os.Symlink(filepath.Join(root, "secret.db"), filepath.Join(data, "escape.db"))
	os.Symlink(filepath.Join(data, "vic.db.new"), filepath.Join(data, "current.db"))
	os.Mkdir(filepath.Join(data, "sub"), 0o755)

	dir, err := realDataDir(filepath.Join(data, "vic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	allowed := map[string]string{
		"data/vic.db.new":                 filepath.Join(dir, "vic.db.new"),
		filepath.Join(data, "vic.db.new"): filepath.Join(dir, "vic.db.new"),
		"data/current.db":                 filepath.Join(dir, "vic.db.new"),
		"data/sub/../vic.db.new":          filepath.Join(dir, "vic.db.new"),
	}
	for req, want := range allowed {
		got, err := resolveDataset(dir, req)
		if err != nil || got != want {
			t.Errorf("%s: got %q, %v; want %q", req, got, err, want)
		}
	}
	for _, req := range []string{"", "secret.db", "data/../secret.db", "data/escape.db", "data/sub", "data", "data/missing.db", "/etc/passwd"} {
		if got, err := resolveDataset(dir, req); err == nil {
			t.Errorf("%s: allowed as %q", req, got)
		}
	}
}

func TestCheckVerifiedNeedsAPassingReportForThisFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vic.db.new")
	dataset(t, path, "v2")
	if err := checkVerified(path, path); err == nil {
		t.Error("activated without a verify report")
	}
	sum, err := sha256File(path)
	if err != nil {
		t.Fatal(err)
	}
	writeReport(t, path, false, sum)
	if err := checkVerified(path, path); err == nil {
		t.Error("activated with a failing report")
	}
	writeReport(t, path, true, "00"+sum[2:])
	if err := checkVerified(path, path); err == nil {
		t.Error("activated a file that changed since verify")
	}
	writeReport(t, path, true, sum)
	if err := checkVerified(path, path); err != nil {
		t.Errorf("passing report refused: %v", err)
	}
}

// Every pooled connection must refuse writes, not just the one a PRAGMA
// happened to run on, and the version must come from the dataset.
func TestOpenServingIsReadOnlyOnEveryConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vic.db")
	dataset(t, path, "gnaf-2026-08")
	ctx := context.Background()
	db, version, n, release, err := openServing(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	defer db.Close()
	if version != "gnaf-2026-08" || n != 1 {
		t.Errorf("version %q, addresses %d", version, n)
	}
	// Hold several connections at once so the pool must open new ones.
	var conns []*sql.Conn
	for i := 0; i < 4; i++ {
		c, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	for i, c := range conns {
		if _, err := c.ExecContext(ctx, `DELETE FROM address`); err == nil {
			t.Errorf("connection %d accepted a write", i)
		}
		c.Close()
	}
	// While served, a loader is refused.
	if _, _, err := schema.OpenWriter(path); err == nil {
		t.Error("loader opened a served dataset for writing")
	}
}
