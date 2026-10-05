package config

import (
	"os"
	"strings"
	"testing"
)

func TestSMTPConfig(t *testing.T) {
	t.Setenv("AUGEO_SMTP_HOST", "smtp.example.com")
	t.Setenv("AUGEO_SMTP_USERNAME", "geo")
	t.Setenv("AUGEO_SMTP_PASSWORD", "hunter2")
	t.Setenv("AUGEO_SMTP_FROM", "Geocoder <noreply@geo.example>")
	cfg, err := Load(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SMTP.Port != 587 || cfg.SMTP.Password != "hunter2" {
		t.Fatalf("%+v", cfg.SMTP)
	}
	if r := cfg.Redacted(); r.SMTP.Password != "REDACTED" || cfg.SMTP.Password != "hunter2" {
		t.Fatal("password not redacted (or original modified)")
	}

	t.Setenv("AUGEO_SMTP_FROM", "")
	if _, err := Load(nil, ""); err == nil || !strings.Contains(err.Error(), "AUGEO_SMTP_FROM") {
		t.Fatalf("missing from: %v", err)
	}
	t.Setenv("AUGEO_SMTP_FROM", "a@b.example\r\nBcc: x@y.example")
	if _, err := Load(nil, ""); err == nil {
		t.Fatal("accepted CRLF in from")
	}
	t.Setenv("AUGEO_SMTP_FROM", "a@b.example")
	t.Setenv("AUGEO_SMTP_PORT", "0")
	if _, err := Load(nil, ""); err == nil {
		t.Fatal("accepted port 0")
	}
	t.Setenv("AUGEO_SMTP_PORT", "25")
	t.Setenv("AUGEO_SMTP_HOST", "")
	if _, err := Load(nil, ""); err == nil || !strings.Contains(err.Error(), "AUGEO_SMTP_HOST") {
		t.Fatalf("settings without host: %v", err)
	}
}

func TestSMTPPasswordFile(t *testing.T) {
	f := t.TempDir() + "/pw"
	if err := os.WriteFile(f, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUGEO_SMTP_HOST", "smtp.example.com")
	t.Setenv("AUGEO_SMTP_USERNAME", "geo")
	t.Setenv("AUGEO_SMTP_FROM", "noreply@geo.example")
	t.Setenv("AUGEO_SMTP_PASSWORD_FILE", f)
	cfg, err := Load(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SMTP.Password != "s3cret" {
		t.Fatalf("password from file: %q", cfg.SMTP.Password)
	}
}
