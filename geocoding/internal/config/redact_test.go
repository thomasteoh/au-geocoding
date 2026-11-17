package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactedHidesDSNURLUserinfoAndAdmins(t *testing.T) {
	var c Config
	setDefaults(&c)
	c.Cluster.StateDSN = "postgres://geo:s3cret@db/geo"
	c.LLM.BaseURL = "https://user:pa55@llm.example/v1?key=abc"
	c.Auth.BootstrapAdmins = []string{"alice@example.com", "bob@example.com"}
	c.CtrlToken = "tok"
	r := c.Redacted()
	b, _ := json.Marshal(r)
	out := string(b)
	for _, leak := range []string{"s3cret", "pa55", "key=abc", "alice@", "bob@", "\"tok\""} {
		if strings.Contains(out, leak) {
			t.Fatalf("redacted config leaks %q: %s", leak, out)
		}
	}
	if !strings.Contains(r.LLM.BaseURL, "llm.example/v1") {
		t.Fatalf("base URL host/path lost: %s", r.LLM.BaseURL)
	}
	if len(r.Auth.BootstrapAdmins) != 1 || r.Auth.BootstrapAdmins[0] != "REDACTED(2)" {
		t.Fatalf("admins: %v", r.Auth.BootstrapAdmins)
	}
	if c.Auth.BootstrapAdmins[0] != "alice@example.com" || c.Cluster.StateDSN == "REDACTED" {
		t.Fatal("original modified")
	}
}

func TestSecretFileUnreadableFailsBoot(t *testing.T) {
	for _, key := range []string{"LLM_API_KEY", "CTRL_TOKEN", "SECRET_KEY", "SMTP_PASSWORD"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv("AUGEO_"+key+"_FILE", filepath.Join(t.TempDir(), "missing"))
			_, err := Load(nil, "")
			if err == nil || !strings.Contains(err.Error(), "AUGEO_"+key+"_FILE") {
				t.Fatalf("want boot failure naming AUGEO_%s_FILE, got %v", key, err)
			}
		})
	}
}

func TestCtrlTokenFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(p, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUGEO_CTRL_TOKEN_FILE", p)
	cfg, err := Load(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CtrlToken != "from-file" {
		t.Fatalf("ctrl token = %q", cfg.CtrlToken)
	}
	t.Setenv("AUGEO_CTRL_TOKEN", "from-env")
	if cfg, _ = Load(nil, ""); cfg.CtrlToken != "from-env" {
		t.Fatalf("env should win over _FILE: %q", cfg.CtrlToken)
	}
}

func TestTrustedProxiesParse(t *testing.T) {
	t.Setenv("AUGEO_TRUSTED_PROXY", "10.0.0.1, 172.16.0.0/12,::ffff:192.168.1.1,fd00::/8")
	cfg, err := Load(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range cfg.Server.TrustedProxies {
		got = append(got, p.String())
	}
	want := "10.0.0.1/32 172.16.0.0/12 192.168.1.1/32 fd00::/8"
	if strings.Join(got, " ") != want {
		t.Fatalf("got %v want %s", got, want)
	}
	t.Setenv("AUGEO_TRUSTED_PROXY", "10.0.0.1,not-an-ip")
	if _, err := Load(nil, ""); err == nil || !strings.Contains(err.Error(), "trusted-proxy") {
		t.Fatalf("bad proxy should fail boot: %v", err)
	}
}
