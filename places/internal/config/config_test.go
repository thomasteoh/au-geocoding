package config

import "testing"

// D-020 precedence: flag > env > file > default. Effective() applies exactly
// that order. A config test locks the precedence so it can't silently drift.
func TestEffectivePrecedence(t *testing.T) {
	tests := []struct {
		name             string
		flagDB, flagAddr string
		envDB, envAddr   string
		fileDB, fileAddr string
		wantDB, wantAddr string
	}{
		{"default", "", "", "", "", "", "", DefaultDB, DefaultAddr},
		{"file overrides default", "", "", "", "", "x.db", ":1234", "x.db", ":1234"},
		{"env overrides file", "", "", "env.db", ":4321", "x.db", ":1234", "env.db", ":4321"},
		{"flag overrides env", "flag.db", ":8081", "env.db", ":4321", "x.db", ":1234", "flag.db", ":8081"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Effective(tt.flagDB, tt.flagAddr, tt.envDB, tt.envAddr, tt.fileDB, tt.fileAddr)
			if got.DB != tt.wantDB || got.Addr != tt.wantAddr {
				t.Fatalf("Effective() = %+v, want db=%q addr=%q", got, tt.wantDB, tt.wantAddr)
			}
		})
	}
}
