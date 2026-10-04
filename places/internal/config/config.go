package config

// Config is the server's configuration (D-020). Precedence: flag > env > file >
// default. Env vars are prefixed AUGEO_. Validated at boot; a misconfigured
// server refuses to start (fail fast). There are no secrets in this service —
// the redaction discipline is for the geocoder, which may carry an LLM key.
type Config struct {
	DB   string `json:"db"`
	Addr string `json:"addr"`
}

// Defaults. Only the serving path and listen address are configurable; the
// dataset version is derived from the data, not the config (INV-5).
const (
	DefaultDB   = "data/vic.db"
	DefaultAddr = ":8080"
)

// Effective returns the effective config given flags, env, and a file. Precedence
// flag > env > file > default. The file is optional; an absent file is fine.
// Secrets (none here) would be redacted in the logged form.
func Effective(flagDB, flagAddr, envDB, envAddr, fileDB, fileAddr string) Config {
	db := DefaultDB
	if fileDB != "" {
		db = fileDB
	}
	if envDB != "" {
		db = envDB
	}
	if flagDB != "" {
		db = flagDB
	}
	addr := DefaultAddr
	if fileAddr != "" {
		addr = fileAddr
	}
	if envAddr != "" {
		addr = envAddr
	}
	if flagAddr != "" {
		addr = flagAddr
	}
	return Config{DB: db, Addr: addr}
}
