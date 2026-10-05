// Package config implements D-020: flag > env > file > default, AUGEO_ env
// prefix, validate at boot, fail fast. All env vars use AUGEO_; secrets support
// the _FILE convention so Docker/Kubernetes secrets work without putting keys
// in the process environment.
package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config is the effective configuration for the geocoder.
// JSON tags make the -config/AUGEO_CONFIG file schema explicit (D-020): a field
// rename must also rename the tag, so the file tier never silently no-ops.
// Tags are kebab-case to match the flag names.
type Config struct {
	Server struct {
		Addr          string `json:"addr"`
		ReadTimeout   int    `json:"read_timeout"`
		WriteTimeout  int    `json:"write_timeout"`
		IdleTimeout   int    `json:"idle_timeout"`
		ShutdownGrace int    `json:"shutdown_grace"`
		TrustedProxy  string `json:"trusted_proxy"`
	} `json:"server"`
	Data struct {
		DataDir string   `json:"data_dir"`
		GNAFDB  string   `json:"gnaf_db"`
		POISDB  string   `json:"pois_db"`
		AppDB   string   `json:"app_db"`
		States  []string `json:"states"`
	} `json:"data"`
	Limits struct {
		MaxQueryLen    int `json:"max_query_len"`
		MaxResults     int `json:"max_results"`
		MaxRadiusM     int `json:"max_radius_m"`
		MaxBodyBytes   int `json:"max_body_bytes"`
		RequestTimeout int `json:"request_timeout"`
	} `json:"limits"`
	Rate struct {
		AnonRPS         float64 `json:"anon_rps"`
		AnonBurst       float64 `json:"anon_burst"`
		AnonDaily       int64   `json:"anon_daily"`
		KeyDefaultRPS   float64 `json:"key_default_rps"`
		KeyDefaultBurst float64 `json:"key_default_burst"`
		KeyDefaultDaily int64   `json:"key_default_daily"`
	} `json:"rate"`
	AnonLLM struct {
		DailyPerIP  int64 `json:"daily_per_ip"`
		DailyGlobal int64 `json:"daily_global"`
	} `json:"anon_llm"`
	LLM struct {
		BaseURL   string `json:"base_url"`
		APIKey    string `json:"api_key"`
		Model     string `json:"model"`
		Timeout   int    `json:"timeout"`
		MaxTokens int    `json:"max_tokens"`
		Enabled   bool   `json:"enabled"`
	} `json:"llm"`
	Queue struct {
		Depth            int `json:"depth"`
		Workers          int `json:"workers"`
		PerKeyInflight   int `json:"per_key_inflight"`
		BreakerThreshold int `json:"breaker_threshold"`
		BreakerCooldown  int `json:"breaker_cooldown"`
	} `json:"queue"`
	Cache struct {
		Entries int `json:"entries"`
		TTL     int `json:"ttl"`
	} `json:"cache"`
	Batch struct {
		MaxRows             int `json:"max_rows"`
		Workers             int `json:"workers"`
		MaxConcurrentPerKey int `json:"max_concurrent_per_key"`
		MaxDuration         int `json:"max_duration"`
	} `json:"batch"`
	Cluster struct {
		StateMode string `json:"state_mode"`
		StateDSN  string `json:"state_dsn"`
	} `json:"cluster"`
	Web struct {
		DemoEnabled    bool     `json:"demo_enabled"`
		DemoMapEnabled bool     `json:"demo_map_enabled"`
		CORSOrigins    []string `json:"cors_origins"`
	} `json:"web"`
	Log struct {
		Level  string `json:"level"`
		Format string `json:"format"`
	} `json:"log"`
	PlacesURL string `json:"places_url"` // split-mode au-places base URL; "" = single-binary
	Auth      Auth   `json:"auth"`
}

// Auth configures the console, SSO, SCIM and API bearer tokens
// (docs/auth.md). The console is enabled when PublicURL and SecretKey are
// both set.
type Auth struct {
	PublicURL       string   `json:"public_url"`
	SecretKey       string   `json:"secret_key"`
	Signup          string   `json:"signup"` // open | closed
	BootstrapAdmins []string `json:"bootstrap_admins"`
	SessionIdle     int      `json:"session_idle"` // seconds
	SessionMax      int      `json:"session_max"`  // seconds
	ProvidersFile   string   `json:"providers_file"`
	// JWTBearer enables Authorization: Bearer on the public API (on by
	// default; it only accepts issuers an org registered).
	JWTBearer bool `json:"jwt_bearer"`
	// AllowPrivateFetch lets OIDC discovery, JWKS and SAML metadata fetches
	// reach private and loopback addresses. Development only.
	AllowPrivateFetch bool `json:"allow_private_fetch"`
}

// ConsoleEnabled reports whether the console and SSO are configured.
func (a Auth) ConsoleEnabled() bool { return a.PublicURL != "" && a.SecretKey != "" }

// Load parses flags, env and an optional file, with precedence flag > env > file
// > default (D-020). Returns the effective config and any validation error.
func Load(args []string, filePath string) (Config, error) {
	var cfg Config
	setDefaults(&cfg)

	// Discover -config/--config from args so the file tier can apply before flags.
	// Also honor AUGEO_CONFIG env (D-020; matches the places service's convention).
	// Env is read first so a flag -config still wins over it (flag > env > file).
	if p := configPathFromArgs(args); p != "" {
		filePath = p
	} else if v := os.Getenv("AUGEO_CONFIG"); v != "" {
		filePath = v
	}
	// File (lowest explicit source, above defaults).
	if filePath != "" {
		if err := loadFile(filePath, &cfg); err != nil {
			return cfg, err
		}
	}
	// Env (overrides file).
	applyEnv(&cfg)

	// Parse flags LAST: flag > env > file > default (D-020). Flag defaults are
	// captured at registration — which is after file+env — so an unset flag keeps
	// the file/env value and a set flag overrides it.
	fs := flag.NewFlagSet("augeo", flag.ContinueOnError)
	var configPath string
	fs.StringVar(&configPath, "config", "", "config file path")
	fs.StringVar(&cfg.Server.Addr, "addr", cfg.Server.Addr, "listen address")
	fs.StringVar(&cfg.Server.TrustedProxy, "trusted-proxy", cfg.Server.TrustedProxy, "IP of a reverse proxy whose X-Forwarded-For is trusted")
	fs.StringVar(&cfg.Data.GNAFDB, "gnaf-db", cfg.Data.GNAFDB, "G-NAF database")
	fs.StringVar(&cfg.Data.POISDB, "pois-db", cfg.Data.POISDB, "POI database")
	fs.StringVar(&cfg.Data.AppDB, "app-db", cfg.Data.AppDB, "app.db (service state)")
	fs.StringVar(&cfg.PlacesURL, "places-url", cfg.PlacesURL, "au-places base URL (split mode)")
	fs.StringVar(&cfg.Log.Level, "log-level", cfg.Log.Level, "log level")
	fs.StringVar(&cfg.Log.Format, "log-format", cfg.Log.Format, "log format")
	fs.StringVar(&cfg.Auth.PublicURL, "public-url", cfg.Auth.PublicURL, "external base URL; enables the console with AUGEO_SECRET_KEY")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	_ = configPath

	// Validate (fail fast — D-020).
	var errs []string
	if cfg.Data.AppDB == "" {
		errs = append(errs, "app-db required")
	}
	if cfg.Server.Addr == "" {
		errs = append(errs, "addr required")
	}
	if cfg.LLM.BaseURL != "" && cfg.LLM.Enabled {
		// Configured and enabled: fine. Configured but disabled: warn at boot.
	}
	if len(cfg.Data.States) == 0 {
		cfg.Data.States = []string{"ALL"}
	}
	if cfg.Limits.MaxQueryLen <= 0 {
		cfg.Limits.MaxQueryLen = 256
	}
	if cfg.Limits.MaxResults <= 0 {
		cfg.Limits.MaxResults = 20
	}
	if cfg.Limits.MaxBodyBytes <= 0 {
		cfg.Limits.MaxBodyBytes = 1 << 20
	}
	errs = append(errs, validateAuth(&cfg.Auth)...)
	if len(errs) > 0 {
		return cfg, fmt.Errorf("invalid config: %s", strings.Join(errs, "; "))
	}
	return cfg, nil
}

func validateAuth(a *Auth) []string {
	var errs []string
	a.PublicURL = strings.TrimSuffix(strings.TrimSpace(a.PublicURL), "/")
	if (a.PublicURL == "") != (a.SecretKey == "") {
		errs = append(errs, "AUGEO_PUBLIC_URL and AUGEO_SECRET_KEY must be set together")
	}
	if a.PublicURL != "" {
		u, err := url.Parse(a.PublicURL)
		switch {
		case err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "":
			errs = append(errs, "public-url must be an origin like https://geo.example.com")
		case u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")):
			// Session cookies are Secure and __Host- prefixed; plain http
			// only works on localhost, where browsers allow it.
			errs = append(errs, "public-url must be https (http only for localhost)")
		}
	}
	switch a.Signup {
	case "open", "closed":
	default:
		errs = append(errs, "auth signup must be open or closed")
	}
	if a.SessionIdle <= 0 || a.SessionMax <= 0 || a.SessionIdle > a.SessionMax {
		errs = append(errs, "auth session idle and max must be positive, idle <= max")
	}
	return errs
}

// configPathFromArgs extracts -config/--config (and -config=value) from args,
// so the file tier can be applied before flags without a separate pre-parse.
func configPathFromArgs(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-config" || a == "--config" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(a, "-config=") || strings.HasPrefix(a, "--config=") {
			return a[strings.Index(a, "=")+1:]
		}
	}
	return ""
}

func setDefaults(c *Config) {
	c.Server.Addr = ":8080"
	c.Server.ReadTimeout = 10
	c.Server.WriteTimeout = 20
	c.Server.IdleTimeout = 120
	c.Server.ShutdownGrace = 10
	c.Data.DataDir = "data"
	c.Data.GNAFDB = "data/gnaf.db"
	c.Data.POISDB = "data/pois.db"
	c.Data.AppDB = "data/app.db"
	c.Limits.MaxQueryLen = 256
	c.Limits.MaxResults = 20
	c.Limits.MaxRadiusM = 5000
	c.Limits.MaxBodyBytes = 1 << 20
	c.Limits.RequestTimeout = 30
	c.Rate.AnonRPS = 2
	c.Rate.AnonBurst = 5
	c.Rate.AnonDaily = 100
	c.Rate.KeyDefaultRPS = 20
	c.Rate.KeyDefaultBurst = 40
	c.Rate.KeyDefaultDaily = 10000
	c.AnonLLM.DailyPerIP = 10
	c.AnonLLM.DailyGlobal = 1000
	c.Queue.Depth = 53
	c.Queue.Workers = 8
	c.Queue.PerKeyInflight = 2
	c.Queue.BreakerThreshold = 5
	c.Queue.BreakerCooldown = 60
	c.Cache.Entries = 1024
	c.Cache.TTL = 300
	c.Batch.MaxRows = 100000
	c.Batch.Workers = 4
	c.Batch.MaxConcurrentPerKey = 1
	c.Batch.MaxDuration = 600
	c.Cluster.StateMode = "single"
	c.Web.DemoEnabled = true
	c.Log.Level = "info"
	c.Log.Format = "json"
	c.Auth.Signup = "closed"
	c.Auth.SessionIdle = 8 * 3600
	c.Auth.SessionMax = 7 * 24 * 3600
	c.Auth.JWTBearer = true
}

func loadFile(path string, c *Config) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return fmt.Errorf("config file %s: %w", path, err)
	}
	return nil
}

func applyEnv(c *Config) {
	str := func(key string, dst *string) {
		if v, ok := os.LookupEnv("AUGEO_" + key); ok {
			*dst = v
		}
	}
	num := func(key string, dst *int) {
		if v, ok := os.LookupEnv("AUGEO_" + key); ok {
			if n, err := strconv.Atoi(v); err == nil {
				*dst = n
			}
		}
	}
	num64 := func(key string, dst *int64) {
		if v, ok := os.LookupEnv("AUGEO_" + key); ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				*dst = n
			}
		}
	}
	boolean := func(key string, dst *bool) {
		if v, ok := os.LookupEnv("AUGEO_" + key); ok {
			if b, err := strconv.ParseBool(v); err == nil {
				*dst = b
			}
		}
	}
	flt := func(key string, dst *float64) {
		if v, ok := os.LookupEnv("AUGEO_" + key); ok {
			if n, err := strconv.ParseFloat(v, 64); err == nil {
				*dst = n
			}
		}
	}
	str("ADDR", &c.Server.Addr)
	str("TRUSTED_PROXY", &c.Server.TrustedProxy)
	str("DATA_DIR", &c.Data.DataDir)
	str("GNAF_DB", &c.Data.GNAFDB)
	str("POIS_DB", &c.Data.POISDB)
	str("APP_DB", &c.Data.AppDB)
	num("MAX_QUERY_LEN", &c.Limits.MaxQueryLen)
	num("MAX_RESULTS", &c.Limits.MaxResults)
	num("MAX_RADIUS_M", &c.Limits.MaxRadiusM)
	num("MAX_BODY_BYTES", &c.Limits.MaxBodyBytes)
	num("REQUEST_TIMEOUT", &c.Limits.RequestTimeout)
	flt("ANON_RPS", &c.Rate.AnonRPS)
	flt("ANON_BURST", &c.Rate.AnonBurst)
	num64("ANON_DAILY", &c.Rate.AnonDaily)
	flt("KEY_DEFAULT_RPS", &c.Rate.KeyDefaultRPS)
	flt("KEY_DEFAULT_BURST", &c.Rate.KeyDefaultBurst)
	num64("KEY_DEFAULT_DAILY", &c.Rate.KeyDefaultDaily)
	num64("ANON_LLM_DAILY_PER_IP", &c.AnonLLM.DailyPerIP)
	num64("ANON_LLM_DAILY_GLOBAL", &c.AnonLLM.DailyGlobal)
	str("LLM_BASE_URL", &c.LLM.BaseURL)
	str("LLM_MODEL", &c.LLM.Model)
	num("LLM_TIMEOUT", &c.LLM.Timeout)
	num("LLM_MAX_TOKENS", &c.LLM.MaxTokens)
	num("QUEUE_DEPTH", &c.Queue.Depth)
	num("QUEUE_WORKERS", &c.Queue.Workers)
	num("QUEUE_PER_KEY_INFLIGHT", &c.Queue.PerKeyInflight)
	num("BREAKER_THRESHOLD", &c.Queue.BreakerThreshold)
	num("BREAKER_COOLDOWN", &c.Queue.BreakerCooldown)
	num("CACHE_ENTRIES", &c.Cache.Entries)
	num("CACHE_TTL", &c.Cache.TTL)
	num("BATCH_MAX_ROWS", &c.Batch.MaxRows)
	num("BATCH_WORKERS", &c.Batch.Workers)
	num("BATCH_MAX_CONCURRENT_PER_KEY", &c.Batch.MaxConcurrentPerKey)
	num("BATCH_MAX_DURATION", &c.Batch.MaxDuration)
	str("STATE_MODE", &c.Cluster.StateMode)
	str("STATE_DSN", &c.Cluster.StateDSN)
	str("LOG_LEVEL", &c.Log.Level)
	str("LOG_FORMAT", &c.Log.Format)
	str("PLACES_URL", &c.PlacesURL)

	// AUGEO_STATES=VIC,NSW (D-025).
	if v, ok := os.LookupEnv("AUGEO_STATES"); ok {
		c.Data.States = strings.Split(v, ",")
	}
	// LLM_API_KEY via _FILE convention.
	if v, ok := os.LookupEnv("AUGEO_LLM_API_KEY_FILE"); ok {
		b, err := os.ReadFile(v)
		if err == nil {
			c.LLM.APIKey = strings.TrimSpace(string(b))
		}
	}
	if v, ok := os.LookupEnv("AUGEO_LLM_API_KEY"); ok {
		c.LLM.APIKey = v
	}
	str("PUBLIC_URL", &c.Auth.PublicURL)
	str("AUTH_SIGNUP", &c.Auth.Signup)
	num("AUTH_SESSION_IDLE", &c.Auth.SessionIdle)
	num("AUTH_SESSION_MAX", &c.Auth.SessionMax)
	str("AUTH_PROVIDERS_FILE", &c.Auth.ProvidersFile)
	boolean("AUTH_JWT_BEARER", &c.Auth.JWTBearer)
	boolean("AUTH_ALLOW_PRIVATE_FETCH", &c.Auth.AllowPrivateFetch)
	if v, ok := os.LookupEnv("AUGEO_AUTH_BOOTSTRAP_ADMINS"); ok {
		c.Auth.BootstrapAdmins = nil
		for _, e := range strings.Split(v, ",") {
			if e = strings.TrimSpace(e); e != "" {
				c.Auth.BootstrapAdmins = append(c.Auth.BootstrapAdmins, e)
			}
		}
	}
	secretFromEnv("SECRET_KEY", &c.Auth.SecretKey)

	// LLM enabled only when BaseURL is set.
	c.LLM.Enabled = c.LLM.BaseURL != ""
}

// secretFromEnv reads AUGEO_<key>_FILE, then AUGEO_<key> (which wins).
func secretFromEnv(key string, dst *string) {
	if v, ok := os.LookupEnv("AUGEO_" + key + "_FILE"); ok {
		if b, err := os.ReadFile(v); err == nil {
			*dst = strings.TrimSpace(string(b))
		}
	}
	if v, ok := os.LookupEnv("AUGEO_" + key); ok {
		*dst = v
	}
}

// Redacted returns a copy of the config safe to log — secrets blanked (runtime.md:
// operators should never have to guess what the container did; secrets redacted).
func (c Config) Redacted() Config {
	cp := c
	if cp.LLM.APIKey != "" {
		cp.LLM.APIKey = "REDACTED"
	}
	if cp.Auth.SecretKey != "" {
		cp.Auth.SecretKey = "REDACTED"
	}
	return cp
}
