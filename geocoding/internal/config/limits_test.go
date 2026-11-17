package config

import (
	"strings"
	"testing"
)

// Zero values that would break every request are refused at boot.
func TestZeroTimeoutAndQueueDepthRejected(t *testing.T) {
	for env, want := range map[string]string{
		"AUGEO_REQUEST_TIMEOUT": "request_timeout",
		"AUGEO_QUEUE_DEPTH":     "queue depth",
		"AUGEO_LLM_TIMEOUT":     "llm timeout",
	} {
		t.Run(env, func(t *testing.T) {
			v := "0"
			if env == "AUGEO_LLM_TIMEOUT" {
				v = "-1" // 0 is allowed there: it means "use the default"
			}
			t.Setenv(env, v)
			if _, err := Load(nil, ""); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("%s=%s: %v", env, v, err)
			}
		})
	}
}

func TestLLMTimeoutDefault(t *testing.T) {
	cfg, err := Load(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LLM.Timeout <= 0 || cfg.LLM.Timeout >= cfg.Limits.RequestTimeout {
		t.Fatalf("llm timeout %d should be set and below the request timeout %d", cfg.LLM.Timeout, cfg.Limits.RequestTimeout)
	}
}
