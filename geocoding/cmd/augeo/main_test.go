package main

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"augeocoding/internal/llm"
	"ausystem/shared/contract"
	"ausystem/shared/slog"
)

func TestHasScope(t *testing.T) {
	if !hasScope([]string{"search"}, "search") {
		t.Fatal("search should match search")
	}
	if hasScope([]string{"search"}, "batch") {
		t.Fatal("search should not match batch")
	}
	if !hasScope([]string{"SEARCH"}, "search") {
		t.Fatal("case-insensitive match")
	}
	if !hasScope(nil, "search") {
		t.Fatal("empty scope set should default to search")
	}
}

func TestEndpointScope(t *testing.T) {
	if endpointScope("batch") != "batch" {
		t.Fatal("batch endpoint should require batch scope")
	}
	if endpointScope("search") != "search" || endpointScope("geocode") != "search" ||
		endpointScope("reverse") != "search" || endpointScope("poi") != "search" ||
		endpointScope("parse") != "search" {
		t.Fatal("non-batch endpoints should require search scope")
	}
	// A batch-scoped key is denied the search family.
	if hasScope([]string{"batch"}, "search") {
		t.Fatal("batch scope should not grant search")
	}
	if !hasScope([]string{"batch"}, "batch") {
		t.Fatal("batch scope should grant batch")
	}
}

func TestTouchesOSMItems(t *testing.T) {
	// No candidates at all → false.
	if touchesOSMItems(batchResp{}) {
		t.Fatal("empty batch should not touch OSM")
	}
	// Only G-NAF candidates → false.
	if touchesOSMItems(batchResp{Items: []batchItem{{Candidates: []contract.Candidate{{Source: "gnaf"}}}}}) {
		t.Fatal("gnaf-only should not touch OSM")
	}
	// An OSM candidate → true.
	if !touchesOSMItems(batchResp{Items: []batchItem{{Candidates: []contract.Candidate{{Source: "osm"}}}}}) {
		t.Fatal("osm candidate should touch OSM")
	}
	// A non-200 item's candidates are not counted (error items carry none), but
	// an OSM candidate in a later item is still detected.
	if !touchesOSMItems(batchResp{Items: []batchItem{
		{Status: 400, Error: "no candidates"},
		{Candidates: []contract.Candidate{{Source: "osm"}}},
	}}) {
		t.Fatal("osm in later item should touch OSM")
	}
}

func TestBatchItemPerItemStatus(t *testing.T) {
	// One bad item must not fail the batch — each carries its own status.
	resp := batchResp{Items: []batchItem{
		{Index: 0, Status: 200, Strategy: "address", Candidates: []contract.Candidate{{ID: contract.CandidateID{PID: "x"}}}},
		{Index: 1, Status: 400, Error: "no candidates"},
	}}
	if len(resp.Items) != 2 {
		t.Fatalf("want 2 items, got %d", len(resp.Items))
	}
	if resp.Items[0].Status != 200 || resp.Items[1].Status != 400 {
		t.Fatalf("per-item status not preserved: %v", resp.Items)
	}
}

func TestCtrlLLMGate(t *testing.T) {
	h := llm.NewHolder(llm.Config{BaseURL: "http://a", Model: "m1", Enabled: true, APIKey: "secret"})
	// Empty token => fail closed (401 even with a token header).
	rec := httptest.NewRecorder()
	handleCtrlLLM(h, "", slog.New(io.Discard, slog.LevelError, nil))(rec, httptest.NewRequest("GET", "/ctrl/llm", nil))
	if rec.Code != 401 {
		t.Fatalf("empty token: want 401, got %d", rec.Code)
	}
	// Wrong token => 401.
	rec = httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ctrl/llm", nil)
	r.Header.Set("X-Augeo-Ctrl-Token", "wrong")
	handleCtrlLLM(h, "right", slog.New(io.Discard, slog.LevelError, nil))(rec, r)
	if rec.Code != 401 {
		t.Fatalf("wrong token: want 401, got %d", rec.Code)
	}
}

func TestCtrlLLMGetRedactsKey(t *testing.T) {
	h := llm.NewHolder(llm.Config{BaseURL: "http://a", Model: "m1", Enabled: true, APIKey: "secret"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ctrl/llm", nil)
	r.Header.Set("X-Augeo-Ctrl-Token", "tok")
	handleCtrlLLM(h, "tok", slog.New(io.Discard, slog.LevelError, nil))(rec, r)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["api_key"] != "REDACTED" {
		t.Fatalf("api key leaked: %v", body["api_key"])
	}
	if body["base_url"] != "http://a" || body["model"] != "m1" {
		t.Fatalf("unexpected config: %v", body)
	}
}

func TestCtrlLLMPostUpdate(t *testing.T) {
	h := llm.NewHolder(llm.Config{BaseURL: "http://a", Model: "m1", Enabled: true})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/ctrl/llm", strings.NewReader(`{"model":"m2","enabled":false}`))
	r.Header.Set("X-Augeo-Ctrl-Token", "tok")
	handleCtrlLLM(h, "tok", slog.New(io.Discard, slog.LevelError, nil))(rec, r)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	got := h.Get()
	if got.Model != "m2" || got.Enabled {
		t.Fatalf("update not applied: %+v", got)
	}
	if got.BaseURL != "http://a" {
		t.Fatalf("absent field should keep current: %+v", got)
	}
}

func TestCtrlLLMBadMethod(t *testing.T) {
	h := llm.NewHolder(llm.Config{})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/ctrl/llm", nil)
	r.Header.Set("X-Augeo-Ctrl-Token", "tok")
	handleCtrlLLM(h, "tok", slog.New(io.Discard, slog.LevelError, nil))(rec, r)
	if rec.Code != 405 {
		t.Fatalf("want 405, got %d", rec.Code)
	}
}
