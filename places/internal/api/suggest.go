package api

// POST /suggest — autocomplete (PR-7). Prefix matching over the street+locality
// suggestion index (suggest_idx), NOT full addresses (S-13). Every entry is
// self-disambiguating: it carries its own locality and postcode, so
//
//	STATION STREET, BRIGHTON VIC 3186
//	STATION STREET, FAIRFIELD VIC 3078
//
// are distinct suggestions even though both are "STATION STREET". Selection
// returns a resolvable handle (street_locality_pid / locality_pid) so the next
// step is an exact lookup, never a re-parse (PR-7.6).
//
// PR-7.5 (INV-1) holds: the query text is never logged, never cached
// cross-caller, never a metric label. Only the count of suggestions returned
// is recorded.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// SuggestRequest is the /suggest request body. Prefix is the keystroke prefix
// so far; a caller typing "12 station st brighton" sends the whole string and
// the handler matches on both street and locality tokens.
type SuggestRequest struct {
	Prefix string `json:"prefix"`
	// Limit caps the number of suggestions returned. 0 means the server default
	// (maxSuggest). Previously the geocoder's SuggestRequest.Limit was dead code
	// — callers could never request more than 10 (UX review finding #7).
	Limit int `json:"limit,omitempty"`
}

// maxSuggest is the server default suggestion count. Callers may set
// SuggestRequest.Limit up to this bound.
const maxSuggest = 10

// MaxSuggestPrefixLen caps the prefix length. Suggest is keystroke-driven —
// a 256-char prefix is never a real keystroke and would be an expensive query.
const MaxSuggestPrefixLen = 64

// SuggestResponse is the /suggest response. Each suggestion is a street+locality
// entry (the indexed middle level), self-disambiguating and carrying resolvable
// handles.
type SuggestResponse struct {
	Suggestions []Suggestion `json:"suggestions"`
	Truncated   bool         `json:"truncated"`
	Version     string       `json:"dataset_version"`
}

// Suggestion is one street+locality autocomplete entry.
type Suggestion struct {
	// Display is the self-disambiguating text the caller shows.
	Display string `json:"display"`
	// Handles for exact lookup (PR-7.6).
	StreetLocalityPID string `json:"street_locality_pid,omitempty"`
	LocalityPID       string `json:"locality_pid,omitempty"`
	StreetName        string `json:"street_name,omitempty"`
	StreetType        string `json:"street_type,omitempty"`
	Locality          string `json:"locality,omitempty"`
	Postcode          string `json:"postcode,omitempty"`
	State             string `json:"state,omitempty"`
}

// SuggestHandler is the /suggest HTTP handler. p provides the active serving DB.
func SuggestHandler(p *DBProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		// Contract version enforcement (contract.md § Versioning): a mismatch is
		// a startup failure — refuse with a distinct signal so the caller can
		// fail fast at boot, not silently per-call. Matches the /resolve handler.
		// Previously /suggest ignored the header entirely (UX review finding #3).
		if v := r.Header.Get(contractVersionHeader); v != "" && v != contractVersion {
			writeJSONError(w, http.StatusBadRequest, "contract version mismatch")
			return
		}
		var req SuggestRequest
		LimitBody(w, r)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad request")
			return
		}
		req.Prefix = strings.TrimSpace(req.Prefix)
		if req.Prefix == "" {
			writeJSONError(w, http.StatusBadRequest, "empty prefix")
			return
		}
		if len(req.Prefix) > MaxSuggestPrefixLen {
			writeJSONError(w, http.StatusBadRequest, "prefix too long")
			return
		}
		// Clamp the caller's Limit to the server bound.
		if req.Limit > maxSuggest {
			req.Limit = maxSuggest
		}
		// INV-1 (PR-7.5): the prefix is never logged, never a metric label,
		// never cached. Only the suggestion count is recorded.
		resp := Suggest(context.Background(), p.Get(), req)
		// Echo the contract version so the caller can verify which wire
		// format it got (UX review finding #3).
		w.Header().Set(contractVersionHeader, contractVersion)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// Suggest runs the prefix lookup over suggest_idx. Tokens are prefix-matched
// with the FTS5 prefix index; the whole query is AND'd across tokens so
// "station brighton" returns STATION in BRIGHTON, not STATION in any locality
// and BRIGHTON in any state.
func Suggest(ctx context.Context, db *sql.DB, req SuggestRequest) SuggestResponse {
	// Tokenise the prefix. Suggest is keystroke-driven: split on whitespace,
	// upper-case (the index stores upper), and require >=2 chars (prefix index
	// covers 2+). A single token is a street/locality prefix.
	fields := strings.Fields(req.Prefix)
	if len(fields) == 0 {
		return SuggestResponse{}
	}
	var phrases []string
	for _, f := range fields {
		f = strings.ToUpper(strings.TrimSpace(f))
		if len(f) < 2 {
			continue
		}
		// Prefix phrase: the index has prefix='2 3 4', so "ST*" matches STATION.
		phrases = append(phrases, `"`+f+`"*`)
	}
	if len(phrases) == 0 {
		return SuggestResponse{}
	}
	match := strings.Join(phrases, " AND ")

	// Use the caller's Limit (default maxSuggest). maxSuggest+1 lets us detect
	// truncation without fetching a second page (UX review finding #7).
	limit := req.Limit
	if limit <= 0 {
		limit = maxSuggest
	}
	rows, err := db.QueryContext(ctx, `
		SELECT street_locality_pid, locality_pid, street_name, street_type,
		       locality_name, postcode, state
		FROM suggest_idx
		WHERE suggest_idx MATCH ?
		LIMIT `+strconv.Itoa(limit+1), match)
	if err != nil {
		return SuggestResponse{}
	}
	defer rows.Close()

	resp := SuggestResponse{Version: datasetVersion(ctx, db)}
	for rows.Next() {
		var s Suggestion
		var slPID, locPID, name, typ, loc, post, state string
		if err := rows.Scan(&slPID, &locPID, &name, &typ, &loc, &post, &state); err != nil {
			return SuggestResponse{}
		}
		s = Suggestion{
			StreetLocalityPID: slPID, LocalityPID: locPID,
			StreetName: name, StreetType: typ, Locality: loc,
			Postcode: post, State: state,
		}
		// Self-disambiguating display (S-13): the entry carries its own
		// locality and postcode. Street name + street type read as a unit
		// ("STATION WALK"), then locality, state, postcode.
		var street string
		if typ != "" {
			street = name + " " + typ
		} else {
			street = name
		}
		parts := []string{}
		if street != "" {
			parts = append(parts, street)
		}
		parts = append(parts, loc)
		s.Display = strings.Join(parts, ", ")
		if state != "" {
			s.Display += " " + state
		}
		if post != "" {
			s.Display += " " + post
		}
		if len(resp.Suggestions) >= limit {
			resp.Truncated = true
			break
		}
		resp.Suggestions = append(resp.Suggestions, s)
	}
	return resp
}
