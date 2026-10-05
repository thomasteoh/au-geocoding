// Package contract carries the resolution contract types — the single interface
// between geocoder (interpretation) and places (resolution). Normative per
// au-system/contract.md. Identical in single-binary mode (Go interface call) and
// split mode (HTTP), so neither deployment pays for the other.
//
// INV-2: no identity field exists. There is no user, key, session, IP or
// timestamp-for-correlation — absent from the type, not merely unpopulated.
package contract

import (
	"context"
	"errors"
)

// Kind identifies the resolution operation. Address | POI | Reverse | Locality |
// Contains.
type Kind int

const (
	KindAddress Kind = iota
	KindPOI
	KindReverse
	KindLocality
	KindContains
)

// Point is a coordinate. Places resolves in GDA2020 (G-NAF) and WGS84 (OSM); the
// two differ by well under a metre in Australia at current epoch, so the contract
// carries a single Point type.
type Point struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// LocalityID is a locality identifier. 0 means "no containment filter".
type LocalityID int64

// CandidateID identifies a candidate.
type CandidateID struct {
	Source string `json:"source"` // "gnaf" | "osm"
	PID    string `json:"pid"`
}

// Candidate is a single resolution candidate.
type Candidate struct {
	ID     CandidateID `json:"id"`
	Kind   Kind        `json:"kind"`
	Point  Point       `json:"point"`
	Source string      `json:"source"` // "gnaf" | "osm"
	Text   string      `json:"text"`   // full address or POI name — what the caller scores against

	// G-NAF only — distinct quality axes, never collapsed
	GnafPID            string `json:"gnaf_pid,omitempty"`
	GnafConfidence     int8   `json:"gnaf_confidence,omitempty"`     // -1..2, how many authorities contributed
	GeocodeReliability int8   `json:"geocode_reliability,omitempty"` // 1..6, coordinate precision

	// MatchScore is the caller-side similarity (0..1) — set by the geocoder's
	// scoring phase, carried so ranking can use it without re-deriving.
	MatchScore float64 `json:"match_score,omitempty"`

	// POI only
	Name     string `json:"name,omitempty"`
	Brand    string `json:"brand,omitempty"`
	Operator string `json:"operator,omitempty"`

	// Context
	LocalityID LocalityID `json:"locality_id,omitempty"`
	DistanceM  *float64   `json:"distance_m,omitempty"` // set when Anchor was supplied
}

// Locality is a resolved locality name.
type Locality struct {
	ID    LocalityID `json:"id"`
	Name  string     `json:"name"`
	State string     `json:"state"`
}

// AddressComponents is a caller-supplied structured address. It exists so a
// caller who already holds parsed fields does not have to concatenate them into
// a string for the ladder to take apart again — which loses the structure they
// started with and can produce a worse answer than they had.
//
// Every field is optional. A partial set is a legitimate coarser query:
// locality + postcode with no street is a locality-level lookup, not an error.
//
// INV-2 still holds — these are address parts, not identity.
type AddressComponents struct {
	StreetNumber string `json:"street_number,omitempty"`
	StreetName   string `json:"street_name,omitempty"`
	StreetType   string `json:"street_type,omitempty"`
	Locality     string `json:"locality,omitempty"`
	State        string `json:"state,omitempty"`
	Postcode     string `json:"postcode,omitempty"`
}

// Empty reports whether no component was supplied at all.
func (c AddressComponents) Empty() bool {
	return c.StreetNumber == "" && c.StreetName == "" && c.StreetType == "" &&
		c.Locality == "" && c.State == "" && c.Postcode == ""
}

// HasStreet reports whether the caller named a street, which is what separates
// an address-level query from a locality-level one.
func (c AddressComponents) HasStreet() bool { return c.StreetName != "" }

// ResolveRequest is a structured resolution request. Places never parses free
// text; geocoder never reads a G-NAF column.
type ResolveRequest struct {
	Kind     Kind     `json:"kind"`
	Generate []string `json:"generate,omitempty"` // reliable tokens — candidate generation
	Score    []string `json:"score,omitempty"`    // full normalised token set — returned for caller scoring

	// Components is set when the caller supplied a structured address instead
	// of free text. Places uses it for field-aware matching rather than
	// inferring which token is which — it never parses, it is simply told.
	// Generate and Score are still populated alongside it so a resolver that
	// ignores Components degrades to token matching rather than failing.
	Components *AddressComponents `json:"components,omitempty"`
	State      string             `json:"state,omitempty"`    // hint, "" if absent
	Postcode   string             `json:"postcode,omitempty"` // hint, "" if absent
	Anchor     *Point             `json:"anchor,omitempty"`   // distance ranking
	Within     LocalityID         `json:"within,omitempty"`
	Limit      int                `json:"limit,omitempty"`        // caller's cap; places applies it AFTER ordering
	MaxRadiusM int                `json:"max_radius_m,omitempty"` // Reverse only
}

// ResolveResponse is the resolution result.
type ResolveResponse struct {
	Candidates     []Candidate `json:"candidates,omitempty"`
	Truncated      bool        `json:"truncated"`           // INV-6 — was the set capped?
	TotalMatched   int         `json:"total_matched"`       // what the caller did not see
	GeneratedCount int         `json:"generated_count"`     // candidates before filtering — cost visibility
	DatasetVersion string      `json:"dataset_version"`     // INV-5
	Ambiguous      []Locality  `json:"ambiguous,omitempty"` // populated when a locality name resolved to many
	Degraded       []string    `json:"degraded,omitempty"`  // e.g. "boundaries-unavailable"
}

// SuggestRequest is a keystroke prefix for autocomplete (PR-7). The caller
// sends the prefix typed so far; places prefix-matches it over the
// street+locality suggestion index. Limit caps the suggestions returned.
type SuggestRequest struct {
	Prefix string `json:"prefix"`
	Limit  int    `json:"limit,omitempty"`
}

// Suggestion is one street+locality autocomplete entry. It self-disambiguates:
// the entry carries its own locality and postcode, so "STATION STREET,
// BRIGHTON VIC 3186" and "STATION STREET, FAIRFIELD VIC 3078" are distinct.
// The handles make selection an exact lookup, never a re-parse (PR-7.6).
type Suggestion struct {
	Display           string `json:"display"`
	StreetLocalityPID string `json:"street_locality_pid,omitempty"`
	LocalityPID       string `json:"locality_pid,omitempty"`
	StreetName        string `json:"street_name,omitempty"`
	StreetType        string `json:"street_type,omitempty"`
	Locality          string `json:"locality,omitempty"`
	Postcode          string `json:"postcode,omitempty"`
	State             string `json:"state,omitempty"`
}

// SuggestResponse is the autocomplete result (PR-7.6). Suggestions are the
// indexed street+locality entries; the caller selects one and resolves via the
// handle it carries.
type SuggestResponse struct {
	Suggestions    []Suggestion `json:"suggestions,omitempty"`
	Truncated      bool         `json:"truncated"`
	DatasetVersion string       `json:"dataset_version,omitempty"`
}

// Resolver is the single-binary-mode interface. Split mode is an HTTP client
// implementing the same interface. The context carries the request deadline
// (runtime.md: deadline shedding on the slow path).
type Resolver interface {
	Resolve(ctx context.Context, req ResolveRequest) (ResolveResponse, error)
	// Suggest prefix-matches a keystroke prefix over the suggestion index. It
	// is a separate interface method because it is a genuinely different
	// problem from resolution (PR-7): sub-50ms prefix lookup, not a rung walk.
	Suggest(ctx context.Context, req SuggestRequest) (SuggestResponse, error)
	// Ready reports whether the resolver can serve requests (split-mode HTTP
	// probe; in-process resolvers return true unconditionally). Used by the
	// geocoder's /readyz.
	Ready(ctx context.Context) (bool, string, error)
}

// Version is the contract's wire-format version. Both sides must agree on it
// before a request round-trips; a mismatch is a startup failure (contract.md §
// Versioning), never a silent per-request error.
const Version = "v1"

// ContractVersionHeader is the HTTP header carrying the contract version.
const ContractVersionHeader = "X-Augeo-Contract-Version"

// Errors are typed, because "the query found nothing" and "the query was
// impossible" need different handling upstream.
var (
	ErrNoCandidates = errors.New("no candidates")
	ErrTooBroad     = errors.New("generation exceeded cost ceiling")
	ErrNotLoaded    = errors.New("dataset absent or mid-load")
	ErrOutOfScope   = errors.New("query targets a state this build excludes")
	ErrDegraded     = errors.New("optional layer unavailable")
)
