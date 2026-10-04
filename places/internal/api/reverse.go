package api

// POST /reverse — reverse geocoding (Step 3). Given a lat/lon, find the
// nearest addresses via the addr_rt RTree index.
//
// POST /locality — boundary containment (Step 3). Given a lat/lon, find the
// locality polygon containing it via the boundary geopoly index.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"auplaces/internal/match"
)

// ReverseRequest is the /reverse request body.
type ReverseRequest struct {
	Lat   float64 `json:"latitude"`
	Lon   float64 `json:"longitude"`
	Limit int     `json:"limit,omitempty"`
}

// ReverseResponse is the /reverse response.
type ReverseResponse struct {
	Version    string             `json:"dataset_version"`
	Candidates []ReverseCandidate `json:"candidates"`
}

// ReverseCandidate is one reverse-geocoded address.
type ReverseCandidate struct {
	ID           string  `json:"id"`
	Address      string  `json:"address"`
	StreetNumber string  `json:"street_number,omitempty"`
	StreetName   string  `json:"street_name,omitempty"`
	Locality     string  `json:"locality"`
	State        string  `json:"state"`
	Postcode     string  `json:"postcode,omitempty"`
	Lat          float64 `json:"latitude"`
	Lon          float64 `json:"longitude"`
	Distance     float64 `json:"distance_m"`
	Source       string  `json:"source"`
}

// ReverseHandler is the /reverse HTTP handler.
func ReverseHandler(p *DBProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req ReverseRequest
		LimitBody(w, r)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad request")
			return
		}
		if req.Lat == 0 && req.Lon == 0 {
			writeJSONError(w, http.StatusBadRequest, "empty coordinate")
			return
		}
		if req.Limit <= 0 {
			req.Limit = 5
		}
		res, err := match.Reverse(context.Background(), p.Get(), req.Lon, req.Lat, req.Limit)
		resp := ReverseResponse{Version: datasetVersion(context.Background(), p.Get())}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "reverse failed")
			return
		}
		for _, c := range res {
			resp.Candidates = append(resp.Candidates, ReverseCandidate{
				ID:           c.PID,
				Address:      formatAddress(c),
				StreetNumber: c.StreetNumber,
				StreetName:   c.StreetName,
				Locality:     c.Locality,
				State:        c.State,
				Postcode:     c.Postcode,
				Lat:          c.Lat,
				Lon:          c.Lon,
				Distance:     c.DistanceM,
				Source:       "gnaf",
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// LocalityRequest is the /locality request body.
type LocalityRequest struct {
	Lat   float64 `json:"latitude"`
	Lon   float64 `json:"longitude"`
	Limit int     `json:"limit,omitempty"`
}

// LocalityResponse is the /locality response.
type LocalityResponse struct {
	Version   string             `json:"dataset_version"`
	Localities []LocalityResult   `json:"localities"`
}

// LocalityResult is one containing locality.
type LocalityResult struct {
	LocPID string `json:"locality_pid"`
	Name   string `json:"name"`
	Class  string `json:"locality_class,omitempty"`
}

// LocalityHandler is the /locality HTTP handler.
func LocalityHandler(p *DBProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req LocalityRequest
		LimitBody(w, r)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad request")
			return
		}
		if req.Lat == 0 && req.Lon == 0 {
			writeJSONError(w, http.StatusBadRequest, "empty coordinate")
			return
		}
		if req.Limit <= 0 {
			req.Limit = 3
		}
		hits, err := match.LocalityAt(context.Background(), p.Get(), req.Lon, req.Lat, req.Limit)
		resp := LocalityResponse{Version: datasetVersion(context.Background(), p.Get())}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "locality failed")
			return
		}
		for _, h := range hits {
			resp.Localities = append(resp.Localities, LocalityResult{
				LocPID: h.LocPID, Name: h.Name, Class: h.LocalityClass,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// formatAddress builds a display address string from a reverse result.
func formatAddress(c match.ReverseResult) string {
	parts := []string{}
	if c.StreetNumber != "" {
		parts = append(parts, c.StreetNumber)
	}
	if c.StreetName != "" {
		parts = append(parts, c.StreetName)
	}
	if c.StreetType != "" {
		parts = append(parts, c.StreetType)
	}
	if len(parts) == 0 {
		return c.Locality
	}
	s := strings.Join(parts, " ") + ", " + c.Locality
	if c.State != "" {
		s += " " + c.State
	}
	if c.Postcode != "" {
		s += " " + c.Postcode
	}
	return s
}
