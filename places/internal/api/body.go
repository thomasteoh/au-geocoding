// Package api implements the serving HTTP handlers for the places service.
package api

import (
	"encoding/json"
	"net/http"
)

// MaxBodyBytes bounds any request body decoded by a handler. Without this cap
// a client can POST an unbounded JSON body and force unbounded memory use in
// the server process. Matches the geocoder's 1MB limit.
const MaxBodyBytes = 1 << 20

// LimitBody wraps r.Body so decoding fails (413) if the body exceeds
// MaxBodyBytes. Call it before json.NewDecoder(r.Body) in every handler.
func LimitBody(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
}

// writeJSONError writes a JSON error body with the application/json content
// type. http.Error forces text/plain even when the body is a JSON object, so
// handlers that return {"error":...} must use this helper instead — clients
// parsing JSON errors would break on text/plain (UX review finding #4).
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: msg})
}
