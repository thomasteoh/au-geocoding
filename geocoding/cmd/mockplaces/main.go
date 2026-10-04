// Command mockplaces is a tiny resolver that implements the contract /resolve
// endpoint for testing the geocoder end to end. It returns canned candidates —
// enough to exercise the ladder, ranking, auth, quota and error paths without a
// real 3 GB dataset.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"ausystem/shared/contract"
)

func main() {
	http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready", "dataset": "mock-v1"})
	})
	http.HandleFunc("/resolve", func(w http.ResponseWriter, r *http.Request) {
		var req contract.ResolveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// Out-of-scope probe: a request targeting a state the build excludes.
		if strings.Contains(req.State, "queensland") || strings.Contains(strings.ToLower(strings.Join(req.Generate, " ")), "qld") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "out_of_scope"})
			return
		}
		// Canned candidates.
		cands := []contract.Candidate{
			{ID: contract.CandidateID{Source: "gnaf", PID: "gnaf-1"}, Source: "gnaf", Kind: contract.KindAddress,
				GnafPID: "gnaf-1", GnafConfidence: 2, GeocodeReliability: 5,
				MatchScore: 0.92, LocalityID: 1},
			{ID: contract.CandidateID{Source: "osm", PID: "osm-1"}, Source: "osm", Kind: contract.KindPOI,
				Name: "Woolworths", MatchScore: 0.85, LocalityID: 2},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(contract.ResolveResponse{
			Candidates:     cands,
			GeneratedCount: len(cands),
			DatasetVersion: "mock-v1",
		})
	})
	log.Fatal(http.ListenAndServe(":8092", nil))
}
