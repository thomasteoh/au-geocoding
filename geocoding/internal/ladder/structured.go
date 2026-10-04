package ladder

// Structured resolution — PR-8.2.
//
// A caller holding parsed address fields does not walk the ladder. The ladder
// exists to work out what a free-text string meant; when the caller has
// already told us, inferring it again can only lose information. So structured
// input goes straight to the address resolver: no rung walk, no LLM, and no
// ambiguity about which strategy fired.

import (
	"context"
	"errors"

	"ausystem/shared/contract"
	"ausystem/shared/normalise"
)

// StrategyStructured is the strategy reported for a structured request. It is
// distinct from StrategyAddress so a caller can tell that no interpretation
// happened — the answer came from the fields they supplied.
const StrategyStructured = "structured"

// StrategyStructuredLocality is the locality-level variant, returned when the
// caller supplied a locality or postcode but no street (PR-8.4).
const StrategyStructuredLocality = "structured_locality"

// ResolveStructured resolves caller-supplied address components directly.
//
// It bypasses the rungs entirely. Generate and Score are built from the
// components rather than parsed out of a string: because each value arrives
// already labelled, the reliable-token set is exact instead of inferred.
func (l *Ladder) ResolveStructured(ctx context.Context, c contract.AddressComponents, limit int) (Result, error) {
	res := l.addressResolver()
	if res == nil {
		return Result{}, ErrNoRung
	}
	if c.Empty() {
		return Result{}, ErrNoRung
	}
	if limit <= 0 {
		limit = 20
	}

	// Normalise per field, and differently per field. Case-folding and
	// punctuation stripping apply everywhere; abbreviation expansion applies
	// only to the street type.
	//
	// This matters more than it looks. The free-text normaliser expands "st"
	// to "street", which is right when it trails a street name and wrong for a
	// locality called "St Kilda" — it would become "Street Kilda" and match
	// nothing. The caller already told us which field is which, so applying
	// the free-text guess here would throw that away and reintroduce exactly
	// the ambiguity structured input removes.
	num := normalise.Fold(c.StreetNumber)
	name := normalise.Fold(c.StreetName)
	typ := normalise.ExpandStreetType(c.StreetType)
	loc := normalise.Fold(c.Locality)
	state := normalise.Fold(c.State)
	post := normalise.Fold(c.Postcode)

	kind := contract.KindAddress
	strategy := StrategyStructured
	if !c.HasStreet() {
		// PR-8.4: locality + postcode with no street is a valid coarser query,
		// not a 400. It resolves at locality level rather than failing.
		kind = contract.KindLocality
		strategy = StrategyStructuredLocality
	}

	// Generate carries the anchors used to produce candidates. Short tokens are
	// excluded for the same reason the free-text path excludes them: the
	// trigram index does not cover tokens under three characters, so a street
	// number is a scoring signal, never a generation anchor.
	var generate []string
	for _, t := range []string{name, loc} {
		if len(t) >= 3 {
			generate = append(generate, t)
		}
	}
	// Score carries everything the caller gave us, including the short tokens.
	var score []string
	for _, t := range []string{num, name, typ, loc, state, post} {
		if t != "" {
			score = append(score, t)
		}
	}

	comps := contract.AddressComponents{
		StreetNumber: num,
		StreetName:   name,
		StreetType:   typ,
		Locality:     loc,
		State:        state,
		Postcode:     post,
	}
	req := contract.ResolveRequest{
		Kind:       kind,
		Generate:   generate,
		Score:      score,
		State:      state,
		Postcode:   post,
		Components: &comps,
		Limit:      limit,
	}
	resp, err := res.Resolve(ctx, req)
	if err != nil {
		// Fold no-candidates into ErrNoRung so structured input gets the same
		// status (400) as the free-text path. Previously ErrNoCandidates (404)
		// leaked through here while free-text converted it to ErrNoRung (400) —
		// the same "no results" input returned different statuses depending on
		// request form (UX review finding #5).
		if errors.Is(err, contract.ErrNoCandidates) {
			return Result{Response: resp}, ErrNoRung
		}
		return Result{Response: resp}, err
	}
	return Result{Strategy: strategy, Response: resp}, nil
}

// addressResolver returns the resolver the address rung talks to, so the
// structured path reaches the same backend without a second wiring point.
func (l *Ladder) addressResolver() contract.Resolver {
	for _, r := range l.Rungs {
		if ar, ok := r.(addressRung); ok {
			return ar.res
		}
	}
	return nil
}
