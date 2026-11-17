package api

import (
	"context"
	"testing"

	"auplaces/internal/match"
	"ausystem/shared/contract"
	"ausystem/shared/normalise"
)

// A unit that G-NAF records both with and without its level: naming the level
// picks the row on it.
func TestUnitAndLevel(t *testing.T) {
	db := fixtureDB(t, "../../testdata/golden_fixture.tsv.gz")
	ctx := context.Background()
	n := normalise.Normalise("Unit 901, Level 9, 140 Bourke St Melbourne")
	resp, err := Resolve(ctx, db, contract.ResolveRequest{Kind: contract.KindAddress, Generate: n.Generate, Score: n.Tokens, Limit: 5})
	if err != nil || len(resp.Candidates) == 0 {
		t.Fatalf("resolve: %v", err)
	}
	var flat, level string
	if err := db.QueryRow(`SELECT flat_number, level_number FROM address WHERE gnaf_pid = ?`,
		resp.Candidates[0].GnafPID).Scan(&flat, &level); err != nil {
		t.Fatal(err)
	}
	if flat != "901" || level != "9" {
		t.Errorf("got unit %q level %q, want unit 901 on level 9", flat, level)
	}
}

// A postcode whose address average lies outside its postal area answers at a
// point inside the area.
func TestPostcodePointInsideArea(t *testing.T) {
	db := fixtureDB(t, "../../testdata/golden_fixture.tsv.gz")
	ctx := context.Background()
	cands, err := postcodeLevel(ctx, db, "3551")
	if err != nil || len(cands) == 0 {
		t.Fatalf("postcodeLevel: %v %v", cands, err)
	}
	p := cands[0].Point
	in, known, err := match.PostcodeContains(ctx, db, "3551", p.Lon, p.Lat)
	if err != nil || !known || !in {
		t.Errorf("3551 answered at %v: inside=%v known=%v err=%v", p, in, known, err)
	}
	hits, err := match.PostcodeAt(ctx, db, p.Lon, p.Lat)
	if err != nil || len(hits) == 0 || hits[0].Postcode != "3551" {
		t.Errorf("PostcodeAt(3551's point) = %v, %v", hits, err)
	}
}

// A PO box postcode answers at its delivery locality with the postal box
// marked; bare, it is a postcode-precision answer at the same place.
func TestPOBoxPostcode(t *testing.T) {
	db := fixtureDB(t, "../../testdata/golden_fixture.tsv.gz")
	ctx := context.Background()
	for _, c := range []struct {
		q, box string
		prec   contract.Precision
	}{
		{"PO Box 9 3001", "PO BOX 9", contract.PrecisionLocality},
		{"3001", "", contract.PrecisionPostcode},
	} {
		n := normalise.Normalise(c.q)
		resp, err := Resolve(ctx, db, contract.ResolveRequest{Kind: contract.KindAddress, Generate: n.Generate, Score: n.Tokens, Limit: 5})
		if err != nil || len(resp.Candidates) == 0 {
			t.Fatalf("%s: %v", c.q, err)
		}
		top := resp.Candidates[0]
		if top.PostalDelivery != c.box || top.Precision != c.prec || top.Point.Lat > -37.7 || top.Point.Lat < -37.9 {
			t.Errorf("%s: %+v", c.q, top)
		}
	}
}
