// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"encoding/json"
	"testing"

	"github.com/hstern/go-subjectid"
)

// TestSETSubjectRoundTrip checks that a SET's Subject field round-trips through
// go-subjectid's own marshaling and parsing. RFC 8417's sub_id is delegated
// wholesale to go-subjectid (RFC 9493); this library only holds the value, so
// the test exercises the delegation boundary rather than re-implementing any
// RFC 9493 parsing.
func TestSETSubjectRoundTrip(t *testing.T) {
	want := subjectid.IssSubID{
		Iss: "https://issuer.example.com/",
		Sub: "145234573",
	}

	s := SET{Subject: want}

	// Marshal the held identifier through go-subjectid's MarshalJSON, then parse
	// it back through go-subjectid's Parse — the path Encode/Parse will take in
	// later building blocks.
	raw, err := json.Marshal(s.Subject)
	if err != nil {
		t.Fatalf("marshal Subject: %v", err)
	}

	got, err := subjectid.Parse(raw)
	if err != nil {
		t.Fatalf("subjectid.Parse: %v", err)
	}

	gotIssSub, ok := got.(*subjectid.IssSubID)
	if !ok {
		t.Fatalf("parsed Subject is %T, want *subjectid.IssSubID", got)
	}
	if *gotIssSub != want {
		t.Errorf("Subject round-trip = %+v, want %+v", *gotIssSub, want)
	}
	if got.Format() != "iss_sub" {
		t.Errorf("Format() = %q, want %q", got.Format(), "iss_sub")
	}
}

// TestSETSubjectAbsent documents that a nil Subject is the "no sub_id" case:
// the claim is OPTIONAL in RFC 8417, and the interface's nil value represents
// its absence without a separate present/absent flag.
func TestSETSubjectAbsent(t *testing.T) {
	var s SET
	if s.Subject != nil {
		t.Errorf("zero SET Subject = %v, want nil", s.Subject)
	}
}
