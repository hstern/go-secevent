// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"encoding/json"
	"testing"
	"time"

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

// TestSubjectAsValueForm checks that SubjectAs and IssSub read the value form
// of the subject — the shape a SET built in Go naturally carries.
func TestSubjectAsValueForm(t *testing.T) {
	want := subjectid.IssSubID{Iss: "https://issuer.example.com/", Sub: "145234573"}
	s := SET{Subject: want}

	if got, ok := SubjectAs[subjectid.IssSubID](&s); !ok || got != want {
		t.Errorf("SubjectAs[IssSubID] = (%+v, %v), want (%+v, true)", got, ok, want)
	}
	if got, ok := s.IssSub(); !ok || got != want {
		t.Errorf("IssSub() = (%+v, %v), want (%+v, true)", got, ok, want)
	}
}

// TestSubjectAsPointerForm checks that SubjectAs and IssSub also read the
// pointer form — the shape Parse produces, since go-subjectid's registry
// constructors return pointers. This is the asymmetry the accessor absorbs.
func TestSubjectAsPointerForm(t *testing.T) {
	want := subjectid.IssSubID{Iss: "https://issuer.example.com/", Sub: "145234573"}
	s := SET{Subject: &want}

	if got, ok := SubjectAs[subjectid.IssSubID](&s); !ok || got != want {
		t.Errorf("SubjectAs[IssSubID] = (%+v, %v), want (%+v, true)", got, ok, want)
	}
	if got, ok := s.IssSub(); !ok || got != want {
		t.Errorf("IssSub() = (%+v, %v), want (%+v, true)", got, ok, want)
	}
}

// TestSubjectAsRoundTrip is the acceptance round-trip: a SET built in Go with
// the value form of the subject, encoded and parsed back, yields an equal
// subject through the accessor — even though Parse hands back the pointer form.
// A consumer never has to write a pointer/value type switch.
func TestSubjectAsRoundTrip(t *testing.T) {
	want := subjectid.IssSubID{Iss: "https://issuer.example.com/", Sub: "145234573"}
	s := SET{
		Issuer:   "https://issuer.example.com/",
		IssuedAt: time.Unix(1699999999, 0).UTC(),
		JWTID:    "jti-round-trip",
		Subject:  want, // value form on the way in
		Events: Events{
			"urn:example:event": json.RawMessage(`{"k":"v"}`),
		},
	}

	out, err := s.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	parsed, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Sanity: the parsed subject is the pointer form, which is exactly why the
	// accessor is needed.
	if _, ok := parsed.Subject.(*subjectid.IssSubID); !ok {
		t.Fatalf("parsed Subject is %T, want *subjectid.IssSubID", parsed.Subject)
	}

	got, ok := parsed.IssSub()
	if !ok {
		t.Fatal("IssSub() on parsed SET = ok false, want true")
	}
	if got != want {
		t.Errorf("round-trip subject = %+v, want %+v", got, want)
	}
}

// TestSubjectAsMismatch covers the not-found branches: an absent subject, a nil
// receiver, and a subject of a different format than the one requested.
func TestSubjectAsMismatch(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		var s SET
		if got, ok := s.IssSub(); ok {
			t.Errorf("IssSub() on empty SET = (%+v, true), want ok false", got)
		}
	})

	t.Run("nil receiver", func(t *testing.T) {
		if got, ok := SubjectAs[subjectid.IssSubID](nil); ok {
			t.Errorf("SubjectAs(nil) = (%+v, true), want ok false", got)
		}
	})

	t.Run("typed nil subject", func(t *testing.T) {
		// A typed nil pointer in the interface is not == nil, so it slips past
		// the s.Subject == nil guard and reaches the reflection path; the
		// !rv.IsNil() check is what keeps rv.Elem() from panicking.
		var p *subjectid.IssSubID
		s := SET{Subject: p}
		if got, ok := SubjectAs[subjectid.IssSubID](&s); ok {
			t.Errorf("SubjectAs with typed-nil Subject = (%+v, true), want ok false", got)
		}
		if got, ok := s.IssSub(); ok {
			t.Errorf("IssSub with typed-nil Subject = (%+v, true), want ok false", got)
		}
	})

	t.Run("wrong format", func(t *testing.T) {
		s := SET{Subject: subjectid.EmailID{Email: "user@example.com"}}
		if got, ok := s.IssSub(); ok {
			t.Errorf("IssSub() on email subject = (%+v, true), want ok false", got)
		}
		// The matching format still resolves.
		if got, ok := SubjectAs[subjectid.EmailID](&s); !ok || got.Email != "user@example.com" {
			t.Errorf("SubjectAs[EmailID] = (%+v, %v), want the email, true", got, ok)
		}
	})
}
