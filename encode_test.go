// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/hstern/go-subjectid"
)

// TestEncodeFullyPopulated encodes a SET carrying every claim and asserts the
// resulting JSON shape: required claims present, the optional claims emitted
// through their codecs, and the event payload preserved.
func TestEncodeFullyPopulated(t *testing.T) {
	s := &SET{
		Issuer:   "https://issuer.example.com",
		IssuedAt: time.Unix(1700000000, 0).UTC(),
		JWTID:    "abc123",
		Audience: Audience{"https://rp.example.com"},
		Subject: &subjectid.IssSubID{
			Iss: "https://issuer.example.com/",
			Sub: "145234573",
		},
		TransactionID: "txn-42",
		TimeOfEvent:   time.Unix(1699999999, 0).UTC(),
		Events: Events{
			"urn:example:event": json.RawMessage(`{"k":"v"}`),
		},
	}

	out, err := s.Encode()
	if err != nil {
		t.Fatalf("Encode returned error: %v", err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("Encode output is not valid JSON: %v", err)
	}

	wantMembers := map[string]string{
		"iss":    `"https://issuer.example.com"`,
		"iat":    `1700000000`,
		"jti":    `"abc123"`,
		"aud":    `"https://rp.example.com"`,
		"sub_id": `{"format":"iss_sub","iss":"https://issuer.example.com/","sub":"145234573"}`,
		"txn":    `"txn-42"`,
		"toe":    `1699999999`,
		"events": `{"urn:example:event":{"k":"v"}}`,
	}
	if len(got) != len(wantMembers) {
		t.Errorf("encoded object has %d members, want %d: %s", len(got), len(wantMembers), out)
	}
	for name, want := range wantMembers {
		raw, ok := got[name]
		if !ok {
			t.Errorf("encoded object missing member %q", name)
			continue
		}
		if string(raw) != want {
			t.Errorf("member %q = %s, want %s", name, raw, want)
		}
	}
}

// TestEncodeMissingRequiredClaim checks that Encode enforces the §2.2 MUSTs at
// the marshal boundary, returning the matching sentinel for each missing
// required claim via errors.Is.
func TestEncodeMissingRequiredClaim(t *testing.T) {
	base := func() *SET {
		return &SET{
			Issuer:   "https://issuer.example.com",
			IssuedAt: time.Unix(1700000000, 0).UTC(),
			JWTID:    "abc123",
			Events:   Events{"urn:example:event": json.RawMessage(`{}`)},
		}
	}

	tests := []struct {
		name    string
		mutate  func(*SET)
		wantErr error
	}{
		{"missing iss", func(s *SET) { s.Issuer = "" }, ErrMissingIssuer},
		{"missing iat", func(s *SET) { s.IssuedAt = time.Time{} }, ErrMissingIssuedAt},
		{"missing jti", func(s *SET) { s.JWTID = "" }, ErrMissingJWTID},
		{"no events", func(s *SET) { s.Events = nil }, ErrNoEvents},
		{"empty events", func(s *SET) { s.Events = Events{} }, ErrNoEvents},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := base()
			tt.mutate(s)
			out, err := s.Encode()
			if err == nil {
				t.Fatalf("Encode returned nil error and output %s, want %v", out, tt.wantErr)
			}
			if out != nil {
				t.Errorf("Encode returned non-nil output %s alongside an error", out)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Encode error = %v, want errors.Is(_, %v)", err, tt.wantErr)
			}
			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Errorf("Encode error = %v, want a *ValidationError in the chain", err)
			}
		})
	}
}

// TestEncodeReportsEveryMissingClaim checks that Encode surfaces all failing
// MUSTs at once — it delegates to Validate, whose errors.Join carries every
// per-claim failure — rather than stopping at the first.
func TestEncodeReportsEveryMissingClaim(t *testing.T) {
	s := &SET{} // every required claim missing
	_, err := s.Encode()
	if err == nil {
		t.Fatal("Encode returned nil error for an empty SET, want a joined error")
	}
	for _, want := range []error{ErrMissingIssuer, ErrMissingIssuedAt, ErrMissingJWTID, ErrNoEvents} {
		if !errors.Is(err, want) {
			t.Errorf("Encode error does not match %v: %v", want, err)
		}
	}
}

// TestEncodeOmitsAbsentOptionalClaims checks that optional claims left unset are
// omitted from the output entirely — no null, no zero value — so a minimal SET
// emits only its required claims.
func TestEncodeOmitsAbsentOptionalClaims(t *testing.T) {
	s := &SET{
		Issuer:   "https://issuer.example.com",
		IssuedAt: time.Unix(1700000000, 0).UTC(),
		JWTID:    "abc123",
		Events:   Events{"urn:example:event": json.RawMessage(`{}`)},
	}

	out, err := s.Encode()
	if err != nil {
		t.Fatalf("Encode returned error: %v", err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("Encode output is not valid JSON: %v", err)
	}
	for _, optional := range []string{"aud", "sub_id", "txn", "toe"} {
		if _, present := got[optional]; present {
			t.Errorf("optional claim %q present in output, want omitted: %s", optional, out)
		}
	}
	if bytes.Contains(out, []byte("null")) {
		t.Errorf("output contains a null literal, want absent optionals fully omitted: %s", out)
	}
}

// TestEncodeArrayAudience checks that a multi-recipient audience encodes as a
// JSON array (the Audience codec emits a single recipient as a bare string).
func TestEncodeArrayAudience(t *testing.T) {
	s := &SET{
		Issuer:   "https://issuer.example.com",
		IssuedAt: time.Unix(1700000000, 0).UTC(),
		JWTID:    "abc123",
		Audience: Audience{"https://a.example.com", "https://b.example.com"},
		Events:   Events{"urn:example:event": json.RawMessage(`{}`)},
	}
	out, err := s.Encode()
	if err != nil {
		t.Fatalf("Encode returned error: %v", err)
	}
	var got struct {
		Aud json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("Encode output is not valid JSON: %v", err)
	}
	want := `["https://a.example.com","https://b.example.com"]`
	if string(got.Aud) != want {
		t.Errorf("aud = %s, want %s", got.Aud, want)
	}
}

// TestEncodeRoundTripByteStable parses the RFC 8417 §2.1 example, re-encodes it,
// and confirms a second parse deep-equals the first SET. It also pins the
// payload bytes of an unregistered event-type URI: those must survive the
// Parse/Encode round-trip verbatim.
func TestEncodeRoundTripByteStable(t *testing.T) {
	const uri = "https://schemas.example.org/secevent/made-up/event-type/widget-spun"
	payload := `{"spin_count":3,"color":"green","nested":{"b":2,"a":1}}`
	input := `{
		"iss": "https://issuer.example.com",
		"iat": 1700000000,
		"jti": "abc123",
		"aud": ["https://a.example.com","https://b.example.com"],
		"sub_id": {"format":"iss_sub","iss":"https://issuer.example.com/","sub":"145234573"},
		"txn": "txn-42",
		"toe": 1699999999,
		"events": {"` + uri + `": ` + payload + `}
	}`

	first, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("first Parse returned error: %v", err)
	}

	encoded, err := first.Encode()
	if err != nil {
		t.Fatalf("Encode returned error: %v", err)
	}

	// The unregistered event-type URI's payload bytes survive verbatim.
	var shell struct {
		Events map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(encoded, &shell); err != nil {
		t.Fatalf("encoded output is not valid JSON: %v", err)
	}
	if got := string(shell.Events[uri]); got != payload {
		t.Errorf("round-tripped event payload = %s, want %s (must be byte-stable)", got, payload)
	}

	second, err := Parse(encoded)
	if err != nil {
		t.Fatalf("second Parse returned error: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Errorf("round-trip mismatch:\n first  = %#v\n second = %#v", first, second)
	}
}

// TestEncodeRoundTripMinimal checks the round-trip invariant for a SET with no
// optional claims and an empty event payload object (which RFC 8417 §2.2 permits
// — the event-type URI alone can carry meaning): the omitted optionals stay
// absent and a re-parse deep-equals the original.
func TestEncodeRoundTripMinimal(t *testing.T) {
	input := `{"iss":"https://i.example","iat":1700000000,"jti":"x","events":{"urn:example:event":{}}}`

	first, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("first Parse returned error: %v", err)
	}
	encoded, err := first.Encode()
	if err != nil {
		t.Fatalf("Encode returned error: %v", err)
	}
	second, err := Parse(encoded)
	if err != nil {
		t.Fatalf("second Parse returned error: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Errorf("round-trip mismatch:\n first  = %#v\n second = %#v", first, second)
	}
}

// TestMarshalJSONNoValidation checks that the raw codec stays pure: marshaling a
// SET missing required claims succeeds (it is Encode, not MarshalJSON, that
// enforces the MUSTs), keeping json.Marshal liberal for round-trip use.
func TestMarshalJSONNoValidation(t *testing.T) {
	s := SET{} // no required claims
	out, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal of an empty SET returned error: %v, want nil (codec is pure)", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("MarshalJSON output is not valid JSON: %v", err)
	}
	// Required claims are always emitted even when unset; optionals are omitted.
	for _, required := range []string{"iss", "iat", "jti", "events"} {
		if _, ok := got[required]; !ok {
			t.Errorf("required claim %q absent from pure-codec output: %s", required, out)
		}
	}
	for _, optional := range []string{"aud", "sub_id", "txn", "toe"} {
		if _, present := got[optional]; present {
			t.Errorf("optional claim %q present in zero-value output: %s", optional, out)
		}
	}
}
