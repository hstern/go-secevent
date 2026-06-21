// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hstern/go-subjectid"
)

// scimExample is the canonical single-event SET claims set from RFC 8417 §2.1
// (SCIM provisioning). It carries every required claim plus an array audience
// and a single event whose payload is a non-trivial object.
const scimExample = `{
  "iss": "https://scim.example.com",
  "iat": 1458496404,
  "jti": "4d3559ec67504aaba65d40b0363faad8",
  "aud": [
    "https://scim.example.com/Feeds/98d52461098511e4",
    "https://scim.example.com/Feeds/5d7604516b1d08641d"
  ],
  "events": {
    "urn:ietf:params:scim:event:create": {
      "ref": "https://scim.example.com/Users/44f6142df96bd6ab61e7521d9",
      "attributes": ["id", "name", "userName", "password", "emails"]
    }
  }
}`

func TestParseSCIMExample(t *testing.T) {
	set, err := Parse([]byte(scimExample))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if got, want := set.Issuer, "https://scim.example.com"; got != want {
		t.Errorf("Issuer = %q, want %q", got, want)
	}
	if got, want := set.IssuedAt.UTC(), time.Unix(1458496404, 0).UTC(); !got.Equal(want) {
		t.Errorf("IssuedAt = %v, want %v", got, want)
	}
	if got, want := set.JWTID, "4d3559ec67504aaba65d40b0363faad8"; got != want {
		t.Errorf("JWTID = %q, want %q", got, want)
	}

	wantAud := Audience{
		"https://scim.example.com/Feeds/98d52461098511e4",
		"https://scim.example.com/Feeds/5d7604516b1d08641d",
	}
	if got := set.Audience; len(got) != len(wantAud) || got[0] != wantAud[0] || got[1] != wantAud[1] {
		t.Errorf("Audience = %v, want %v", got, wantAud)
	}

	// Claims absent from the §2.1 example stay at their zero values (Postel).
	if !set.TimeOfEvent.IsZero() {
		t.Errorf("TimeOfEvent = %v, want zero", set.TimeOfEvent)
	}
	if set.TransactionID != "" {
		t.Errorf("TransactionID = %q, want empty", set.TransactionID)
	}
	if set.Subject != nil {
		t.Errorf("Subject = %v, want nil", set.Subject)
	}

	if got := set.Events.Len(); got != 1 {
		t.Fatalf("Events.Len() = %d, want 1", got)
	}
}

// TestParsePreservesUnknownEventBytes checks the forward-compatibility contract:
// an event-type URI this build does not recognise keeps its payload bytes
// verbatim, so a later Encode can reproduce them unchanged.
func TestParsePreservesUnknownEventBytes(t *testing.T) {
	const uri = "https://schemas.example.org/secevent/made-up/event-type/widget-spun"
	payload := `{"spin_count":3,"color":"green","nested":{"b":2,"a":1}}`
	input := `{
		"iss": "https://issuer.example.com",
		"iat": 1700000000,
		"jti": "abc123",
		"events": {"` + uri + `": ` + payload + `}
	}`

	set, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	raw, ok := set.Events.Raw()[uri]
	if !ok {
		t.Fatalf("event %q not present in Events", uri)
	}
	if got := string(raw); got != payload {
		t.Errorf("event payload bytes = %s, want %s (must survive byte-stably)", got, payload)
	}
}

func TestParseLiberalMissingRequiredClaims(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty object", `{}`},
		{"only events", `{"events":{"urn:example:event":{}}}`},
		{"missing iss and jti", `{"iat":1700000000,"events":{"urn:example:event":{}}}`},
		{"empty events object", `{"iss":"https://i.example","iat":1700000000,"jti":"x","events":{}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse([]byte(tt.input)); err != nil {
				t.Errorf("Parse(%s) returned error %v, want nil (decode is liberal)", tt.input, err)
			}
		})
	}
}

func TestParseToleratesUnknownTopLevelClaims(t *testing.T) {
	input := `{
		"iss": "https://issuer.example.com",
		"iat": 1700000000,
		"jti": "abc123",
		"sub": "discouraged-bare-subject",
		"some_future_claim": {"anything": true},
		"events": {"urn:example:event": {}}
	}`
	set, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if set.Issuer != "https://issuer.example.com" {
		t.Errorf("Issuer = %q, want issuer.example.com", set.Issuer)
	}
}

func TestParseSubID(t *testing.T) {
	input := `{
		"iss": "https://issuer.example.com",
		"iat": 1700000000,
		"jti": "abc123",
		"sub_id": {
			"format": "iss_sub",
			"iss": "https://issuer.example.com/",
			"sub": "145234573"
		},
		"toe": 1699999999,
		"txn": "txn-42",
		"events": {"urn:example:event": {}}
	}`
	set, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if set.Subject == nil {
		t.Fatalf("Subject is nil, want a decoded iss_sub identifier")
	}
	if got, want := set.Subject.Format(), "iss_sub"; got != want {
		t.Errorf("Subject.Format() = %q, want %q", got, want)
	}
	iss, ok := set.Subject.(subjectid.IssSubID)
	if !ok {
		t.Fatalf("Subject has type %T, want subjectid.IssSubID", set.Subject)
	}
	if iss.Iss != "https://issuer.example.com/" || iss.Sub != "145234573" {
		t.Errorf("Subject = {Iss:%q Sub:%q}, want {iss/ 145234573}", iss.Iss, iss.Sub)
	}

	if got, want := set.TimeOfEvent.UTC(), time.Unix(1699999999, 0).UTC(); !got.Equal(want) {
		t.Errorf("TimeOfEvent = %v, want %v", got, want)
	}
	if set.TransactionID != "txn-42" {
		t.Errorf("TransactionID = %q, want txn-42", set.TransactionID)
	}
}

func TestParseSubIDNullIsNoSubject(t *testing.T) {
	input := `{"iss":"https://i.example","iat":1700000000,"jti":"x","sub_id":null,"events":{"urn:example:event":{}}}`
	set, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if set.Subject != nil {
		t.Errorf("Subject = %v, want nil for sub_id:null", set.Subject)
	}
}

func TestParseSubIDInvalidIsError(t *testing.T) {
	// A sub_id object with no "format" member is rejected by go-subjectid.
	input := `{"iss":"https://i.example","iat":1700000000,"jti":"x","sub_id":{"iss":"x"},"events":{"urn:example:event":{}}}`
	if _, err := Parse([]byte(input)); err == nil {
		t.Fatal("Parse returned nil error for a sub_id with no format member, want error")
	}
}

func TestParseMalformedJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"truncated object", `{"iss":"https://i.example"`},
		{"trailing garbage", `{"iss":"x"}trailing`},
		{"not an object", `42`},
		{"empty input", ``},
		{"aud wrong type", `{"aud":123}`},
		{"iat wrong type", `{"iat":"not-a-number"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse([]byte(tt.input)); err == nil {
				t.Errorf("Parse(%q) returned nil error, want a decode error", tt.input)
			}
		})
	}
}

// TestParseAudSingleString confirms the string-or-array aud codec is reached
// through Parse: a bare string decodes to a one-element Audience.
func TestParseAudSingleString(t *testing.T) {
	input := `{"iss":"https://i.example","iat":1700000000,"jti":"x","aud":"https://rp.example","events":{"urn:example:event":{}}}`
	set, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(set.Audience) != 1 || set.Audience[0] != "https://rp.example" {
		t.Errorf("Audience = %v, want single-element [https://rp.example]", set.Audience)
	}
}

// TestParseRoundTripThroughJSONUnmarshal documents that SET satisfies
// json.Unmarshaler, so a SET nested inside another structure decodes too.
func TestParseSETImplementsUnmarshaler(t *testing.T) {
	var s SET
	if err := json.Unmarshal([]byte(`{"iss":"https://i.example","events":{"urn:example:event":{}}}`), &s); err != nil {
		t.Fatalf("json.Unmarshal into SET returned error: %v", err)
	}
	if s.Issuer != "https://i.example" {
		t.Errorf("Issuer = %q, want i.example", s.Issuer)
	}
}
