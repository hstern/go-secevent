// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hstern/go-subjectid"
)

// conformanceEventURI is the event-type URI of the single_aud.json fixture's
// event. The conformance suite registers a decoder for it so one fixture
// exercises the typed-decode path through the registry (RegisterEventType /
// Events.Typed), alongside the unregistered URIs the other fixtures carry to
// prove the raw byte-stable round-trip.
const conformanceEventURI = "https://schemas.example.com/secevent/example/event-type/typed"

// conformanceEvent is the test-local typed event the conformance suite decodes
// the single_aud.json payload into. It mirrors the registry_test.go fake-event
// shape: a minimal Event whose only payload field is a subject string.
type conformanceEvent struct {
	Subject string `json:"subject"`
}

var _ Event = conformanceEvent{}

func (conformanceEvent) EventTypeURI() string { return conformanceEventURI }

// init registers the conformance event decoder once for the whole package test
// binary. The registry is process-wide with no unregister, and registering a
// URI twice panics, so registration lives in init rather than in a test body
// where -count or a second test could re-run it.
func init() {
	RegisterEventType(conformanceEventURI, func(raw json.RawMessage) (Event, error) {
		var ev conformanceEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, err
		}
		return ev, nil
	})
}

// conformanceCase describes one golden fixture and the SET fields a correct
// Parse must recover from it. The want* fields name only the claims the fixture
// actually carries; absent optional claims are checked against their zero value
// by the assertions below.
type conformanceCase struct {
	name string // fixture basename under testdata/, without .json

	wantIssuer   string
	wantIssuedAt int64 // iat, seconds since epoch
	wantJWTID    string
	wantAudience []string // nil means the aud claim is absent
	wantTxn      string
	wantTimeOf   int64 // toe, seconds since epoch; 0 means absent

	// wantSubject, when non-empty, is the (iss, sub) pair the fixture's
	// RFC 9493 iss_sub sub_id must decode to. The zero value means no sub_id.
	wantSubject subjectid.IssSubID

	// wantEventURIs is the exact set of event-type URIs the events claim must
	// contain, each mapped to the typed value the registry should produce for
	// it. A nil value means the URI is unregistered and must stay raw —
	// Events.Typed returns (nil, false, nil) for it.
	wantEvents map[string]Event
}

func conformanceCases() []conformanceCase {
	return []conformanceCase{
		{
			name:         "scim_create",
			wantIssuer:   "https://scim.example.com",
			wantIssuedAt: 1458496404,
			wantJWTID:    "4d3559ec67504aaba65d40b0363faad8",
			wantAudience: []string{
				"https://scim.example.com/Feeds/98d52461098511e4",
				"https://scim.example.com/Feeds/5d7604516b1d08641d",
			},
			wantEvents: map[string]Event{
				"urn:ietf:params:scim:event:create": nil,
			},
		},
		{
			name:         "minimal",
			wantIssuer:   "https://issuer.example.com",
			wantIssuedAt: 1458496404,
			wantJWTID:    "minimal-set-0000000000000000",
			wantEvents: map[string]Event{
				"https://schemas.example.com/secevent/example/event-type/minimal": nil,
			},
		},
		{
			name:         "txn_toe_subid",
			wantIssuer:   "https://transmitter.example.com",
			wantIssuedAt: 1493856000,
			wantJWTID:    "synthetic-txn-toe-subid-0001",
			wantAudience: []string{
				"https://receiver.example.com/feed/a",
				"https://receiver.example.com/feed/b",
			},
			wantTxn:    "8675309-jenny",
			wantTimeOf: 1493855000,
			wantSubject: subjectid.IssSubID{
				Iss: "https://issuer.example.com/",
				Sub: "145234573",
			},
			wantEvents: map[string]Event{
				"https://schemas.example.com/secevent/example/event-type/state-change": nil,
			},
		},
		{
			name:         "single_aud",
			wantIssuer:   "https://transmitter.example.com",
			wantIssuedAt: 1493856000,
			wantJWTID:    "synthetic-single-aud-0001",
			wantAudience: []string{"https://receiver.example.com"},
			wantEvents: map[string]Event{
				conformanceEventURI: conformanceEvent{Subject: "alice"},
			},
		},
	}
}

// TestConformanceFixtures drives every golden fixture through the full
// consumer/producer cycle: Parse the spec-derived claims-set bytes, assert the
// decoded SET fields against the spec figure, confirm Validate accepts the
// fixture, Encode it back, and confirm the round-trip is stable — both for the
// typed SET fields (a re-Parse deep-equals the first) and, byte-for-byte, for
// every event payload (the open-extension guarantee CAEP/RISC rely on).
func TestConformanceFixtures(t *testing.T) {
	for _, tc := range conformanceCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fixture := readFixture(t, tc.name)

			set, err := Parse(fixture)
			if err != nil {
				t.Fatalf("Parse(%s.json): %v", tc.name, err)
			}

			assertSETFields(t, set, tc)

			if err := set.Validate(); err != nil {
				t.Fatalf("Validate() of spec fixture %s.json = %v, want nil", tc.name, err)
			}

			assertTypedEvents(t, set, tc)

			assertEventPayloadsSourceOrdered(t, fixture, set)

			encoded, err := set.Encode()
			if err != nil {
				t.Fatalf("Encode(): %v", err)
			}

			assertEventPayloadsVerbatim(t, set, encoded)
			assertRoundTripStable(t, set, encoded, tc)
		})
	}
}

// assertSETFields checks the scalar and structural claims a correct Parse must
// recover from the fixture.
func assertSETFields(t *testing.T, set *SET, tc conformanceCase) {
	t.Helper()

	if set.Issuer != tc.wantIssuer {
		t.Errorf("Issuer = %q, want %q", set.Issuer, tc.wantIssuer)
	}
	if got := set.IssuedAt.UTC(); !got.Equal(time.Unix(tc.wantIssuedAt, 0).UTC()) {
		t.Errorf("IssuedAt = %v, want unix %d", got, tc.wantIssuedAt)
	}
	if set.JWTID != tc.wantJWTID {
		t.Errorf("JWTID = %q, want %q", set.JWTID, tc.wantJWTID)
	}

	if !audienceEqual(set.Audience, tc.wantAudience) {
		t.Errorf("Audience = %v, want %v", set.Audience, tc.wantAudience)
	}

	if set.TransactionID != tc.wantTxn {
		t.Errorf("TransactionID = %q, want %q", set.TransactionID, tc.wantTxn)
	}

	if tc.wantTimeOf == 0 {
		if !set.TimeOfEvent.IsZero() {
			t.Errorf("TimeOfEvent = %v, want zero (toe absent)", set.TimeOfEvent)
		}
	} else if got := set.TimeOfEvent.UTC(); !got.Equal(time.Unix(tc.wantTimeOf, 0).UTC()) {
		t.Errorf("TimeOfEvent = %v, want unix %d", got, tc.wantTimeOf)
	}

	assertSubject(t, set, tc)

	if got := set.Events.Len(); got != len(tc.wantEvents) {
		t.Errorf("Events.Len() = %d, want %d", got, len(tc.wantEvents))
	}
	for uri := range tc.wantEvents {
		if _, present := set.Events.Raw()[uri]; !present {
			t.Errorf("events claim missing expected URI %q", uri)
		}
	}
}

// assertSubject checks the sub_id delegation: an empty wantSubject means the
// claim is absent and Subject must be nil; otherwise the held identifier must
// be the expected RFC 9493 iss_sub pair.
func assertSubject(t *testing.T, set *SET, tc conformanceCase) {
	t.Helper()

	if tc.wantSubject == (subjectid.IssSubID{}) {
		if set.Subject != nil {
			t.Errorf("Subject = %v, want nil (sub_id absent)", set.Subject)
		}
		return
	}

	got, ok := set.Subject.(subjectid.IssSubID)
	if !ok {
		t.Fatalf("Subject is %T, want subjectid.IssSubID", set.Subject)
	}
	if got != tc.wantSubject {
		t.Errorf("Subject = %+v, want %+v", got, tc.wantSubject)
	}
}

// assertTypedEvents checks the registry path: a URI mapped to a non-nil typed
// value in the case must decode to that value through Events.Typed, and a URI
// mapped to nil must stay raw (Typed reports ok = false with no error).
func assertTypedEvents(t *testing.T, set *SET, tc conformanceCase) {
	t.Helper()

	for uri, want := range tc.wantEvents {
		event, ok, err := set.Events.Typed(uri)
		if err != nil {
			t.Fatalf("Events.Typed(%q): %v", uri, err)
		}

		if want == nil {
			if ok {
				t.Errorf("Events.Typed(%q) ok = true, want false for an unregistered URI", uri)
			}
			if _, present := set.Events.Raw()[uri]; !present {
				t.Errorf("unregistered event %q not retained as raw", uri)
			}
			continue
		}

		if !ok {
			t.Errorf("Events.Typed(%q) ok = false, want true for a registered URI", uri)
			continue
		}
		if event != want {
			t.Errorf("Events.Typed(%q) = %#v, want %#v", uri, event, want)
		}
	}
}

// assertEventPayloadsSourceOrdered confirms that the event payload bytes Parse
// stored are the fixture's own bytes in source order, with no key reordering.
// It compacts both the fixture's events object and the stored payload and
// asserts the stored payload appears within the compacted source — the property
// json.RawMessage buys over map[string]any, which would reorder keys on encode.
func assertEventPayloadsSourceOrdered(t *testing.T, fixture []byte, set *SET) {
	t.Helper()

	compactFixture := compactJSON(t, fixture)
	for uri, payload := range set.Events.Raw() {
		compactPayload := compactJSON(t, payload)
		if !bytes.Contains(compactFixture, compactPayload) {
			t.Errorf("event %q payload not found in source order within the fixture; keys may have been reordered\n  payload: %s",
				uri, compactPayload)
		}
	}
}

// assertEventPayloadsVerbatim confirms that every event payload appears
// byte-for-byte in the Encode output. Encode re-serializes the claims-set
// framing compactly — and a json.RawMessage member is compacted to its
// canonical form on the way out — so the comparison is against the compacted
// payload. The bytes must survive unchanged, including for the unregistered
// event-type URIs: the byte-stable open-extension contract CAEP/RISC rely on.
func assertEventPayloadsVerbatim(t *testing.T, set *SET, encoded []byte) {
	t.Helper()

	for uri, payload := range set.Events.Raw() {
		want := compactJSON(t, payload)
		if !bytes.Contains(encoded, want) {
			t.Errorf("event %q payload not reproduced verbatim in Encode output\n  payload: %s\n  encoded: %s",
				uri, want, encoded)
		}
	}
}

// assertRoundTripStable confirms that re-Parsing the Encode output yields a SET
// whose fields match the first Parse and whose event payload bytes are now a
// fixed point: a second Encode of the re-parsed SET reproduces them identically.
// Because Encode compacts each payload, the first Encode's output is already
// canonical, so the re-parsed payload bytes equal the encoded payload exactly.
func assertRoundTripStable(t *testing.T, set *SET, encoded []byte, tc conformanceCase) {
	t.Helper()

	reparsed, err := Parse(encoded)
	if err != nil {
		t.Fatalf("Parse(Encode()): %v", err)
	}

	assertSETFields(t, reparsed, tc)

	reEncoded, err := reparsed.Encode()
	if err != nil {
		t.Fatalf("Encode() of re-parsed SET: %v", err)
	}
	if !bytes.Equal(reEncoded, encoded) {
		t.Errorf("Parse → Encode is not a fixed point\n  first:  %s\n  second: %s", encoded, reEncoded)
	}

	for uri, payload := range set.Events.Raw() {
		want := compactJSON(t, payload)
		got, present := reparsed.Events.Raw()[uri]
		if !present {
			t.Errorf("event %q dropped across the round-trip", uri)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("event %q payload changed across the round-trip\n  before: %s\n  after:  %s",
				uri, want, got)
		}
	}
}

// compactJSON returns the canonical compact form of valid JSON bytes, with no
// insignificant whitespace and member order preserved. It fails the test if the
// input is not valid JSON.
func compactJSON(t *testing.T, raw []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		t.Fatalf("compact JSON %s: %v", raw, err)
	}
	return buf.Bytes()
}

// audienceEqual reports whether a decoded Audience equals the expected slice,
// treating nil and empty as the absent-audience case.
func audienceEqual(got Audience, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// readFixture loads a golden claims-set fixture from testdata by basename.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()

	path := filepath.Join("testdata", name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return data
}
