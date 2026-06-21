// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestEventsByteStableRoundTrip is the load-bearing forward-compatibility
// check: an events object keyed by an event-type URI this build does not
// recognize, carrying a non-trivial payload, must survive a full
// decode/re-encode of the Events container with that payload's bytes unchanged
// (RFC 8417 §2.2). Because the member values are json.RawMessage, each payload
// is emitted verbatim — nested object key order, member order, and number
// formatting all preserved. A map[string]any container would reorder the keys
// of the payload and break this contract.
func TestEventsByteStableRoundTrip(t *testing.T) {
	const uri = "https://schemas.example.com/secevent/unknown/event-type/widget-frobnicated"

	// Member-order- and whitespace-sensitive payload: a map[string]any decode
	// would reorder these keys, breaking byte-stability.
	payload := json.RawMessage(`{"z_last":1,"a_first":"x","nested":{"b":[3,2,1],"a":true}}`)

	// A second, known-shape member alongside the unknown one, so the container
	// holds more than a single event across the round-trip.
	const knownURI = "urn:ietf:params:scim:event:create"
	knownPayload := json.RawMessage(`{"ref":"https://example.com/Users/44"}`)

	input := []byte(`{"` + uri + `":` + string(payload) + `,"` + knownURI + `":` + string(knownPayload) + `}`)

	var ev Events
	if err := json.Unmarshal(input, &ev); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got := ev.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}

	// The unknown-URI payload bytes are preserved verbatim on decode.
	got, ok := ev.Raw()[uri]
	if !ok {
		t.Fatalf("Raw() missing key %q", uri)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload bytes changed on decode:\n got %s\nwant %s", got, payload)
	}

	// A full re-encode of the container reproduces each payload's bytes
	// unchanged. (encoding/json sorts the top-level member keys; byte-stability
	// is a per-payload guarantee, which is what interop pins on.)
	encoded, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var reDecoded Events
	if err := json.Unmarshal(encoded, &reDecoded); err != nil {
		t.Fatalf("re-Unmarshal: %v", err)
	}
	if !bytes.Equal(reDecoded.Raw()[uri], payload) {
		t.Errorf("unknown-URI payload changed across round-trip:\n got %s\nwant %s",
			reDecoded.Raw()[uri], payload)
	}
	if !bytes.Equal(reDecoded.Raw()[knownURI], knownPayload) {
		t.Errorf("known-URI payload changed across round-trip:\n got %s\nwant %s",
			reDecoded.Raw()[knownURI], knownPayload)
	}
}

// TestEventsEmpty documents the zero and empty cases. An empty events object
// decodes to an Events of length zero; a SET with such a container is invalid
// per §2.2, but enforcing that MUST is the validator's job, not the container's
// — Events itself simply reports the count.
func TestEventsEmpty(t *testing.T) {
	var ev Events
	if err := json.Unmarshal([]byte(`{}`), &ev); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got := ev.Len(); got != 0 {
		t.Errorf("Len() of empty events = %d, want 0", got)
	}

	var nilEvents Events
	if got := nilEvents.Len(); got != 0 {
		t.Errorf("Len() of nil Events = %d, want 0", got)
	}
	if nilEvents.Raw() != nil {
		t.Errorf("Raw() of nil Events = %v, want nil", nilEvents.Raw())
	}
}

// TestEventsRawMutationVisible documents that Raw returns the backing map, so a
// mutation through the returned map is visible on the Events. This is the
// "read access to the raw map" contract; callers that need isolation copy.
func TestEventsRawMutationVisible(t *testing.T) {
	ev := Events{"a": json.RawMessage(`1`)}
	ev.Raw()["b"] = json.RawMessage(`2`)
	if ev.Len() != 2 {
		t.Errorf("Len() after Raw() mutation = %d, want 2", ev.Len())
	}
}

// TestTypedRegistered covers the one case in which Typed returns a typed value:
// the URI is present in the events claim and a decoder is registered for it. A
// distinct, freshly-registered URI keeps the process-wide registry state
// independent of other tests under -shuffle (fakeEvent / decodeFake are the
// test-local fixtures from registry_test.go).
func TestTypedRegistered(t *testing.T) {
	const uri = "https://schemas.example.com/secevent/test/event-type/typed-registered"
	RegisterEventType(uri, decodeFake(uri))

	ev := Events{uri: json.RawMessage(`{"subject":"alice"}`)}

	event, ok, err := ev.Typed(uri)
	if err != nil {
		t.Fatalf("Typed(%q) err = %v, want nil", uri, err)
	}
	if !ok {
		t.Fatalf("Typed(%q) ok = false, want true for a registered, decodable member", uri)
	}
	if event == nil {
		t.Fatalf("Typed(%q) returned nil event with ok = true", uri)
	}
	if got := event.EventTypeURI(); got != uri {
		t.Errorf("decoded event EventTypeURI() = %q, want %q", got, uri)
	}
	fe, isFake := event.(fakeEvent)
	if !isFake {
		t.Fatalf("decoded event has type %T, want fakeEvent", event)
	}
	if fe.Subject != "alice" {
		t.Errorf("decoded Subject = %q, want %q", fe.Subject, "alice")
	}
}

// TestTypedUnregisteredPresent covers a present member whose URI has no
// registered decoder: an event type this build does not recognize. Typed
// reports (nil, false, nil) — not an error — and the raw bytes stay reachable
// through Raw, preserving the byte-stable-unknown-events guarantee.
func TestTypedUnregisteredPresent(t *testing.T) {
	const uri = "https://schemas.example.com/secevent/test/event-type/typed-unregistered"
	payload := json.RawMessage(`{"opaque":["x",1,true],"order":"preserved"}`)
	ev := Events{uri: payload}

	event, ok, err := ev.Typed(uri)
	if err != nil {
		t.Fatalf("Typed(%q) err = %v, want nil for an unregistered URI", uri, err)
	}
	if ok {
		t.Errorf("Typed(%q) ok = true, want false for an unregistered URI", uri)
	}
	if event != nil {
		t.Errorf("Typed(%q) event = %v, want nil when ok = false", uri, event)
	}
	if got := ev.Raw()[uri]; !bytes.Equal(got, payload) {
		t.Errorf("raw payload after Typed changed:\n got %s\nwant %s", got, payload)
	}
}

// TestTypedAbsent covers a URI that is not a member of the events claim at all:
// Typed reports (nil, false, nil), the same not-typed signal as an unregistered
// present member, distinguished by the member's absence from Raw.
func TestTypedAbsent(t *testing.T) {
	const present = "https://schemas.example.com/secevent/test/event-type/typed-absent-present"
	const absent = "https://schemas.example.com/secevent/test/event-type/typed-absent-missing"
	ev := Events{present: json.RawMessage(`{}`)}

	event, ok, err := ev.Typed(absent)
	if err != nil {
		t.Fatalf("Typed(%q) err = %v, want nil for an absent URI", absent, err)
	}
	if ok {
		t.Errorf("Typed(%q) ok = true, want false for an absent URI", absent)
	}
	if event != nil {
		t.Errorf("Typed(%q) event = %v, want nil for an absent URI", absent, event)
	}
	if _, ok := ev.Raw()[absent]; ok {
		t.Errorf("absent URI %q unexpectedly present in Raw()", absent)
	}
}

// TestTypedNilReceiver documents that Typed is safe on a nil Events: indexing a
// nil map yields not-present, so any URI reports (nil, false, nil) rather than
// panicking. This matches Len and Raw, which also tolerate a nil receiver.
func TestTypedNilReceiver(t *testing.T) {
	var ev Events
	event, ok, err := ev.Typed("https://schemas.example.com/secevent/test/event-type/nil-recv")
	if event != nil || ok || err != nil {
		t.Errorf("nil Events Typed = (%v, %v, %v), want (nil, false, nil)", event, ok, err)
	}
}

// errDecodeFailed is a sentinel a failing decoder returns so the test can match
// the wrapped error with errors.Is — confirming Typed wraps with %w rather than
// flattening the decoder's error.
var errDecodeFailed = errors.New("fake decoder rejected payload")

// TestTypedDecoderError covers a present, registered member whose decoder
// fails: Typed returns (nil, false, err), and err wraps the decoder's error
// (matchable with errors.Is) with the event-type URI for context.
func TestTypedDecoderError(t *testing.T) {
	const uri = "https://schemas.example.com/secevent/test/event-type/typed-decoder-error"
	RegisterEventType(uri, func(json.RawMessage) (Event, error) {
		return nil, errDecodeFailed
	})

	ev := Events{uri: json.RawMessage(`{"subject":"bob"}`)}

	event, ok, err := ev.Typed(uri)
	if err == nil {
		t.Fatalf("Typed(%q) err = nil, want a wrapped decode error", uri)
	}
	if ok {
		t.Errorf("Typed(%q) ok = true, want false when the decoder fails", uri)
	}
	if event != nil {
		t.Errorf("Typed(%q) event = %v, want nil when the decoder fails", uri, event)
	}
	if !errors.Is(err, errDecodeFailed) {
		t.Errorf("Typed error does not wrap the decoder error: %v", err)
	}
	if !strings.Contains(err.Error(), uri) {
		t.Errorf("Typed error %q does not mention the event-type URI %q", err, uri)
	}
}

// TestTypedDecoderErrorAsJSON confirms the wrapped error also unwraps to a
// concrete error type via errors.As, using a decoder that surfaces the
// json.Unmarshal failure on malformed payload bytes (decodeFake's behavior).
func TestTypedDecoderErrorAsJSON(t *testing.T) {
	const uri = "https://schemas.example.com/secevent/test/event-type/typed-decoder-error-as"
	RegisterEventType(uri, decodeFake(uri))

	// "subject" is declared as a string on fakeEvent; a number is a type error.
	ev := Events{uri: json.RawMessage(`{"subject":12345}`)}

	_, ok, err := ev.Typed(uri)
	if ok || err == nil {
		t.Fatalf("Typed(%q) = (_, %v, %v), want (nil, false, non-nil)", uri, ok, err)
	}
	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		t.Errorf("Typed error does not unwrap to *json.UnmarshalTypeError: %v", err)
	}
}

// TestTypedIterationOverRaw exercises the documented iteration pattern: ranging
// Raw and calling Typed per URI decodes the registered events and leaves the
// unknown ones raw, in a single pass over a mixed container.
func TestTypedIterationOverRaw(t *testing.T) {
	const knownURI = "https://schemas.example.com/secevent/test/event-type/iter-known"
	const unknownURI = "https://schemas.example.com/secevent/test/event-type/iter-unknown"
	RegisterEventType(knownURI, decodeFake(knownURI))

	unknownPayload := json.RawMessage(`{"still":"raw"}`)
	ev := Events{
		knownURI:   json.RawMessage(`{"subject":"carol"}`),
		unknownURI: unknownPayload,
	}

	typed := make(map[string]Event)
	rawLeft := make(map[string]json.RawMessage)
	for uri := range ev.Raw() {
		event, ok, err := ev.Typed(uri)
		switch {
		case err != nil:
			t.Fatalf("Typed(%q) err = %v, want nil", uri, err)
		case ok:
			typed[uri] = event
		default:
			rawLeft[uri] = ev.Raw()[uri]
		}
	}

	if len(typed) != 1 || typed[knownURI] == nil {
		t.Errorf("typed = %v, want exactly the known URI decoded", typed)
	}
	if len(rawLeft) != 1 || !bytes.Equal(rawLeft[unknownURI], unknownPayload) {
		t.Errorf("rawLeft = %v, want exactly the unknown URI left raw", rawLeft)
	}
}
