// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"bytes"
	"encoding/json"
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
