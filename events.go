// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"encoding/json"
	"fmt"
)

// Events is the RFC 8417 §2.2 "events" claim: a JSON object whose members map
// an event-type URI to that event's payload. It is the defining claim of a
// SET — a SET MUST carry at least one event (RFC 8417 §2.2), and that
// non-empty requirement is enforced at the marshal boundary, not here.
//
// Each member value is held as a json.RawMessage rather than a decoded Go
// value. This preserves the payload bytes verbatim, so an event-type URI this
// build does not recognize survives a decode/encode round-trip unchanged — the
// forward-compatibility contract CAEP, RISC, and other vocabularies depend on.
// Typed access to a known event is provided by the Typed method, which decodes
// a member through the event-type registry; Raw exposes the underlying bytes.
//
// json.RawMessage is used instead of map[string]any deliberately: interop
// scenarios pin exact JSON bytes, and a map reorders its keys on every encode.
type Events map[string]json.RawMessage

// Raw returns the underlying event-type-URI to payload-bytes map. The returned
// map is the container's own backing map, not a copy; callers that mutate it
// mutate the Events. It is provided for reading individual event payloads by
// their event-type URI without decoding the whole container.
func (e Events) Raw() map[string]json.RawMessage {
	return e
}

// Len reports the number of events in the container. A SET with zero events is
// invalid (RFC 8417 §2.2); Len lets callers check that MUST without reaching
// into the map.
func (e Events) Len() int {
	return len(e)
}

// Typed decodes the single events-claim member keyed by uri into a typed Event,
// using the decoder registered for uri (see RegisterEventType). It distinguishes
// four cases, and the returned bool is true in exactly one of them:
//
//   - uri is not a member of the events claim: returns (nil, false, nil). The
//     event simply is not present.
//   - uri is present but no decoder is registered for it (an event type this
//     build does not recognize): returns (nil, false, nil). The member stays
//     raw — reach it via Raw()[uri] — preserving the byte-stable round-trip that
//     unknown event types depend on. An unregistered URI is the expected case,
//     not an error.
//   - uri is present and its registered decoder succeeds: returns
//     (event, true, nil). This is the only case in which ok is true and a
//     non-nil Event is returned.
//   - uri is present and its registered decoder fails: returns (nil, false,
//     err), where err wraps the decoder's error with the event-type URI for
//     context. Inspect it with errors.Is or errors.As.
//
// To walk every event in the claim — decoding the recognized ones and leaving
// the rest raw — range over the keys of Raw and call Typed per URI:
//
//	for uri := range e.Raw() {
//		event, ok, err := e.Typed(uri)
//		switch {
//		case err != nil:
//			// the registered decoder rejected the payload
//		case ok:
//			// event is the typed value
//		default:
//			// no decoder registered; e.Raw()[uri] holds the raw bytes
//		}
//	}
func (e Events) Typed(uri string) (Event, bool, error) {
	raw, present := e[uri]
	if !present {
		return nil, false, nil
	}

	decode, registered := LookupEventType(uri)
	if !registered {
		return nil, false, nil
	}

	event, err := decode(raw)
	if err != nil {
		return nil, false, fmt.Errorf("secevent: decode event %s: %w", uri, err)
	}
	return event, true, nil
}
