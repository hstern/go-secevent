// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import "encoding/json"

// Events is the RFC 8417 §2.2 "events" claim: a JSON object whose members map
// an event-type URI to that event's payload. It is the defining claim of a
// SET — a SET MUST carry at least one event (RFC 8417 §2.2), and that
// non-empty requirement is enforced at the marshal boundary, not here.
//
// Each member value is held as a json.RawMessage rather than a decoded Go
// value. This preserves the payload bytes verbatim, so an event-type URI this
// build does not recognize survives a decode/encode round-trip unchanged — the
// forward-compatibility contract CAEP, RISC, and other vocabularies depend on.
// Typed access to a known event is provided through the event-type registry
// (a later building block); this type is the raw container only.
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
