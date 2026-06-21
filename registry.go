// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"encoding/json"
	"sync"
)

// Event is the contract a typed security-event payload satisfies. An event
// vocabulary that wants its payloads decoded into a concrete Go type registers
// a decoder for its event-type URI (see RegisterEventType) and returns values
// implementing this interface from that decoder.
//
// EventTypeURI reports the event-type URI under which the event is carried in a
// SET's events claim (RFC 8417 §2.2): it is the events map key for this event.
// The returned value identifies the event type, not a particular occurrence —
// every value of a given concrete type returns the same URI, and that URI is
// the one its decoder was registered under. The library defines no concrete
// event types itself; event vocabularies supply them.
type Event interface {
	// EventTypeURI returns the event-type URI that keys this event within a
	// SET's events claim (RFC 8417 §2.2).
	EventTypeURI() string
}

// EventDecoder decodes the raw payload bytes of a single events-claim member
// into a typed Event. The bytes are the verbatim JSON value stored for the
// event-type URI the decoder is registered under (an Events map value). A
// decoder reports a non-nil error if the payload is malformed for its event
// type; it must not mutate the bytes it is given.
type EventDecoder func(json.RawMessage) (Event, error)

// eventRegistry holds the process-wide event-type URI to decoder mapping. It is
// guarded by an RWMutex so concurrent LookupEventType calls (the read-heavy
// path, taken once per decoded event) proceed in parallel while the rare
// RegisterEventType writes (typically at package-init time) serialize.
var eventRegistry = struct {
	sync.RWMutex
	decoders map[string]EventDecoder
}{decoders: make(map[string]EventDecoder)}

// RegisterEventType registers decode as the decoder for the given event-type
// URI, making LookupEventType (and the typed-access helpers built on it) able
// to turn that event's raw payload bytes into a typed Event. An event
// vocabulary calls this once per event type it defines, customarily from a
// package init function so a side-effect import wires the whole vocabulary in.
//
// Registration is process-wide and permanent: there is no unregister. The uri
// must be the same string the event's EventTypeURI method returns.
//
// RegisterEventType panics on programmer error, mirroring the standard
// library's own registries (database/sql.Register, image.RegisterFormat): a
// duplicate registration, an empty uri, or a nil decode are all init-time bugs
// in the calling program, not runtime conditions a caller could recover from.
// Specifically it panics if uri is empty, if decode is nil, or if uri is
// already registered. Two vocabularies that genuinely need to claim the same
// URI is itself the bug the panic surfaces.
func RegisterEventType(uri string, decode EventDecoder) {
	if uri == "" {
		panic("secevent: RegisterEventType: empty event-type URI")
	}
	if decode == nil {
		panic("secevent: RegisterEventType: nil decoder for " + uri)
	}

	eventRegistry.Lock()
	defer eventRegistry.Unlock()

	if _, dup := eventRegistry.decoders[uri]; dup {
		panic("secevent: RegisterEventType: event-type URI already registered: " + uri)
	}
	eventRegistry.decoders[uri] = decode
}

// LookupEventType returns the decoder registered for the given event-type URI.
// ok reports whether a decoder is registered; when ok is false the returned
// decoder is nil. An unregistered URI is not an error — it is the expected case
// for an event type this build does not know about, whose payload stays raw and
// round-trips byte-stably.
func LookupEventType(uri string) (decode EventDecoder, ok bool) {
	eventRegistry.RLock()
	defer eventRegistry.RUnlock()

	decode, ok = eventRegistry.decoders[uri]
	return decode, ok
}
