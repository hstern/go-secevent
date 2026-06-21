// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"encoding/json"
	"testing"
)

// fakeEvent is a minimal test-local Event implementation. The exported,
// reusable fake-event fixture that downstream vocabularies model is a later
// building block; this unexported type exists only to exercise the registry.
type fakeEvent struct {
	uri     string
	Subject string `json:"subject"`
}

var _ Event = fakeEvent{}

func (e fakeEvent) EventTypeURI() string { return e.uri }

// decodeFake builds a decoder closure bound to uri so each test can register a
// distinct event-type URI. The registry is process-wide, so reusing a URI
// across tests would collide; binding the URI per call keeps registrations
// independent and order-insensitive under -shuffle.
func decodeFake(uri string) EventDecoder {
	return func(raw json.RawMessage) (Event, error) {
		ev := fakeEvent{uri: uri}
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, err
		}
		return ev, nil
	}
}

// TestRegisterAndLookup registers a decoder for a fresh URI and confirms
// LookupEventType returns a working decoder for it.
func TestRegisterAndLookup(t *testing.T) {
	const uri = "https://schemas.example.com/secevent/test/event-type/register-and-lookup"
	RegisterEventType(uri, decodeFake(uri))

	decode, ok := LookupEventType(uri)
	if !ok {
		t.Fatalf("LookupEventType(%q) ok = false, want true after registration", uri)
	}
	if decode == nil {
		t.Fatalf("LookupEventType(%q) returned nil decoder with ok = true", uri)
	}

	ev, err := decode(json.RawMessage(`{"subject":"alice"}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := ev.EventTypeURI(); got != uri {
		t.Errorf("EventTypeURI() = %q, want %q", got, uri)
	}
	fe, ok := ev.(fakeEvent)
	if !ok {
		t.Fatalf("decoded event has type %T, want fakeEvent", ev)
	}
	if fe.Subject != "alice" {
		t.Errorf("decoded Subject = %q, want %q", fe.Subject, "alice")
	}
}

// TestLookupUnregistered confirms that looking up a URI no decoder was
// registered for reports ok = false with a nil decoder, rather than panicking
// or erroring. An unknown event type is the expected forward-compatibility
// case, not a fault.
func TestLookupUnregistered(t *testing.T) {
	const uri = "https://schemas.example.com/secevent/test/event-type/never-registered"
	decode, ok := LookupEventType(uri)
	if ok {
		t.Errorf("LookupEventType(%q) ok = true, want false for an unregistered URI", uri)
	}
	if decode != nil {
		t.Errorf("LookupEventType(%q) decoder = non-nil, want nil when ok = false", uri)
	}
}

// TestRegisterDuplicatePanics confirms the duplicate-registration policy:
// registering the same URI twice is an init-time programmer error and panics,
// matching the standard library's database/sql and image registries.
func TestRegisterDuplicatePanics(t *testing.T) {
	const uri = "https://schemas.example.com/secevent/test/event-type/duplicate"
	RegisterEventType(uri, decodeFake(uri))

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("RegisterEventType(%q) twice did not panic", uri)
		}
	}()
	RegisterEventType(uri, decodeFake(uri))
}

// TestRegisterEmptyURIPanics confirms that an empty event-type URI is rejected
// with a panic — a decoder keyed on "" could never match a real events member.
func TestRegisterEmptyURIPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("RegisterEventType with empty URI did not panic")
		}
	}()
	RegisterEventType("", decodeFake("anything"))
}

// TestRegisterNilDecoderPanics confirms that a nil decoder is rejected with a
// panic — a registered nil would crash at lookup time on first use instead of
// at the registration site where the bug lives.
func TestRegisterNilDecoderPanics(t *testing.T) {
	const uri = "https://schemas.example.com/secevent/test/event-type/nil-decoder"
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("RegisterEventType(%q, nil) did not panic", uri)
		}
	}()
	RegisterEventType(uri, nil)
}

// TestRegisterEmptyURITakesPriorityOverNilDecoder documents the validation
// order: an empty URI is reported even when the decoder is also nil, so the
// caller sees the first problem rather than a misleading nil-decoder message.
func TestRegisterEmptyURITakesPriorityOverNilDecoder(t *testing.T) {
	defer func() {
		r := recover()
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("recover() = %v (%T), want a string panic value", r, r)
		}
		if want := "secevent: RegisterEventType: empty event-type URI"; msg != want {
			t.Errorf("panic message = %q, want %q", msg, want)
		}
	}()
	RegisterEventType("", nil)
}
