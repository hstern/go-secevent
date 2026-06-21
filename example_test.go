// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	secevent "github.com/hstern/go-secevent"
	subjectid "github.com/hstern/go-subjectid"
)

// ExampleParse decodes an already-verified, already-base64url-decoded SET
// claims set, validates the RFC 8417 §2.2 MUSTs, and walks its events —
// leaving an event type this build does not recognize as raw bytes.
func ExampleParse() {
	// The bytes a JOSE/transport layer hands over after verifying the JWS and
	// base64url-decoding the payload. Parse never sees the compact JWS itself.
	// The event-type URI below is one this build has no decoder for, so it
	// stays raw — exactly how a forward-compatible consumer treats an event
	// vocabulary it has not imported.
	payload := []byte(`{
		"iss": "https://idp.example.com/",
		"iat": 1615305600,
		"jti": "set-0001",
		"aud": "https://receiver.example.com/",
		"events": {
			"https://example.com/secevent/parse-example/event": {"k": "v"}
		}
	}`)

	set, err := secevent.Parse(payload)
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	if err := set.Validate(); err != nil {
		fmt.Println("invalid:", err)
		return
	}

	fmt.Println("issuer:", set.Issuer)
	fmt.Println("events:", set.Events.Len())

	// Walk every event. With no decoder registered for this URI, Typed reports
	// (nil, false, nil) and the payload stays reachable as raw bytes via Raw.
	for uri := range set.Events.Raw() {
		event, ok, err := set.Events.Typed(uri)
		switch {
		case err != nil:
			fmt.Println("decode error:", err)
		case ok:
			fmt.Printf("typed: %s\n", event.EventTypeURI())
		default:
			fmt.Printf("raw: %s = %s\n", uri, set.Events.Raw()[uri])
		}
	}

	// Output:
	// issuer: https://idp.example.com/
	// events: 1
	// raw: https://example.com/secevent/parse-example/event = {"k": "v"}
}

// Example_encode builds a SET from typed Go values and encodes it to the JSON
// claims-set payload a signer would wrap in a JWS. Encode enforces the §2.2
// required-claim MUSTs at the marshal boundary.
func Example_encode() {
	subject, err := subjectid.Parse([]byte(
		`{"format":"iss_sub","iss":"https://idp.example.com/","sub":"user-7f3e2a"}`,
	))
	if err != nil {
		fmt.Println("subject:", err)
		return
	}

	set := &secevent.SET{
		Issuer:   "https://idp.example.com/",
		IssuedAt: time.Unix(1615305600, 0),
		JWTID:    "set-0002",
		Audience: secevent.Audience{"https://receiver.example.com/"},
		Subject:  subject,
		Events: secevent.Events{
			"https://schemas.openid.net/secevent/caep/event-type/session-revoked": json.RawMessage(`{"initiating_entity":"policy"}`),
		},
	}

	payload, err := set.Encode()
	if err != nil {
		fmt.Println("encode:", err)
		return
	}
	fmt.Printf("%s\n", payload)

	// Output:
	// {"iss":"https://idp.example.com/","iat":1615305600,"jti":"set-0002","aud":"https://receiver.example.com/","sub_id":{"format":"iss_sub","iss":"https://idp.example.com/","sub":"user-7f3e2a"},"events":{"https://schemas.openid.net/secevent/caep/event-type/session-revoked":{"initiating_entity":"policy"}}}
}

// ExampleSET_IssSub reads the typed sub_id of a parsed SET. IssSub returns the
// iss_sub value directly regardless of whether the held identifier is the value
// or pointer form, so a consumer never has to handle the distinction itself.
func ExampleSET_IssSub() {
	// Verified, base64url-decoded claims-set bytes carrying an iss_sub subject.
	payload := []byte(`{
		"iss": "https://idp.example.com/",
		"iat": 1615305600,
		"jti": "set-0003",
		"sub_id": {"format": "iss_sub", "iss": "https://idp.example.com/", "sub": "user-7f3e2a"},
		"events": {
			"https://example.com/secevent/iss-sub-example/event": {}
		}
	}`)

	set, err := secevent.Parse(payload)
	if err != nil {
		fmt.Println("parse:", err)
		return
	}

	sub, ok := set.IssSub()
	if !ok {
		fmt.Println("subject is absent or not iss_sub")
		return
	}
	fmt.Println("iss:", sub.Iss)
	fmt.Println("sub:", sub.Sub)

	// Output:
	// iss: https://idp.example.com/
	// sub: user-7f3e2a
}

// docExampleEventURI is the event-type URI this example's event vocabulary
// claims. It is deliberately unique to this documentation example so it never
// collides with the CAEP/RISC URIs or other test fixtures registered elsewhere
// in the test binary — the registry has no unregister.
const docExampleEventURI = "https://example.com/secevent/doc-example/event"

// docExampleEvent is a minimal typed event payload, the kind an event
// vocabulary (CAEP, RISC, …) defines and registers a decoder for. It satisfies
// the secevent.Event interface by reporting its event-type URI.
type docExampleEvent struct {
	Reason string `json:"reason"`
}

func (docExampleEvent) EventTypeURI() string { return docExampleEventURI }

// Example_registerEventType shows the registry seam end to end: implement the
// Event interface for a vocabulary's payload, register a decoder for its
// event-type URI, then recover the typed value from a parsed SET via Typed.
func Example_registerEventType() {
	// An event vocabulary wires its decoder in once, customarily from an init
	// function so a side-effect import registers the whole vocabulary.
	secevent.RegisterEventType(docExampleEventURI, func(raw json.RawMessage) (secevent.Event, error) {
		var e docExampleEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, err
		}
		return e, nil
	})

	set, err := secevent.Parse([]byte(`{
		"iss": "https://idp.example.com/",
		"iat": 1615305600,
		"jti": "set-0003",
		"events": {
			"https://example.com/secevent/doc-example/event": {"reason": "policy"}
		}
	}`))
	if err != nil {
		fmt.Println("parse:", err)
		return
	}

	event, ok, err := set.Events.Typed(docExampleEventURI)
	if err != nil {
		fmt.Println("typed:", err)
		return
	}
	if !ok {
		fmt.Println("no decoder registered")
		return
	}

	fmt.Printf("decoded %T: reason=%q\n", event, event.(docExampleEvent).Reason)

	// Output:
	// decoded secevent_test.docExampleEvent: reason="policy"
}

// Example_registerEventType_unknown contrasts the registered case above: an
// event-type URI with no registered decoder is not an error. Typed reports
// (nil, false, nil) and the payload stays reachable as raw bytes, the
// byte-stable forward-compatibility contract unknown event types depend on.
func Example_registerEventType_unknown() {
	set, err := secevent.Parse([]byte(`{
		"iss": "https://idp.example.com/",
		"iat": 1615305600,
		"jti": "set-0004",
		"events": {
			"https://example.com/secevent/never-registered/event": {"k": "v"},
			"https://example.com/secevent/also-unknown/event": {"k": "w"}
		}
	}`))
	if err != nil {
		fmt.Println("parse:", err)
		return
	}

	// Sort the URIs for deterministic output; map iteration order is random.
	for _, uri := range slices.Sorted(maps.Keys(set.Events.Raw())) {
		_, ok, err := set.Events.Typed(uri)
		fmt.Printf("%s ok=%t err=%v raw=%s\n", uri, ok, err, set.Events.Raw()[uri])
	}

	// Output:
	// https://example.com/secevent/also-unknown/event ok=false err=<nil> raw={"k": "w"}
	// https://example.com/secevent/never-registered/event ok=false err=<nil> raw={"k": "v"}
}

// Example_validateBoundary shows the §4 boundary in error form: Validate
// reports the missing §2.2 MUSTs and only those, matchable with errors.Is —
// it never asserts anything about authentication or authorization.
func Example_validateBoundary() {
	set, _ := secevent.Parse([]byte(`{"iat":1615305600,"events":{}}`))
	err := set.Validate()

	fmt.Println("missing iss:  ", errors.Is(err, secevent.ErrMissingIssuer))
	fmt.Println("missing jti:  ", errors.Is(err, secevent.ErrMissingJWTID))
	fmt.Println("no events:    ", errors.Is(err, secevent.ErrNoEvents))
	fmt.Println("iat present:  ", !errors.Is(err, secevent.ErrMissingIssuedAt))

	// Output:
	// missing iss:   true
	// missing jti:   true
	// no events:     true
	// iat present:   true
}
