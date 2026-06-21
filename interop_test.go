// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hstern/go-subjectid"
)

// The interop fixtures are Shared-Signals-shaped SETs: the decoded claims-set
// bytes a JOSE/transport layer would hand to Parse after verifying the JWS. The
// events are keyed by the real public OpenID event-type URIs that CAEP and RISC
// define, so the tests exercise the exact consumer flow a Shared Signals
// receiver runs — Parse the claims set, Validate it, decode the event types it
// recognizes through the registry, and leave the rest raw and byte-stable. The
// library defines no CAEP/RISC payload types itself (those are downstream
// vocabularies); the decoders below are test-local fakes standing in for them.
//
// These URIs are the public CAEP 1.0 / RISC event-type identifiers under
// schemas.openid.net. They are distinct from the schemas.example.com test URIs
// registered elsewhere in this package's test binary, so registering decoders
// for them in init does not collide with the process-wide registry (which has
// no unregister and panics on a duplicate).
//
// These tests scope themselves to the interop scenario — real CAEP/RISC SET
// shapes, the multi-event decode-known/leave-rest partition, and byte-stable
// round-trips. The registry mechanics they build on (unregistered-present,
// absent, and decoder-error paths) are exercised directly in events_test.go and
// are not re-tested here.
const (
	caepSessionRevokedURI   = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	caepCredentialChangeURI = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	riscAccountDisabledURI  = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
)

// caepSessionRevoked is a test-local stand-in for a CAEP session-revoked event
// payload. It models only the fields the fixtures carry; a real CAEP vocabulary
// would define the full typed event. The event-type URI is fixed per type, as
// the Event contract requires.
type caepSessionRevoked struct {
	EventTimestamp   int64           `json:"event_timestamp"`
	InitiatingEntity string          `json:"initiating_entity,omitempty"`
	ReasonAdmin      json.RawMessage `json:"reason_admin,omitempty"`
}

var _ Event = caepSessionRevoked{}

func (caepSessionRevoked) EventTypeURI() string { return caepSessionRevokedURI }

// riscAccountDisabled is a test-local stand-in for a RISC account-disabled event
// payload. RISC events name their subject inside the event payload (an RFC 9493
// Subject Identifier object), distinct from a top-level sub_id, so the fake
// decodes the subject through go-subjectid to mirror that real shape.
type riscAccountDisabled struct {
	Subject json.RawMessage `json:"subject"`
	Reason  string          `json:"reason,omitempty"`
}

var _ Event = riscAccountDisabled{}

func (riscAccountDisabled) EventTypeURI() string { return riscAccountDisabledURI }

// init registers the CAEP/RISC interop decoders once for the whole package test
// binary. The registry is process-wide with no unregister and panics on a
// duplicate URI, so registration lives in init rather than a test body where
// -count or -shuffle could re-run it. The credential-change URI is deliberately
// left unregistered: the multi_event fixture carries it so the consumer flow can
// demonstrate "decode the events I know, leave the rest raw".
func init() {
	RegisterEventType(caepSessionRevokedURI, func(raw json.RawMessage) (Event, error) {
		var ev caepSessionRevoked
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, err
		}
		return ev, nil
	})
	RegisterEventType(riscAccountDisabledURI, func(raw json.RawMessage) (Event, error) {
		var ev riscAccountDisabled
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, err
		}
		return ev, nil
	})
}

// readInteropFixture loads a Shared-Signals-shaped fixture from testdata by
// basename.
func readInteropFixture(t *testing.T, name string) []byte {
	t.Helper()

	path := filepath.Join("testdata", name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return data
}

// TestInteropCAEPSessionRevoked drives the single-CAEP-event consumer flow:
// Parse the claims set, confirm it validates, decode the session-revoked event
// through the registry into the typed value, and confirm the top-level sub_id
// the receiver keys revocation by is the expected RFC 9493 iss_sub pair.
func TestInteropCAEPSessionRevoked(t *testing.T) {
	t.Parallel()

	payload := readInteropFixture(t, "caep_session_revoked")

	set, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse(caep_session_revoked.json): %v", err)
	}
	if err := set.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for a complete SET", err)
	}

	wantSubject := subjectid.IssSubID{Iss: "https://idp.example.com/", Sub: "user-7f3e2a"}
	got, isIssSub := set.Subject.(*subjectid.IssSubID)
	if !isIssSub {
		t.Fatalf("Subject is %T, want *subjectid.IssSubID", set.Subject)
	}
	if *got != wantSubject {
		t.Errorf("Subject = %+v, want %+v", *got, wantSubject)
	}

	event, ok, err := set.Events.Typed(caepSessionRevokedURI)
	if err != nil {
		t.Fatalf("Events.Typed(%q): %v", caepSessionRevokedURI, err)
	}
	if !ok {
		t.Fatalf("Events.Typed(%q) ok = false, want true for the registered CAEP URI", caepSessionRevokedURI)
	}
	revoked, isRevoked := event.(caepSessionRevoked)
	if !isRevoked {
		t.Fatalf("decoded event is %T, want caepSessionRevoked", event)
	}
	if revoked.EventTimestamp != 1615305500 {
		t.Errorf("EventTimestamp = %d, want 1615305500", revoked.EventTimestamp)
	}
	if revoked.InitiatingEntity != "policy" {
		t.Errorf("InitiatingEntity = %q, want %q", revoked.InitiatingEntity, "policy")
	}
}

// TestInteropRISCAccountDisabled drives the single-RISC-event consumer flow and
// confirms the RISC-style per-event subject (an RFC 9493 Subject Identifier
// nested inside the event payload, not at the SET top level) decodes through
// go-subjectid.
func TestInteropRISCAccountDisabled(t *testing.T) {
	t.Parallel()

	payload := readInteropFixture(t, "risc_account_disabled")

	set, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse(risc_account_disabled.json): %v", err)
	}
	if err := set.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for a complete SET", err)
	}

	// RISC names the subject inside the event, so the SET carries no top-level
	// sub_id.
	if set.Subject != nil {
		t.Errorf("Subject = %v, want nil (RISC carries the subject inside the event)", set.Subject)
	}

	event, ok, err := set.Events.Typed(riscAccountDisabledURI)
	if err != nil {
		t.Fatalf("Events.Typed(%q): %v", riscAccountDisabledURI, err)
	}
	if !ok {
		t.Fatalf("Events.Typed(%q) ok = false, want true for the registered RISC URI", riscAccountDisabledURI)
	}
	disabled, isDisabled := event.(riscAccountDisabled)
	if !isDisabled {
		t.Fatalf("decoded event is %T, want riscAccountDisabled", event)
	}
	if disabled.Reason != "hijacking" {
		t.Errorf("Reason = %q, want %q", disabled.Reason, "hijacking")
	}

	subject, err := subjectid.Parse(disabled.Subject)
	if err != nil {
		t.Fatalf("decode per-event subject: %v", err)
	}
	issSub, isIssSub := subject.(*subjectid.IssSubID)
	if !isIssSub {
		t.Fatalf("per-event subject is %T, want *subjectid.IssSubID", subject)
	}
	want := subjectid.IssSubID{Iss: "https://idp.example.com/", Sub: "user-7f3e2a"}
	if *issSub != want {
		t.Errorf("per-event subject = %+v, want %+v", *issSub, want)
	}
}

// TestInteropMultiEventDecodeKnownLeaveRest is the headline Shared Signals
// receiver pattern: a SET carrying several events, of which the receiver decodes
// the types it recognizes (CAEP session-revoked, RISC account-disabled) and
// leaves the rest raw and byte-stable (a CAEP credential-change for which this
// build registers no decoder). It walks the events exactly as a receiver would —
// ranging Raw and calling Typed per URI — and asserts the partition.
func TestInteropMultiEventDecodeKnownLeaveRest(t *testing.T) {
	t.Parallel()

	payload := readInteropFixture(t, "multi_event")

	set, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse(multi_event.json): %v", err)
	}
	if err := set.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for a complete SET", err)
	}
	if got := set.Events.Len(); got != 3 {
		t.Fatalf("Events.Len() = %d, want 3", got)
	}

	typed := make(map[string]Event)
	raw := make(map[string]json.RawMessage)
	for uri := range set.Events.Raw() {
		event, ok, err := set.Events.Typed(uri)
		switch {
		case err != nil:
			t.Fatalf("Events.Typed(%q): %v", uri, err)
		case ok:
			typed[uri] = event
		default:
			raw[uri] = set.Events.Raw()[uri]
		}
	}

	// The two registered URIs decode to typed values.
	if _, ok := typed[caepSessionRevokedURI].(caepSessionRevoked); !ok {
		t.Errorf("CAEP session-revoked did not decode to caepSessionRevoked: %#v", typed[caepSessionRevokedURI])
	}
	if _, ok := typed[riscAccountDisabledURI].(riscAccountDisabled); !ok {
		t.Errorf("RISC account-disabled did not decode to riscAccountDisabled: %#v", typed[riscAccountDisabledURI])
	}
	if len(typed) != 2 {
		t.Errorf("typed events = %d, want 2 (the recognized CAEP/RISC types)", len(typed))
	}

	// The unregistered URI stays raw and reachable through Raw.
	if len(raw) != 1 {
		t.Fatalf("raw events = %d, want 1 (the unrecognized credential-change)", len(raw))
	}
	if _, ok := raw[caepCredentialChangeURI]; !ok {
		t.Errorf("unregistered URI %q not left raw", caepCredentialChangeURI)
	}
}

// TestInteropFixturesRoundTripByteStable confirms every interop fixture survives
// a Parse → Encode round-trip with each event payload reproduced byte-for-byte —
// including the unregistered credential-change in multi_event. Encode compacts
// each json.RawMessage member to its canonical form, so the comparison is
// against the compacted payload; the bytes (and member order within each
// payload) must be unchanged, and a second Encode of the re-parsed SET must be a
// fixed point. This is the open-extension guarantee CAEP/RISC rely on.
func TestInteropFixturesRoundTripByteStable(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"caep_session_revoked", "risc_account_disabled", "multi_event"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			payload := readInteropFixture(t, name)

			set, err := Parse(payload)
			if err != nil {
				t.Fatalf("Parse(%s.json): %v", name, err)
			}

			encoded, err := set.Encode()
			if err != nil {
				t.Fatalf("Encode(): %v", err)
			}

			for uri, p := range set.Events.Raw() {
				want := compactJSON(t, p)
				if !bytes.Contains(encoded, want) {
					t.Errorf("event %q payload not reproduced verbatim in Encode output\n  payload: %s\n  encoded: %s",
						uri, want, encoded)
				}
			}

			reparsed, err := Parse(encoded)
			if err != nil {
				t.Fatalf("Parse(Encode()): %v", err)
			}
			reEncoded, err := reparsed.Encode()
			if err != nil {
				t.Fatalf("Encode() of re-parsed SET: %v", err)
			}
			if !bytes.Equal(reEncoded, encoded) {
				t.Errorf("Parse → Encode is not a fixed point\n  first:  %s\n  second: %s", encoded, reEncoded)
			}

			for uri, p := range set.Events.Raw() {
				want := compactJSON(t, p)
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
		})
	}
}
