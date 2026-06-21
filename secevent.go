// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

// Package secevent implements RFC 8417 — Security Event Token (SET): the
// typed SET claims-set envelope (iss, iat, jti, aud, sub_id, txn, toe, and
// the required events claim) plus an event-type registry through which event
// vocabularies (such as CAEP and RISC) plug in typed decoders.
//
// The library operates on the decoded claims-set bytes: a SET is a JWT whose
// payload conveys that a security event occurred. Verifying the surrounding
// JWS and producing those bytes is a separate concern (a JOSE/transport
// layer); this package parses, validates, and encodes the claims set itself.
// A SET is not an access token and must never be treated as an authorization
// or authentication assertion (RFC 8417 §4).
package secevent

import (
	"time"

	"github.com/hstern/go-subjectid"
)

// SpecVersion is the RFC 8417 — Security Event Token (SET) version this build
// implements.
const SpecVersion = "RFC 8417"

// SET is a decoded RFC 8417 Security Event Token claims set. It is the typed
// envelope that carries one or more security-event payloads; the events
// themselves are decoded through the event-type registry.
//
// This type models the §2.2 claims as Go fields. Parse decodes the claims set
// across the JSON boundary into a SET, Validate checks the §2.2/§2.3
// required-claim MUSTs, and Encode marshals a SET back to the claims-set bytes.
type SET struct {
	// Issuer (iss) identifies the principal that issued the SET. REQUIRED
	// (RFC 8417 §2.2).
	Issuer string

	// IssuedAt (iat) is the time at which the SET was issued, carried on the
	// wire as an RFC 7519 NumericDate. REQUIRED (RFC 8417 §2.2).
	IssuedAt time.Time

	// JWTID (jti) is a string uniquely identifying the SET; recipients use it
	// to detect duplicate deliveries. REQUIRED (RFC 8417 §2.2).
	JWTID string

	// Audience (aud) identifies the intended recipient(s) of the SET. Carried
	// on the wire as either a single string or an array of strings (RFC 7519
	// §4.1.3); an absent or null claim is no audience. OPTIONAL (RFC 8417
	// §2.2).
	Audience Audience

	// Subject (sub_id) identifies the subject of the security event as an
	// RFC 9493 Subject Identifier. RFC 8417 predates RFC 9493 and names the
	// subject with the bare JWT sub claim; the modern Shared Signals suite that
	// this library serves uses sub_id instead. Parsing and validating the
	// identifier is delegated to go-subjectid; this package only holds the
	// field. A nil Subject means the claim is absent. OPTIONAL (RFC 8417 §2.2,
	// RFC 9493 §3).
	//
	// Parse yields the value form of the identifier (for example
	// subjectid.IssSubID), the same form a SET built in Go naturally holds; a
	// SET may also be hand-built with the pointer form (*subjectid.IssSubID).
	// Use SubjectAs or IssSub to read the concrete subject without handling
	// both forms by hand.
	Subject subjectid.SubjectIdentifier

	// TransactionID (txn) optionally correlates the SET with related events or
	// requests. OPTIONAL (RFC 8417 §2.2).
	TransactionID string

	// TimeOfEvent (toe) is the time at which the event(s) conveyed by the SET
	// occurred, which may differ from IssuedAt. Carried as an RFC 7519
	// NumericDate. OPTIONAL (RFC 8417 §2.2).
	TimeOfEvent time.Time

	// Events is the SET's payload: a map of event-type URI to the raw bytes of
	// that event's payload. It is REQUIRED and MUST contain at least one member
	// (RFC 8417 §2.2); that MUST is enforced at the marshal boundary, not on
	// this field. Unknown event-type URIs round-trip byte-stably.
	Events Events
}
