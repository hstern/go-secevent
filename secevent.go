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

import "time"

// SpecVersion is the RFC 8417 — Security Event Token (SET) version this build
// implements.
const SpecVersion = "RFC 8417"

// SET is a decoded RFC 8417 Security Event Token claims set. It is the typed
// envelope that carries one or more security-event payloads; the events
// themselves are decoded through the event-type registry.
//
// The audience (aud), subject identifier (sub_id), and events claims are added
// by later building blocks; this type currently models the scalar claims of
// §2.2.
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

	// TransactionID (txn) optionally correlates the SET with related events or
	// requests. OPTIONAL (RFC 8417 §2.2).
	TransactionID string

	// TimeOfEvent (toe) is the time at which the event(s) conveyed by the SET
	// occurred, which may differ from IssuedAt. Carried as an RFC 7519
	// NumericDate. OPTIONAL (RFC 8417 §2.2).
	TimeOfEvent time.Time
}
