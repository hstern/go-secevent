// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"encoding/json"

	"github.com/hstern/go-subjectid"
)

// Encode marshals the SET into the JSON claims-set payload of a Security Event
// Token (RFC 8417 §2.2), enforcing the required-claim MUSTs at the marshal
// boundary.
//
// Encode is the producer-side counterpart of Parse and the strict half of the
// library's "liberal unmarshal, strict marshal" contract: where Parse decodes
// whatever the wire gave it, Encode refuses to emit a structurally incomplete
// SET. It first calls Validate and returns that error unchanged when any of the
// §2.2 MUSTs (iss, iat, jti present; events present and non-empty) is unmet, so
// the caller branches on the same *ValidationError values and sentinels
// (ErrMissingIssuer, ErrMissingIssuedAt, ErrMissingJWTID, ErrNoEvents) that
// Validate documents. The presence checks are not duplicated here; Validate is
// the single source of truth for them.
//
// Encode does not sign. It emits the decoded claims-set bytes that a separate
// JOSE/transport layer base64url-encodes and wraps in a JWS — the same boundary
// Parse consumes from. The bytes are compact (no insignificant whitespace).
// Optional claims that are unset (aud, sub_id, txn, toe) are omitted entirely
// rather than emitted as JSON null or a zero value, and an unregistered
// event-type URI's payload bytes are reproduced verbatim, so a Parse/Encode
// round-trip is byte-stable.
func (s *SET) Encode() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

// marshalSET is the on-the-wire shape used to encode a SET. It is the marshal
// counterpart of wireSET: where wireSET decodes with value-typed codecs that
// tolerate absent claims, marshalSET uses pointer fields for the optional date
// and audience claims so that encoding/json's omitempty drops them when unset
// instead of emitting a zero NumericDate or a null audience. The required
// claims (iss, iat, jti, events) carry no omitempty and are always emitted;
// enforcing that they are meaningfully populated is Encode's job via Validate,
// not MarshalJSON's, which stays a pure symmetric codec so json.Marshal remains
// liberal.
type marshalSET struct {
	Issuer        string                      `json:"iss"`
	IssuedAt      NumericDate                 `json:"iat"`
	JWTID         string                      `json:"jti"`
	Audience      *Audience                   `json:"aud,omitempty"`
	SubjectID     subjectid.SubjectIdentifier `json:"sub_id,omitempty"`
	TransactionID string                      `json:"txn,omitempty"`
	TimeOfEvent   *NumericDate                `json:"toe,omitempty"`
	Events        Events                      `json:"events"`
}

// MarshalJSON encodes a SET claims set per RFC 8417 §2.2. It is a pure symmetric
// codec performing no validation, so it is the exact inverse of UnmarshalJSON
// and a decoded SET round-trips through it cleanly: the date claims are emitted
// as RFC 7519 NumericDate seconds, aud through the Audience codec (a single
// recipient as a bare string, otherwise an array), sub_id through go-subjectid's
// RFC 9493 marshaler, and each event payload as its preserved raw bytes.
//
// The required claims (iss, iat, jti, events) are always present in the output;
// the optional claims (aud, sub_id, txn, toe) are omitted when unset rather than
// emitted as null or a zero value, so "no audience" and "audience is the empty
// string" stay distinguishable across a round-trip. Required-claim presence is
// enforced by Encode, not here.
func (s SET) MarshalJSON() ([]byte, error) {
	m := marshalSET{
		Issuer:        s.Issuer,
		IssuedAt:      *NewNumericDate(s.IssuedAt),
		JWTID:         s.JWTID,
		SubjectID:     s.Subject,
		TransactionID: s.TransactionID,
		Events:        s.Events,
	}
	if s.Audience != nil {
		m.Audience = &s.Audience
	}
	if !s.TimeOfEvent.IsZero() {
		m.TimeOfEvent = NewNumericDate(s.TimeOfEvent)
	}
	return json.Marshal(m)
}
