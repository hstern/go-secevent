// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/hstern/go-subjectid"
)

// Parse decodes the claims set of a Security Event Token from already-verified,
// already-base64url-decoded JSON bytes into a SET (RFC 8417 §2.2).
//
// Parse is the consumer-side entry point of the library. It expects the decoded
// JWT claims set, not a compact JWS: verifying the surrounding signature and
// base64url-decoding the payload belong to a separate JOSE/transport layer,
// which hands the resulting claims-set bytes here. There is consequently no
// typ, alg, or kid handling in this package (RFC 8417 §2.3 explicit typing is
// the signer's concern).
//
// Decoding is liberal, following Postel's law: Parse tolerates a claims set
// that omits required claims (iss, iat, jti, events), and it ignores unknown
// top-level claims. It does not validate the §2.2/§2.3 MUSTs — that is the job
// of Validate, kept separate so a consumer can inspect a structurally incomplete
// SET before deciding what to do with it. Parse returns an error only when the
// input is not well-formed JSON or a recognised claim has the wrong shape (for
// example, a sub_id object go-subjectid rejects).
//
// Event payloads are preserved as raw bytes, so an event-type URI this build
// does not recognise survives a Parse/Encode round-trip byte-for-byte.
func Parse(payload []byte) (*SET, error) {
	var s SET
	if err := json.Unmarshal(payload, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// wireSET is the on-the-wire shape of a SET claims set. It mirrors the §2.2
// claims with their JSON member names and the wire-level codecs (NumericDate
// for the date claims, the string-or-array Audience for aud), then SET's
// UnmarshalJSON maps it onto the typed SET fields. sub_id is held as raw bytes
// here and dispatched through go-subjectid only when present, so an absent or
// null sub_id leaves SET.Subject nil rather than erroring.
type wireSET struct {
	Issuer        string          `json:"iss"`
	IssuedAt      NumericDate     `json:"iat"`
	JWTID         string          `json:"jti"`
	Audience      Audience        `json:"aud"`
	SubjectID     json.RawMessage `json:"sub_id"`
	TransactionID string          `json:"txn"`
	TimeOfEvent   NumericDate     `json:"toe"`
	Events        Events          `json:"events"`
}

// UnmarshalJSON decodes a SET claims set per RFC 8417 §2.2. It is liberal:
// missing claims are left as their zero values and unknown top-level claims are
// ignored. The sub_id Subject Identifier is decoded through go-subjectid
// (RFC 9493) only when the claim is present and not JSON null; otherwise Subject
// stays nil to mean "no subject". An error is returned only for malformed JSON
// or a sub_id object go-subjectid cannot decode.
func (s *SET) UnmarshalJSON(data []byte) error {
	var w wireSET
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}

	subject, err := parseSubjectID(w.SubjectID)
	if err != nil {
		return err
	}

	*s = SET{
		Issuer:        w.Issuer,
		IssuedAt:      w.IssuedAt.Time,
		JWTID:         w.JWTID,
		Audience:      w.Audience,
		Subject:       subject,
		TransactionID: w.TransactionID,
		TimeOfEvent:   w.TimeOfEvent.Time,
		Events:        w.Events,
	}
	return nil
}

// parseSubjectID dispatches a raw sub_id claim through go-subjectid. An absent
// claim (nil bytes) or an explicit JSON null yields a nil SubjectIdentifier —
// the SET simply carries no subject. Any other value is delegated to
// subjectid.Parse, whose error is wrapped with context and returned.
func parseSubjectID(raw json.RawMessage) (subjectid.SubjectIdentifier, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	subject, err := subjectid.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("secevent: decode sub_id: %w", err)
	}
	return subject, nil
}
