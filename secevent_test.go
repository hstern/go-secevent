// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"testing"
	"time"
)

func TestSpecVersion(t *testing.T) {
	if SpecVersion != "RFC 8417" {
		t.Errorf("SpecVersion = %q, want %q", SpecVersion, "RFC 8417")
	}
}

// TestSETScalarClaims pins the scalar §2.2 claims onto the SET struct and
// checks the NumericDate wire type bridges iat/toe losslessly for whole
// seconds. Parse/Encode wire the full claims set (including aud, sub_id, and
// events) across the JSON boundary in later building blocks.
func TestSETScalarClaims(t *testing.T) {
	iat := time.Unix(1458496404, 0).UTC()
	toe := time.Unix(1458496400, 0).UTC()

	s := SET{
		Issuer:        "https://scim.example.com",
		IssuedAt:      iat,
		JWTID:         "4d3559ec67504aaba65d40b0363faad8",
		TransactionID: "8675309",
		TimeOfEvent:   toe,
	}

	if s.Issuer != "https://scim.example.com" {
		t.Errorf("Issuer = %q", s.Issuer)
	}
	if s.JWTID != "4d3559ec67504aaba65d40b0363faad8" {
		t.Errorf("JWTID = %q", s.JWTID)
	}
	if s.TransactionID != "8675309" {
		t.Errorf("TransactionID = %q", s.TransactionID)
	}

	// The dates survive a trip through the NumericDate wire type unchanged.
	if got := NewNumericDate(s.IssuedAt).Unix(); got != 1458496404 {
		t.Errorf("iat via NumericDate = %d, want 1458496404", got)
	}
	if got := NewNumericDate(s.TimeOfEvent).Unix(); got != 1458496400 {
		t.Errorf("toe via NumericDate = %d, want 1458496400", got)
	}
}

// TestSETZeroValueOptionalClaims documents that the optional scalar claims are
// the Go zero value when absent — an empty txn and a zero TimeOfEvent.
func TestSETZeroValueOptionalClaims(t *testing.T) {
	var s SET
	if s.TransactionID != "" {
		t.Errorf("zero SET TransactionID = %q, want empty", s.TransactionID)
	}
	if !s.TimeOfEvent.IsZero() {
		t.Errorf("zero SET TimeOfEvent = %v, want zero", s.TimeOfEvent)
	}
}
