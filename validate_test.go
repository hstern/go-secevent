// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// validSET returns a SET carrying exactly the four RFC 8417 §2.2 required
// claims (iss, iat, jti, one event) and no optional claims. Each test that
// needs an invalid SET starts from this and removes a single claim, so a
// failure is attributable to that one removal.
func validSET() *SET {
	return &SET{
		Issuer:   "https://issuer.example.com",
		IssuedAt: time.Unix(1700000000, 0),
		JWTID:    "abc123",
		Events:   Events{"urn:example:event": []byte(`{}`)},
	}
}

func TestValidateRequiredClaimsOnlyPasses(t *testing.T) {
	if err := validSET().Validate(); err != nil {
		t.Errorf("Validate() on a SET with only the four required claims = %v, want nil", err)
	}
}

func TestValidateFullyPopulatedPasses(t *testing.T) {
	set, err := Parse([]byte(scimExample))
	if err != nil {
		t.Fatalf("Parse(scimExample) returned error: %v", err)
	}
	if err := set.Validate(); err != nil {
		t.Errorf("Validate() on the fully-populated §2.1 example = %v, want nil", err)
	}
}

func TestValidateMissingClaimSentinels(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*SET)
		want    error
		wantStr string // expected ValidationError.Claim
	}{
		{
			name:    "missing iss",
			mutate:  func(s *SET) { s.Issuer = "" },
			want:    ErrMissingIssuer,
			wantStr: "iss",
		},
		{
			name:    "missing iat",
			mutate:  func(s *SET) { s.IssuedAt = time.Time{} },
			want:    ErrMissingIssuedAt,
			wantStr: "iat",
		},
		{
			name:    "missing jti",
			mutate:  func(s *SET) { s.JWTID = "" },
			want:    ErrMissingJWTID,
			wantStr: "jti",
		},
		{
			name:    "events nil",
			mutate:  func(s *SET) { s.Events = nil },
			want:    ErrNoEvents,
			wantStr: "events",
		},
		{
			name:    "events present but empty",
			mutate:  func(s *SET) { s.Events = Events{} },
			want:    ErrNoEvents,
			wantStr: "events",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := validSET()
			tt.mutate(set)

			err := set.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want error wrapping %v", tt.want)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("errors.Is(err, %v) = false, err = %v", tt.want, err)
			}

			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("errors.As(err, *ValidationError) = false, err = %v", err)
			}
			if ve.Claim != tt.wantStr {
				t.Errorf("ValidationError.Claim = %q, want %q", ve.Claim, tt.wantStr)
			}
		})
	}
}

// TestValidateOptionalClaimsAbsentNoError confirms that the optional §2.2 claims
// (aud, sub_id, txn, toe) are never required: a SET that omits all of them but
// carries the four required claims validates clean.
func TestValidateOptionalClaimsAbsentNoError(t *testing.T) {
	set := validSET()
	if set.Audience != nil {
		t.Fatalf("test precondition: Audience should be nil, got %v", set.Audience)
	}
	if set.Subject != nil {
		t.Fatalf("test precondition: Subject should be nil, got %v", set.Subject)
	}
	if set.TransactionID != "" || !set.TimeOfEvent.IsZero() {
		t.Fatalf("test precondition: txn/toe should be unset")
	}
	if err := set.Validate(); err != nil {
		t.Errorf("Validate() with all optional claims absent = %v, want nil", err)
	}
}

// TestValidateReportsAllFailures confirms the errors.Join behaviour: an empty
// SET fails every MUST at once, and errors.Is matches each sentinel in the
// joined tree.
func TestValidateReportsAllFailures(t *testing.T) {
	var empty SET
	err := empty.Validate()
	if err == nil {
		t.Fatal("Validate() on a zero SET = nil, want a joined error")
	}
	for _, sentinel := range []error{ErrMissingIssuer, ErrMissingIssuedAt, ErrMissingJWTID, ErrNoEvents} {
		if !errors.Is(err, sentinel) {
			t.Errorf("errors.Is(err, %v) = false, want true (all four MUSTs failed)", sentinel)
		}
	}
}

// ExampleSET_Validate shows checking the RFC 8417 §2.2 required-claim MUSTs on
// a parsed SET and matching the empty-events failure with errors.Is. A nil
// return confirms structural well-formedness only — never that the SET is good
// for authentication or authorization (RFC 8417 §4).
func ExampleSET_Validate() {
	set, err := Parse([]byte(`{
		"iss": "https://issuer.example.com",
		"iat": 1700000000,
		"jti": "abc-123",
		"events": {"https://schemas.example.org/event-type/widget-spun": {}}
	}`))
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	if err := set.Validate(); err != nil {
		fmt.Println("invalid:", err)
	} else {
		fmt.Println("structurally valid SET")
	}

	// A SET whose events object is empty fails the load-bearing §2.2 MUST.
	empty, _ := Parse([]byte(`{"iss":"i","iat":1700000000,"jti":"x","events":{}}`))
	fmt.Println("empty events is ErrNoEvents:", errors.Is(empty.Validate(), ErrNoEvents))

	// Output:
	// structurally valid SET
	// empty events is ErrNoEvents: true
}

// TestValidationErrorMessage pins the human-readable form of a single failure.
func TestValidationErrorMessage(t *testing.T) {
	set := validSET()
	set.Issuer = ""
	err := set.Validate()

	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("errors.As(err, *ValidationError) = false, err = %v", err)
	}
	if got, want := ve.Error(), "secevent: iss: issuer is required"; got != want {
		t.Errorf("ValidationError.Error() = %q, want %q", got, want)
	}
}
