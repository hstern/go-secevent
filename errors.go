// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import "errors"

// Sentinel errors for the RFC 8417 §2.2 required-claim checks performed by
// Validate. Each *ValidationError that Validate produces wraps one of these;
// match them with errors.Is. They describe structural well-formedness only —
// never an authentication or authorization outcome (RFC 8417 §4).
var (
	// ErrMissingIssuer indicates the REQUIRED iss claim is absent (§2.2).
	ErrMissingIssuer = errors.New("secevent: missing required claim iss")
	// ErrMissingIssuedAt indicates the REQUIRED iat claim is absent (§2.2).
	ErrMissingIssuedAt = errors.New("secevent: missing required claim iat")
	// ErrMissingJWTID indicates the REQUIRED jti claim is absent (§2.2).
	ErrMissingJWTID = errors.New("secevent: missing required claim jti")
	// ErrNoEvents indicates the REQUIRED events claim is absent or carries no
	// members. A SET MUST convey at least one event (§2.2) — this is the
	// load-bearing SET-specific MUST.
	ErrNoEvents = errors.New("secevent: events claim is absent or empty")
)

// ValidationError reports a single failed RFC 8417 claim check. It names the
// offending claim, carries a human-readable reason, and wraps the matching
// sentinel so callers can branch with errors.Is (against the sentinel) or
// errors.As (against *ValidationError to recover the Claim name).
//
// Validate reports every failing claim at once by joining the per-claim
// *ValidationErrors with errors.Join; errors.Is still matches any wrapped
// sentinel across the joined tree.
type ValidationError struct {
	// Claim is the RFC 8417 §2.2 claim member name at fault (for example "iss"
	// or "events").
	Claim string
	// Reason is a human-readable explanation of why the claim failed its check.
	Reason string

	err error
}

var _ error = (*ValidationError)(nil)

// Error implements the error interface.
func (e *ValidationError) Error() string {
	return "secevent: " + e.Claim + ": " + e.Reason
}

// Unwrap exposes the wrapped sentinel so errors.Is can match it.
func (e *ValidationError) Unwrap() error { return e.err }
