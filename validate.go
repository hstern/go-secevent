// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import "errors"

// Validate checks the RFC 8417 §2.2/§2.3 required-claim MUSTs that this library
// owns: iss, iat, and jti MUST be present, and the events claim MUST be present
// with at least one member (§2.2). It is the opt-in counterpart to Parse, which
// decodes liberally and performs no validation, so a consumer can inspect a
// structurally incomplete SET before deciding whether to reject it.
//
// Validate reports every failing claim, not just the first: the per-claim
// failures are wrapped in *ValidationError values and combined with
// errors.Join. A nil return means all four MUSTs are satisfied. Match a
// specific failure with errors.Is against the sentinels (ErrMissingIssuer,
// ErrMissingIssuedAt, ErrMissingJWTID, ErrNoEvents) — errors.Is traverses the
// joined tree — or recover the offending claim name with errors.As against
// *ValidationError. The optional claims (aud, sub_id, txn, toe) are never
// required and their absence is not an error (§2.2).
//
// A successful Validate confirms structural well-formedness only. A SET is not
// an access token: RFC 8417 §4 is explicit that a SET MUST NOT be treated as an
// authentication or authorization assertion, and a validated SET carries no
// "still good for auth" semantics. It is a statement that an event occurred,
// nothing more. Validate performs no signature, issuer, audience, expiry, or
// time-window checking — those either belong to the JOSE/transport layer or are
// access-token semantics that do not apply to SETs.
func (s *SET) Validate() error {
	var errs []error

	if s.Issuer == "" {
		errs = append(errs, &ValidationError{
			Claim:  "iss",
			Reason: "issuer is required",
			err:    ErrMissingIssuer,
		})
	}
	if s.IssuedAt.IsZero() {
		errs = append(errs, &ValidationError{
			Claim:  "iat",
			Reason: "issued-at time is required",
			err:    ErrMissingIssuedAt,
		})
	}
	if s.JWTID == "" {
		errs = append(errs, &ValidationError{
			Claim:  "jti",
			Reason: "unique identifier is required",
			err:    ErrMissingJWTID,
		})
	}
	if s.Events.Len() == 0 {
		errs = append(errs, &ValidationError{
			Claim:  "events",
			Reason: "at least one event is required",
			err:    ErrNoEvents,
		})
	}

	return errors.Join(errs...)
}
