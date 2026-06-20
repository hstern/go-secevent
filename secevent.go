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

// SpecVersion is the RFC 8417 — Security Event Token (SET) version this build
// implements.
const SpecVersion = "RFC 8417"
