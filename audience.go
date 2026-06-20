// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import "encoding/json"

// Audience is the RFC 8417 §2.2 "aud" claim. Per RFC 7519 §4.1.3 it is carried
// on the wire as either a single case-sensitive string or an array of such
// strings; Audience decodes both forms and encodes a single-element audience
// as a bare string (the JWT idiom), any other audience as a JSON array.
//
// The aud claim is OPTIONAL for a SET. A JSON null or an absent claim decodes
// to an empty (nil) Audience — no audience — never to a one-element audience
// holding the empty string.
type Audience []string

// UnmarshalJSON accepts both the string and []string wire forms. A JSON null
// is treated as an absent audience (left nil), not a single empty-string
// member, so callers can distinguish "no audience" from a real recipient.
func (a *Audience) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// MarshalJSON emits a single-element audience as a bare string and any other
// audience as a JSON array, matching the JWT convention for the aud claim.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}
