// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import "github.com/hstern/go-subjectid"

// SubjectAs returns the SET's sub_id as the concrete Subject Identifier type T,
// reporting ok=false when the subject is absent or of a different format.
//
// go-subjectid's Parse returns identifiers in their value form (for example
// subjectid.IssSubID), the same form a SET built in Go holds, so T is the value
// type — SubjectAs[subjectid.IssSubID]. It is a typed, nil-safe read of the
// SET.Subject interface: a checked type assertion that also tolerates a nil SET
// or an absent subject.
//
//	if iss, ok := secevent.SubjectAs[subjectid.IssSubID](set); ok {
//	    // iss is a subjectid.IssSubID
//	}
//
// For the overwhelmingly common iss_sub case, (*SET).IssSub is a shorthand.
func SubjectAs[T subjectid.SubjectIdentifier](s *SET) (T, bool) {
	var zero T
	if s == nil || s.Subject == nil {
		return zero, false
	}
	if v, ok := s.Subject.(T); ok {
		return v, true
	}
	return zero, false
}

// IssSub returns the SET's sub_id as a subjectid.IssSubID when the subject is
// present and in the iss_sub format, reporting ok=false otherwise. It is a
// shorthand for SubjectAs[subjectid.IssSubID] covering the most common subject
// format.
func (s *SET) IssSub() (subjectid.IssSubID, bool) {
	return SubjectAs[subjectid.IssSubID](s)
}
