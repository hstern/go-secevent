// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"reflect"

	"github.com/hstern/go-subjectid"
)

// SubjectAs returns the SET's sub_id as the concrete Subject Identifier type T,
// reporting ok=false when the subject is absent or of a different format.
//
// It exists to absorb the value/pointer distinction in the Subject field.
// go-subjectid's Parse returns identifiers in their value form (for example
// subjectid.IssSubID), the same form a SET built in Go naturally holds, so the
// two share a dynamic type. A SET may nonetheless be hand-built with the
// pointer form (*subjectid.IssSubID also satisfies the interface), and a
// consumer that type-asserts SET.Subject directly would have to handle both.
// SubjectAs handles them once: it accepts the value type as T (for example
// SubjectAs[subjectid.IssSubID]) and matches whether the held identifier is the
// value or the pointer form, always returning the value.
//
//	if iss, ok := secevent.SubjectAs[subjectid.IssSubID](set); ok {
//	    // iss is a subjectid.IssSubID regardless of how set was built
//	}
//
// For the overwhelmingly common iss_sub case, (*SET).IssSub is a shorthand.
func SubjectAs[T subjectid.SubjectIdentifier](s *SET) (T, bool) {
	var zero T
	if s == nil || s.Subject == nil {
		return zero, false
	}

	// The value form (a SET built in Go) matches directly.
	if v, ok := s.Subject.(T); ok {
		return v, true
	}

	// The pointer form (a hand-built SET) is *T; dereference it. A type
	// assertion to *T will not compile for an arbitrary type parameter, so
	// reach for reflection to peel exactly one pointer indirection.
	rv := reflect.ValueOf(s.Subject)
	if rv.Kind() == reflect.Pointer && !rv.IsNil() {
		if v, ok := reflect.TypeAssert[T](rv.Elem()); ok {
			return v, true
		}
	}

	return zero, false
}

// IssSub returns the SET's sub_id as a subjectid.IssSubID when the subject is
// present and in the iss_sub format, reporting ok=false otherwise. It is a
// shorthand for SubjectAs[subjectid.IssSubID] covering the most common subject
// format, and it transparently handles both the value and pointer forms of the
// held identifier (see SubjectAs).
func (s *SET) IssSub() (subjectid.IssSubID, bool) {
	return SubjectAs[subjectid.IssSubID](s)
}
