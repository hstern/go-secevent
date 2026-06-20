// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
)

// TestAudienceWireForms covers the RFC 7519 §4.1.3 string-or-array wire forms
// in both directions: a bare string and a single-element array both decode to
// a one-element Audience and re-encode as a bare string (the JWT idiom), while
// a multi-element array decodes and re-encodes as a JSON array.
func TestAudienceWireForms(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Audience
		out  string
	}{
		{"single string", `"a"`, Audience{"a"}, `"a"`},
		{"array one", `["a"]`, Audience{"a"}, `"a"`},
		{"array many", `["a","b"]`, Audience{"a", "b"}, `["a","b"]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var a Audience
			if err := json.Unmarshal([]byte(tc.in), &a); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if !slices.Equal(a, tc.want) {
				t.Errorf("decoded %v, want %v", a, tc.want)
			}
			b, err := json.Marshal(a)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(b) != tc.out {
				t.Errorf("encoded %s, want %s", b, tc.out)
			}
		})
	}
}

// TestAudienceRejectsNonStringForms exercises the lenient-decode floor: aud is
// a string or an array of strings, so any other JSON shape (number, boolean,
// object, numeric array) is a decode error rather than a silent empty
// audience.
func TestAudienceRejectsNonStringForms(t *testing.T) {
	for _, in := range []string{`5`, `true`, `{"x":1}`, `[1,2]`} {
		t.Run(in, func(t *testing.T) {
			var a Audience
			if err := json.Unmarshal([]byte(in), &a); err == nil {
				t.Errorf("Unmarshal(%s) = nil error, want a decode error", in)
			}
		})
	}
}

// TestAudienceNullIsAbsent pins the RFC 8417 §2.2 / RFC 7519 rule that a null
// aud is no audience: it must decode to an empty (nil) Audience, never to a
// one-element audience holding the empty string.
func TestAudienceNullIsAbsent(t *testing.T) {
	var a Audience
	if err := json.Unmarshal([]byte(`null`), &a); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(a) != 0 {
		t.Fatalf("aud:null decoded to %v, want empty", a)
	}
}

// TestAudienceAbsentVsEmptyString distinguishes an absent claim from a real
// recipient. The wrapper carries aud as a pointer so the codec can observe
// "field omitted" (nil pointer) versus "field present"; an absent aud must
// leave the audience empty, and an explicit empty-string member must survive
// as a distinct, non-empty audience.
func TestAudienceAbsentVsEmptyString(t *testing.T) {
	type wrapper struct {
		Audience *Audience `json:"aud,omitempty"`
	}

	t.Run("absent", func(t *testing.T) {
		var w wrapper
		if err := json.Unmarshal([]byte(`{}`), &w); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if w.Audience != nil {
			t.Fatalf("absent aud decoded to %v, want nil pointer", *w.Audience)
		}
	})

	t.Run("empty string member", func(t *testing.T) {
		var w wrapper
		if err := json.Unmarshal([]byte(`{"aud":""}`), &w); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if w.Audience == nil {
			t.Fatal("present aud decoded to nil pointer")
		}
		if want := (Audience{""}); !slices.Equal(*w.Audience, want) {
			t.Fatalf("empty-string aud decoded to %v, want %v", *w.Audience, want)
		}
	})
}

// TestAudienceOmitemptyRoundTrip confirms that, wrapped with omitempty, a nil
// Audience is omitted from the encoded object entirely (no aud key), so an
// encode of a SET without an audience reproduces the absent claim.
func TestAudienceOmitemptyRoundTrip(t *testing.T) {
	type wrapper struct {
		Audience Audience `json:"aud,omitempty"`
	}

	b, err := json.Marshal(wrapper{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `{}`; string(b) != want {
		t.Errorf("encoded %s, want %s", b, want)
	}
}

// TestAudienceByteStableRoundTrip ensures the canonical wire bytes survive a
// decode → encode round-trip unchanged: a bare string stays a bare string and
// a multi-element array stays an array. (A single-element array is
// deliberately normalized to a bare string and so is covered by
// TestAudienceWireForms, not here.)
func TestAudienceByteStableRoundTrip(t *testing.T) {
	for _, in := range []string{`"a"`, `["a","b"]`} {
		t.Run(in, func(t *testing.T) {
			var a Audience
			if err := json.Unmarshal([]byte(in), &a); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			b, err := json.Marshal(a)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(b) != in {
				t.Errorf("round-trip = %s, want %s", b, in)
			}
		})
	}
}

// ExampleAudience demonstrates the RFC 7519 string-or-array handling of the
// aud claim: a single recipient decodes from (and re-encodes to) a bare
// string, while multiple recipients use a JSON array.
func ExampleAudience() {
	var single Audience
	_ = json.Unmarshal([]byte(`"https://rp.example.com"`), &single)

	var many Audience
	_ = json.Unmarshal([]byte(`["https://a.example.com","https://b.example.com"]`), &many)

	one, _ := json.Marshal(single)
	two, _ := json.Marshal(many)
	fmt.Printf("%s\n%s\n", one, two)
	// Output:
	// "https://rp.example.com"
	// ["https://a.example.com","https://b.example.com"]
}
