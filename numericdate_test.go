// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNumericDateMarshal(t *testing.T) {
	// Encodes whole seconds since the Unix epoch (RFC 7519).
	nd := NewNumericDate(time.Unix(1458496404, 0))
	got, err := json.Marshal(nd)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := "1458496404"; string(got) != want {
		t.Errorf("Marshal = %s, want %s", got, want)
	}
}

func TestNumericDateUnmarshalInteger(t *testing.T) {
	var nd NumericDate
	if err := json.Unmarshal([]byte("1458496404"), &nd); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !nd.Equal(time.Unix(1458496404, 0)) {
		t.Errorf("Unmarshal = %v, want %v", nd.Time, time.Unix(1458496404, 0).UTC())
	}
}

func TestNumericDateUnmarshalFractional(t *testing.T) {
	// RFC 7519 permits non-integer NumericDate values (fractional seconds).
	var nd NumericDate
	if err := json.Unmarshal([]byte("1458496404.5"), &nd); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if want := time.Unix(1458496404, 500_000_000).UTC(); !nd.Equal(want) {
		t.Errorf("Unmarshal fractional = %v, want %v", nd.Time, want)
	}
}

func TestNumericDateUnmarshalNull(t *testing.T) {
	// A JSON null leaves the zero value untouched (claim absent).
	nd := NewNumericDate(time.Unix(1, 0))
	before := nd.Time
	if err := json.Unmarshal([]byte("null"), nd); err != nil {
		t.Fatalf("Unmarshal null: %v", err)
	}
	if !nd.Equal(before) {
		t.Errorf("Unmarshal null mutated value: %v", nd.Time)
	}
}

func TestNumericDateUnmarshalInvalid(t *testing.T) {
	var nd NumericDate
	if err := json.Unmarshal([]byte(`"not-a-number"`), &nd); err == nil {
		t.Fatal("Unmarshal of a non-numeric value: want error, got nil")
	}
}

func TestNumericDateRoundTripByteStable(t *testing.T) {
	// Marshal → Unmarshal → Marshal reproduces the same bytes.
	const wire = "1458496404"
	var nd NumericDate
	if err := json.Unmarshal([]byte(wire), &nd); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	out, err := json.Marshal(nd)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != wire {
		t.Errorf("round-trip = %s, want %s", out, wire)
	}
}

func TestNewNumericDateTruncatesToSeconds(t *testing.T) {
	nd := NewNumericDate(time.Unix(1458496404, 750_000_000))
	if nd.Nanosecond() != 0 {
		t.Errorf("NewNumericDate kept sub-second precision: %d ns", nd.Nanosecond())
	}
	if nd.Unix() != 1458496404 {
		t.Errorf("NewNumericDate Unix = %d, want 1458496404", nd.Unix())
	}
}
