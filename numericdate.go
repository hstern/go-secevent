// Copyright 2026 The go-secevent Authors
// SPDX-License-Identifier: Apache-2.0

package secevent

import (
	"math"
	"strconv"
	"time"
)

// NumericDate is an RFC 7519 NumericDate: a JSON number of seconds since the
// Unix epoch, used by the SET iat and toe claims (RFC 8417 §2.2). It decodes
// integer and fractional values and encodes whole seconds.
type NumericDate struct {
	time.Time
}

// NewNumericDate wraps t as a *NumericDate, truncated to whole seconds.
func NewNumericDate(t time.Time) *NumericDate {
	return &NumericDate{Time: time.Unix(t.Unix(), 0).UTC()}
}

// MarshalJSON encodes the date as whole seconds since the Unix epoch.
func (n NumericDate) MarshalJSON() ([]byte, error) {
	return strconv.AppendInt(nil, n.Unix(), 10), nil
}

// UnmarshalJSON decodes an RFC 7519 NumericDate. A JSON null leaves the value
// unchanged (the claim is treated as absent); fractional values are honoured.
func (n *NumericDate) UnmarshalJSON(data []byte) error {
	s := string(data)
	if s == "null" {
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return err
	}
	sec, frac := math.Modf(f)
	n.Time = time.Unix(int64(sec), int64(math.Round(frac*1e9))).UTC()
	return nil
}
