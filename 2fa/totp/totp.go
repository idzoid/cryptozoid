// Package totp implements time-based one-time passwords (TOTP) as defined
// by RFC 6238, using the HOTP implementation from the sibling hotp package.
package totp

import (
	"errors"
	"time"

	"github.com/idzoid/cryptozoid/2fa/hotp"
)

// TimeStep calculates the TOTP counter for timestamp t, an interval in
// seconds, and epoch. For standard TOTP, use time.Unix(0, 0) as the epoch.
//
// It returns an error when interval is non-positive or t precedes epoch.
func TimeStep(t time.Time, interval int64, epoch time.Time) (uint64, error) {
	if interval <= 0 {
		return 0, errors.New("TOTP interval must be positive")
	}
	if t.Before(epoch) {
		return 0, errors.New("TOTP timestamp must not precede the epoch")
	}
	return uint64((t.Unix() - epoch.Unix()) / interval), nil
}

// GenerateCodeFromBase32 decodes a Base32 secret, calculates the TOTP counter
// for t using interval seconds, and generates the code. Both padded and
// unpadded Base32 input are accepted by the underlying HOTP implementation.
// The last modulus in modules controls the number of output digits; the
// default is six digits.
//
// It returns an error for invalid time parameters, invalid secrets, or an
// invalid modulus.
func GenerateCodeFromBase32(secret string, t time.Time,
	interval int64, modules ...int) (string, error) {
	counter, err := TimeStep(t, interval, time.Unix(0, 0))
	if err != nil {
		return "", err
	}
	return hotp.GenerateCodeFromBase32(secret, counter, modules...)
}

// GenerateCode generates a six-digit TOTP code for secret at t using the
// supplied interval in seconds and the Unix epoch.
//
// It returns an error when interval is non-positive, t precedes the Unix
// epoch, or secret is invalid.
func GenerateCode(secret string, t time.Time, interval int64) (string, error) {
	return GenerateCodeFromBase32(secret, t, interval, hotp.DefaultModule)
}
