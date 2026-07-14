// Package totp implements time-based one-time passwords (TOTP) as defined
// by RFC 6238, using the HOTP implementation from the sibling hotp package.
package totp

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/idzoid/cryptozoid/2fa/hotp"
)

const (
	// DefaultWindow is the number of adjacent time steps accepted on either
	// side of the current step by VerifyCode.
	DefaultWindow = 1

	// MaxWindow bounds verification work and limits abuse through oversized
	// clock-skew windows.
	MaxWindow = 10
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

// VerifyCodeFromBase32 verifies code for secret at t. It accepts the current
// time step and window adjacent steps on either side of it. The last modulus
// in modules controls the expected code width; the default is six digits.
//
// Verification is intentionally stateless: callers must persist accepted time
// steps to prevent replay and must apply rate limiting at the application
// boundary. This function does not log or return the submitted code.
//
// It returns an error for invalid secrets, code format, time parameters,
// modulus, or window values.
func VerifyCodeFromBase32(secret, code string, t time.Time, interval int64,
	window int, modules ...int) (bool, error) {
	if window < 0 || window > MaxWindow {
		return false, fmt.Errorf("TOTP window must be between 0 and %d", MaxWindow)
	}

	width, err := hotp.CodeWidth(modules...)
	if err != nil {
		return false, err
	}
	if err := validateCode(code, width); err != nil {
		return false, err
	}

	counter, err := TimeStep(t, interval, time.Unix(0, 0))
	if err != nil {
		return false, err
	}

	matched := 0
	for offset := -window; offset <= window; offset++ {
		candidateCounter, ok := offsetCounter(counter, offset)
		if !ok {
			continue
		}
		candidate, err := hotp.GenerateCodeFromBase32(
			secret, candidateCounter, modules...)
		if err != nil {
			return false, err
		}
		matched |= subtle.ConstantTimeCompare([]byte(code), []byte(candidate))
	}

	return matched == 1, nil
}

// VerifyCode verifies a six-digit TOTP code using the Unix epoch, the
// supplied interval, and DefaultWindow.
//
// Replay prevention and rate limiting remain the caller's responsibility.
func VerifyCode(secret, code string, t time.Time, interval int64) (bool, error) {
	return VerifyCodeFromBase32(
		secret, code, t, interval, DefaultWindow, hotp.DefaultModule)
}

func validateCode(code string, width int) error {
	if len(code) != width {
		return fmt.Errorf("TOTP code must contain %d digits", width)
	}
	for i := range code {
		if code[i] < '0' || code[i] > '9' {
			return errors.New("TOTP code must contain only decimal digits")
		}
	}
	return nil
}

func offsetCounter(counter uint64, offset int) (uint64, bool) {
	if offset < 0 {
		distance := uint64(-offset)
		if distance > counter {
			return 0, false
		}
		return counter - distance, true
	}

	distance := uint64(offset)
	if ^uint64(0)-counter < distance {
		return 0, false
	}
	return counter + distance, true
}

// GenerateCode generates a six-digit TOTP code for secret at t using the
// supplied interval in seconds and the Unix epoch.
//
// It returns an error when interval is non-positive, t precedes the Unix
// epoch, or secret is invalid.
func GenerateCode(secret string, t time.Time, interval int64) (string, error) {
	return GenerateCodeFromBase32(secret, t, interval, hotp.DefaultModule)
}
