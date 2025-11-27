package totp

import (
	"time"

	"github.com/idzoid/cryptozoid/2fa/hotp"
)

// TimeStep calculates the TOTP counter based on timestamp, interval (seconds),
// and epoch. For standard TOTP use epoch = time.Unix(0, 0).
func TimeStep(t time.Time, interval int64, epoch time.Time) uint64 {
	return uint64((t.Unix() - epoch.Unix()) / interval)
}

// GenerateCodeFromBase32 decodes the base32 secret, calculates the counter,
// then generates the TOTP code. The last module parameter defines the digit
// count (e.g. 1_000_000 for 6 digits).
func GenerateCodeFromBase32(secret string, t time.Time,
	interval int64, modules ...int) (string, error) {
	counter := TimeStep(t, interval, time.Unix(0, 0))
	return hotp.GenerateCodeFromBase32(secret, counter, modules...)
}

// GenerateCode is a convenience wrapper to generate a 6-digit TOTP code
// (default module 1_000_000).
func GenerateCode(secret string, t time.Time, interval int64) (string, error) {
	return GenerateCodeFromBase32(secret, t, interval, hotp.DEFAULT_MODULE)
}
