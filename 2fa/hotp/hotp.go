// Package hotp implements HMAC-based one-time passwords (HOTP) as defined
// by RFC 4226.
package hotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	// DefaultModule is the modulus for a six-digit OTP.
	DefaultModule = 1_000_000

	// DEFAULT_MODULE is retained for compatibility. New code should use
	// DefaultModule.
	//
	// Deprecated: use DefaultModule.
	DEFAULT_MODULE = DefaultModule

	minSecretBytes = 16 // RFC 4226 requires at least 128 bits of secret key.
)

// HOTP computes the OTP value for key and counter using RFC 4226 dynamic
// truncation and the requested modulus. The last modulus in modules is used,
// if present; otherwise DefaultModule is used.
//
// The key must contain at least 16 bytes. A non-positive modulus is invalid.
func HOTP(key []byte, counter uint64, modules ...int) (int, error) {
	if len(key) < minSecretBytes {
		return 0, errors.New("secret must contain at least 16 bytes")
	}
	module, _, err := resolveModule(modules...)
	if err != nil {
		return 0, err
	}
	return rawHOTP(key, counter) % module, nil
}

// rawHOTP executes the RFC4226 truncation logic and returns the raw integer
// value.
func rawHOTP(key []byte, counter uint64) int {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	h := hmac.New(sha1.New, key)
	h.Write(buf[:])
	hash := h.Sum(nil)
	offset := hash[len(hash)-1] & 0x0F
	code := (int(hash[offset])&0x7f)<<24 |
		(int(hash[offset+1])&0xff)<<16 |
		(int(hash[offset+2])&0xff)<<8 |
		(int(hash[offset+3]) & 0xff)
	return code
}

func resolveModule(modules ...int) (int, int, error) {
	module := DefaultModule
	if len(modules) > 0 {
		module = modules[len(modules)-1]
	}
	if module <= 0 {
		return 0, 0, errors.New("OTP modulus must be positive")
	}
	return module, len(fmt.Sprintf("%d", module-1)), nil
}

// GenerateCodeFromBase32 decodes a Base32 secret and generates the HOTP code
// for counter. Both padded and unpadded Base32 input are accepted; spaces and
// lowercase letters are normalized.
//
// The decoded secret must contain at least 16 bytes. The last modulus in
// modules controls the number of output digits; DefaultModule produces six
// digits. A non-positive modulus returns an error.
func GenerateCodeFromBase32(secret string, counter uint64,
	modules ...int) (string, error) {
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))

	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	if strings.Contains(secret, "=") {
		encoding = base32.StdEncoding
	}
	key, err := encoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to decode secret: %w", err)
	}
	if len(key) < minSecretBytes {
		return "", fmt.Errorf("secret must contain at least %d bytes", minSecretBytes)
	}

	module, width, err := resolveModule(modules...)
	if err != nil {
		return "", err
	}
	code, err := HOTP(key, counter, module)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", width, code), nil
}
