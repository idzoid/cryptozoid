package hotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
)

const DEFAULT_MODULE = 1_000_000

// HOTP computes the code value for the key and counter, using RFC4226
// truncation and a modulus. The last module in the variadic modules argument
// is applied (if any), otherwise defaults to 1_000_000 (6 digits).
func HOTP(key []byte, counter uint64, modules ...int) int {
	code := rawHOTP(key, counter)
	module := DEFAULT_MODULE
	if len(modules) > 0 {
		module = modules[len(modules)-1]
		if module <= 0 {
			module = DEFAULT_MODULE
		}
	}
	return code % module
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

// GenerateCodeFromBase32 decodes the base32 secret, then generates the HOTP
// code for the specified counter and module.
func GenerateCodeFromBase32(secret string, counter uint64,
	modules ...int) (string, error) {
	secret = strings.ToUpper(secret)
	secret = strings.ReplaceAll(secret, " ", "")
	key, err := base32.StdEncoding.WithPadding(
		base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to decode secret: %w", err)
	}
	code := HOTP(key, counter, modules...)
	module := DEFAULT_MODULE
	if len(modules) > 0 && modules[len(modules)-1] > 0 {
		module = modules[len(modules)-1]
	}
	width := len(fmt.Sprintf("%d", module-1))
	return fmt.Sprintf("%0*d", width, code), nil
}
