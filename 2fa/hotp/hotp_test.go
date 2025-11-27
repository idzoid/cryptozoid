package hotp

import (
	"encoding/base32"
	"fmt"
	"testing"
)

// RFC4226 HOTP vectors - counters 0..9
func RFC4226Vectors() []int {
	return []int{755224, 287082, 359152, 969429, 338314, 254676, 287922,
		162583, 399871, 520489}
}

// Expected values from RFC4226 Appendix D.
func TestHOTPRFC4226Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	expected := RFC4226Vectors()

	for i, exp := range expected {
		got := HOTP(key, uint64(i))
		if got != exp {
			t.Fatalf("counter=%d: want %06d got %06d", i, exp, got)
		}
	}
}

func TestGenerateCodeFromBase32(t *testing.T) {
	key := []byte("12345678901234567890")
	secret := base32.StdEncoding.WithPadding(
		base32.NoPadding).EncodeToString(key)
	expected := RFC4226Vectors()

	for i, exp := range expected {
		// For HOTP, counter is just i for RFC vectors
		counter := uint64(i)
		code, err := GenerateCodeFromBase32(secret, counter)
		if err != nil {
			t.Fatalf("GenerateCodeFromBase32 error: %v", err)
		}
		want := fmt.Sprintf("%06d", exp)
		if code != want {
			t.Fatalf("counter=%d: want %s got %s", i, want, code)
		}
	}
}
