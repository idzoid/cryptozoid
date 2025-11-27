package totp

import (
	"encoding/base32"
	"fmt"
	"testing"
	"time"
)

// RFC4226 HOTP vectors - counters 0..9
// Expected values from RFC4226 Appendix D.
func RFC4226Vectors() []int {
	return []int{755224, 287082, 359152, 969429, 338314, 254676, 287922,
		162583, 399871, 520489}
}

func TestGenerateCodeFromBase32_TOTP(t *testing.T) {
	key := []byte("12345678901234567890")
	secret := base32.StdEncoding.WithPadding(
		base32.NoPadding).EncodeToString(key)
	interval := int64(30)
	expected := RFC4226Vectors()

	for i, exp := range expected {
		ts := time.Unix(int64(i)*interval, 0)
		code, err := GenerateCodeFromBase32(secret, ts, interval)
		if err != nil {
			t.Fatalf("GenerateCodeFromBase32 error: %v", err)
		}
		want := fmt.Sprintf("%06d", exp)
		if code != want {
			t.Fatalf("counter=%d: want %s got %s", i, want, code)
		}
	}
}
