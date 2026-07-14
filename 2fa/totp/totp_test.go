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

func TestRFC6238Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	secret := base32.StdEncoding.WithPadding(
		base32.NoPadding).EncodeToString(key)

	tests := []struct {
		timestamp int64
		modulus   int
		want      string
	}{
		{timestamp: 59, modulus: 100_000_000, want: "94287082"},
		{timestamp: 1_111_111_109, modulus: 100_000_000, want: "07081804"},
		{timestamp: 1_111_111_111, modulus: 100_000_000, want: "14050471"},
		{timestamp: 1_234_567_890, modulus: 100_000_000, want: "89005924"},
		{timestamp: 2_000_000_000, modulus: 100_000_000, want: "69279037"},
		{timestamp: 20_000_000_000, modulus: 100_000_000, want: "65353130"},
	}

	for _, test := range tests {
		code, err := GenerateCodeFromBase32(
			secret, time.Unix(test.timestamp, 0), 30, test.modulus)
		if err != nil {
			t.Fatalf("timestamp=%d: %v", test.timestamp, err)
		}
		if code != test.want {
			t.Errorf("timestamp=%d: want %s got %s",
				test.timestamp, test.want, code)
		}
	}
}

func TestInvalidTOTPIntervals(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(
		base32.NoPadding).EncodeToString([]byte("12345678901234567890"))

	for _, interval := range []int64{0, -30} {
		if _, err := GenerateCode(secret, time.Unix(0, 0), interval); err == nil {
			t.Errorf("interval=%d: expected an error", interval)
		}
	}

	if _, err := TimeStep(time.Unix(-1, 0), 30, time.Unix(0, 0)); err == nil {
		t.Error("expected a timestamp before the epoch to return an error")
	}
}
