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

func TestVerifyCode(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(
		base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	timestamp := time.Unix(60, 0)
	code, err := GenerateCode(secret, timestamp, 30)
	if err != nil {
		t.Fatalf("GenerateCode error: %v", err)
	}

	valid, err := VerifyCode(secret, code, timestamp, 30)
	if err != nil {
		t.Fatalf("VerifyCode error: %v", err)
	}
	if !valid {
		t.Fatal("expected generated code to verify")
	}

	valid, err = VerifyCode(secret, "000000", timestamp, 30)
	if err != nil {
		t.Fatalf("wrong code should not return an error: %v", err)
	}
	if valid {
		t.Fatal("expected wrong code to fail verification")
	}
}

func TestVerifyCodeWindow(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(
		base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	code, err := GenerateCode(secret, time.Unix(0, 0), 30)
	if err != nil {
		t.Fatalf("GenerateCode error: %v", err)
	}

	valid, err := VerifyCodeFromBase32(
		secret, code, time.Unix(30, 0), 30, 1)
	if err != nil {
		t.Fatalf("window verification error: %v", err)
	}
	if !valid {
		t.Fatal("expected adjacent time step to verify within window")
	}

	valid, err = VerifyCodeFromBase32(
		secret, code, time.Unix(60, 0), 30, 1)
	if err != nil {
		t.Fatalf("out-of-window verification error: %v", err)
	}
	if valid {
		t.Fatal("expected code outside the verification window to fail")
	}
}

func TestVerifyCodeValidation(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(
		base32.NoPadding).EncodeToString([]byte("12345678901234567890"))

	for name, code := range map[string]string{
		"wrong length": "12345",
		"non-decimal":  "12x456",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyCode(secret, code, time.Unix(0, 0), 30); err == nil {
				t.Fatal("expected malformed code to return an error")
			}
		})
	}

	if _, err := VerifyCodeFromBase32(
		secret, "123456", time.Unix(0, 0), 30, MaxWindow+1); err == nil {
		t.Fatal("expected oversized verification window to return an error")
	}
}
