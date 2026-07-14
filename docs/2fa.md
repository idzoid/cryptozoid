# HOTP and TOTP

Cryptozoid provides HOTP and TOTP code generation plus stateless TOTP
verification.

## Current compatibility

The current implementation uses HMAC-SHA-1 for RFC 4226 HOTP and RFC 6238
TOTP compatibility. The default TOTP configuration is:

- 6 decimal digits;
- 30-second time step;
- Unix epoch (`T0 = 0`);
- verification window of one adjacent step on either side (`-1..+1`).

SHA-256 and SHA-512 selection is planned separately. Do not advertise those
algorithms in enrollment data until algorithm configuration is implemented.

## Secret handling

Secrets are supplied as Base32 strings. Padded and unpadded Base32 are
accepted, including lowercase input and spaces. The decoded secret must contain
at least 16 bytes.

Generate secrets with a cryptographically secure random source and store them
with strict access control. Never log secrets, OTP codes, enrollment URIs, or
recovery material.

```go
key := make([]byte, 20)
if _, err := rand.Read(key); err != nil {
	return err
}
secret := base32.StdEncoding.WithPadding(
	base32.NoPadding).EncodeToString(key)
```

The example requires:

```go
import (
	"crypto/rand"
	"encoding/base32"
)
```

## Generate a TOTP code

```go
code, err := totp.GenerateCode(secret, time.Now(), 30)
if err != nil {
	return err
}
fmt.Println(code)
```

`GenerateCode` returns an error for an invalid secret, a non-positive interval,
or a timestamp before the Unix epoch.

## Verify a TOTP code

```go
valid, err := totp.VerifyCode(secret, submittedCode, time.Now(), 30)
if err != nil {
	return err
}
if !valid {
	// Reject the authentication attempt.
}
```

`VerifyCode` accepts the current time step plus one adjacent step on either
side. For an explicit window, use `VerifyCodeFromBase32`:

```go
valid, err := totp.VerifyCodeFromBase32(
	secret,
	submittedCode,
	time.Now(),
	30,
	1, // accepted steps on either side
)
```

The window is bounded to 10 steps to limit verification work. The verifier is
stateless: the consuming application must persist accepted time steps to
prevent replay and must apply rate limiting to failed attempts.

## Generate an HOTP code

```go
counter := uint64(0)
code, err := hotp.GenerateCodeFromBase32(secret, counter)
if err != nil {
	return err
}
fmt.Println(code)
```

The application owns counter persistence and must advance or reject counters
according to its replay policy.

## Enrollment boundary

This package does not currently generate secrets, `otpauth://` enrollment URIs,
or QR images as an API. Applications may build enrollment material around the
same secret and must declare the exact algorithm, digit count, and period used
by code generation. QR rendering belongs to the application presentation
layer.

## Not provided by this package

- account/session persistence;
- replay storage;
- rate limiting or lockout policy;
- recovery codes;
- secret-at-rest storage;
- enrollment UI or QR rendering.
