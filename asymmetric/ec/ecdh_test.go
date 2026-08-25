package ec

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"encoding/hex"
	"testing"
)

func TestECDHKeyManagerAcrossCurves(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
		want  string
	}{
		{name: "P256", curve: elliptic.P256(), want: "P-256"},
		{name: "P384", curve: elliptic.P384(), want: "P-384"},
		{name: "P521", curve: elliptic.P521(), want: "P-521"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pk1, err := GenerateECDSAKey(test.curve)
			if err != nil {
				t.Fatal(err)
			}
			ecdsaKm1 := NewECDSAKeyManager(pk1)
			p1Km, err := ecdsaKm1.ECDHKeyManager()
			if err != nil {
				t.Fatal(err)
			}

			pk2, err := GenerateECDSAKey(test.curve)
			if err != nil {
				t.Fatal(err)
			}
			ecdsaKm2 := NewECDSAKeyManager(pk2)
			p2Km, err := ecdsaKm2.ECDHKeyManager()
			if err != nil {
				t.Fatal(err)
			}

			if got := p1Km.CurveName(); got != test.want {
				t.Fatalf("party one curve = %q, want %q", got, test.want)
			}
			if got := p2Km.CurveName(); got != test.want {
				t.Fatalf("party two curve = %q, want %q", got, test.want)
			}

			p1Shared, err := p1Km.DeriveSharedSecret(p2Km.Key().PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			p2Shared, err := p2Km.DeriveSharedSecret(p1Km.Key().PublicKey())
			if err != nil {
				t.Fatal(err)
			}

			if got, want := hex.EncodeToString(p1Shared), hex.EncodeToString(p2Shared); got != want {
				t.Fatalf("shared secrets differ: party one %s, party two %s", got, want)
			}
		})
	}
}

func TestECDHKeyManagerCurveSpecificPEMHelpers(t *testing.T) {
	tests := []struct {
		name      string
		curve     ecdh.Curve
		parsePriv func([]byte) (*ecdh.PrivateKey, error)
		parsePub  func([]byte) (*ecdh.PublicKey, error)
	}{
		{name: "P256", curve: ecdh.P256(), parsePriv: ECDHP256PemToKey, parsePub: ECDHP256PemToPublic},
		{name: "P384", curve: ecdh.P384(), parsePriv: ECDHP384PemToKey, parsePub: ECDHP384PemToPublic},
		{name: "P521", curve: ecdh.P521(), parsePriv: ECDHP521PemToKey, parsePub: ECDHP521PemToPublic},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := GenerateECDHKey(test.curve)
			if err != nil {
				t.Fatal(err)
			}
			manager := NewECDHKeyManager(key)

			privatePEM, err := manager.PrivateKeyToPem()
			if err != nil {
				t.Fatal(err)
			}
			parsedPrivate, err := test.parsePriv(privatePEM)
			if err != nil {
				t.Fatal(err)
			}
			if parsedPrivate.Curve() != key.Curve() {
				t.Fatal("private curve changed after PEM round trip")
			}

			publicPEM, err := manager.PublicKeyToPem()
			if err != nil {
				t.Fatal(err)
			}
			parsedPublic, err := test.parsePub(publicPEM)
			if err != nil {
				t.Fatal(err)
			}
			if parsedPublic.Curve() != key.Curve() {
				t.Fatal("public curve changed after PEM round trip")
			}
		})
	}
}
