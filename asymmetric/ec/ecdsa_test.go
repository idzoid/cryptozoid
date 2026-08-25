package ec

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"testing"
)

func TestECDSAKeyManagerAcrossCurves(t *testing.T) {
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
			key, err := GenerateECDSAKey(test.curve)
			if err != nil {
				t.Fatal(err)
			}
			manager := NewECDSAKeyManager(key)

			if got := manager.CurveName(); got != test.want {
				t.Fatalf("CurveName() = %q, want %q", got, test.want)
			}

			privateBytes, err := manager.KeyBytes()
			if err != nil {
				t.Fatal(err)
			}
			publicBytes, err := manager.PublicBytes()
			if err != nil {
				t.Fatal(err)
			}

			privatePEM, err := manager.KeyToPem()
			if err != nil {
				t.Fatal(err)
			}
			parsedPrivate, err := manager.PemToKey(privatePEM)
			if err != nil {
				t.Fatal(err)
			}
			parsedManager := NewECDSAKeyManager(parsedPrivate)
			parsedPrivateBytes, err := parsedManager.KeyBytes()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(privateBytes, parsedPrivateBytes) {
				t.Fatal("private key changed after PEM round trip")
			}

			publicPEM, err := manager.PublicToPem()
			if err != nil {
				t.Fatal(err)
			}
			parsedPublic, err := manager.PemToPublic(publicPEM)
			if err != nil {
				t.Fatal(err)
			}
			parsedPublicBytes, err := x509.MarshalPKIXPublicKey(parsedPublic)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(publicBytes, parsedPublicBytes) {
				t.Fatal("public key changed after PEM round trip")
			}
		})
	}
}

func TestECDSAPemToPrivateKeyAcrossCurves(t *testing.T) {
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
			key, err := GenerateECDSAKey(test.curve)
			if err != nil {
				t.Fatal(err)
			}
			manager := NewECDSAKeyManager(key)
			privatePEM, err := manager.KeyToPem()
			if err != nil {
				t.Fatal(err)
			}

			ecdhKey, err := ECDSAPemToPrivateKey(privatePEM)
			if err != nil {
				t.Fatal(err)
			}
			if got := ecdhCurveName(ecdhKey.Curve()); got != test.want {
				t.Fatalf("curve = %q, want %q", got, test.want)
			}
		})
	}
}
